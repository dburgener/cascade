// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use sexp::{atom_s, list, Sexp};
use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::TryFrom;
use std::ops::Range;

use crate::alias_map::Declared;
use crate::annotations::{
    get_type_annotations, Annotated, AnnotationInfo, Associated, InsertExtendTiming,
};
use crate::ast::{
    Annotation, Annotations, Argument, CascadeString, Declaration, Expression, FuncCall,
    LetBinding, Machine, Module, PolicyFile, Statement, TypeDecl,
};
use crate::constants;
use crate::context::{BindableObject, BlockType, Context as BlockContext};
use crate::error::{
    add_or_create_compile_error, CascadeErrors, CompileError, ErrorItem, InternalError,
};
use crate::functions::{
    create_non_virtual_child_rules, determine_castable, initialize_castable, initialize_terminated,
    propagate, search_for_recursion, ArgForValidation, CallerInfo, DeferredStatement,
    FSContextType, FileSystemContextRule, FunctionArgument, FunctionClass, FunctionInfo,
    FunctionMap, ValidatedCall, ValidatedStatement,
};
use crate::internal_rep::{
    generate_sid_rules, validate_derive_args, ClassList, Context, Sid, TypeInfo, TypeInstance,
    TypeMap, TypeVar,
};
use crate::machine::{MachineMap, ModuleMap, ValidatedMachine, ValidatedModule};
use crate::warning::{Warnings, WithWarnings};

use codespan_reporting::files::SimpleFile;

pub fn compile_rules_one_file<'a>(
    p: &'a PolicyFile,
    classlist: &'a ClassList<'a>,
    type_map: &'a TypeMap,
    func_map: &'a FunctionMap<'a>,
    global_context: &'a BlockContext<'a>,
) -> Result<WithWarnings<BTreeSet<ValidatedStatement<'a>>>, CascadeErrors> {
    do_rules_pass(
        &p.policy.exprs,
        type_map,
        func_map,
        classlist,
        FunctionClass::Global,
        Some(global_context),
        &p.file,
    )
}

pub fn generate_sexp(
    type_map: &TypeMap,
    classlist: &ClassList,
    policy_rules: &BTreeSet<ValidatedStatement>,
    func_map: &FunctionMap<'_>,
    sids: &BTreeSet<Sid<'_>>,
    machine_configurations: &Option<&BTreeMap<String, &Argument>>,
) -> Result<Vec<sexp::Sexp>, CascadeErrors> {
    let type_decl_list = organize_type_map(type_map)?;
    // TODO: The rest of compilation
    let cil_types = type_list_to_sexp(type_decl_list, type_map);
    let headers = generate_cil_headers(classlist, *machine_configurations);
    let cil_rules = rules_list_to_sexp(policy_rules)?;
    let cil_macros = func_map_to_sexp(func_map)?;
    let sid_statements = generate_sid_rules(sids.iter().collect());

    let mut ret = headers;
    ret.extend(cil_types);
    ret.extend(cil_macros);
    ret.extend(cil_rules);
    ret.extend(sid_statements);
    Ok(ret)
}

// These are hardcoded, at least for now.
// This sets up MLS, UBAC, and RBAC properties of the machine.
// Version 0.1 won't allow any language control of these properties, but that will come later.
// Until we can actually set these things in the language, we need some sensible defaults to make
// secilc happy. As we add the above listed security models, this should be refactored to set them
// in accordance with the policy
fn generate_cil_headers(
    classlist: &ClassList,
    machine_configurations: Option<&BTreeMap<String, &Argument>>,
) -> Vec<sexp::Sexp> {
    let mut ret = classlist.generate_class_perm_cil();
    ret.append(&mut vec![
        list(&[atom_s("sensitivity"), atom_s("s0")]),
        list(&[atom_s("sensitivityorder"), list(&[atom_s("s0")])]),
        list(&[atom_s("user"), atom_s("system_u")]),
        list(&[atom_s("role"), atom_s("system_r")]),
        list(&[atom_s("role"), atom_s("object_r")]),
        list(&[atom_s("userrole"), atom_s("system_u"), atom_s("system_r")]),
        list(&[atom_s("userrole"), atom_s("system_u"), atom_s("object_r")]),
        list(&[
            atom_s("userlevel"),
            atom_s("system_u"),
            list(&[atom_s("s0")]),
        ]),
        list(&[
            atom_s("userrange"),
            atom_s("system_u"),
            list(&[list(&[atom_s("s0")]), list(&[atom_s("s0")])]),
        ]),
    ]);
    if let Some(c) = machine_configurations {
        if let Some(Argument::Var(handle_unknown)) =
            c.get(&constants::HANDLE_UNKNOWN_PERMS.to_string())
        {
            ret.append(&mut vec![list(&[
                atom_s("handleunknown"),
                atom_s(handle_unknown.as_ref()),
            ])]);
        }
    }
    ret
}

// Helper function for getting annotations from a typeDecl and adding them to a map
// of annotations
// Returns a bool as an error flag
fn map_annotation_info(
    file: &SimpleFile<String, String>,
    key: CascadeString,
    type_decl: &TypeDecl,
    warnings: &mut Warnings,
    errors: &mut CascadeErrors,
    annotation_map: &mut BTreeMap<CascadeString, BTreeSet<AnnotationInfo>>,
) -> bool {
    let mut annotation_infos = match get_type_annotations(file, &type_decl.annotations) {
        Ok(ai) => ai.inner(warnings),
        Err(e) => {
            errors.append(e.into());
            return false;
        }
    };
    let annotations = annotation_map.entry(key).or_default();
    if !annotation_infos.is_empty() {
        annotations.append(&mut annotation_infos);
    }
    annotations.insert(AnnotationInfo::Inherit(type_decl.inherits.clone()));
    true
}

// Extend the type map by inserting new types found in a given policy file
// Returns a map of annotations on extend {} blocks, so that the real types can be augmented with
// them after all types have been inserted
pub fn extend_type_map(
    p: &PolicyFile,
    type_map: &mut TypeMap,
) -> Result<WithWarnings<BTreeMap<CascadeString, BTreeSet<AnnotationInfo>>>, CascadeErrors> {
    let mut ret = BTreeMap::new();
    let mut errors = CascadeErrors::new();
    let mut warnings = Warnings::new();
    for e in &p.policy.exprs {
        let d = match e {
            Expression::Decl(d) => d,
            _ => continue,
        };
        if let Declaration::Type(t) = d {
            let mut associated_resources = BTreeSet::new();
            // If there are nested declarations, they associate
            for e in &t.expressions {
                if let Expression::Decl(Declaration::Type(associated_type)) = e {
                    if !associated_type.is_extension {
                        let nested_name =
                            get_synthetic_resource_name(&t.name, &associated_type.name);
                        if type_map.get(nested_name.as_ref()).is_none() {
                            // Make the synthetic type to associate
                            // create_synthetic_resource() assumes this must be inherited from a
                            // global parent, which may not be the case
                            let mut nested_td = associated_type.clone();
                            nested_td.name = nested_name.clone();
                            match TypeInfo::new(*nested_td, &p.file) {
                                Ok(ww) => {
                                    let new_type = ww.inner(&mut warnings);
                                    type_map.insert(nested_name.to_string(), new_type)?;
                                    associated_resources.insert((&nested_name).into());
                                }
                                Err(e) => errors.append(e),
                            }
                        } else {
                            // The domain doesn't exist in the map yet, so we can't use
                            // make_duplciate_associate_error() here
                            return Err(ErrorItem::make_compile_or_internal_error(
                                "This resource is explicitly associated to both the parent and child.  (Perhaps you meant to extend the existing resource in the child?)",
                                Some(&p.file),
                                associated_type.name.get_range(),
                                "").into());
                        }
                        let ann_to_insert = AnnotationInfo::NestAssociate(Associated {
                            resources: BTreeSet::from([(&nested_name).into()]),
                        });
                        let annotations = ret.entry(t.name.clone()).or_insert_with(BTreeSet::new);
                        annotations.insert(ann_to_insert);
                    } else {
                        // Insert its annotations
                        if !map_annotation_info(
                            &p.file,
                            CascadeString::from(
                                t.name.to_string() + "." + associated_type.name.as_ref(),
                            ),
                            associated_type,
                            &mut warnings,
                            &mut errors,
                            &mut ret,
                        ) {
                            continue;
                        }
                    }
                }
            }

            if !t.is_extension {
                match TypeInfo::new(*t.clone(), &p.file) {
                    Ok(new_type) => {
                        let mut new_type = new_type.inner(&mut warnings);
                        new_type
                            .associated_resources
                            .append(&mut associated_resources);
                        type_map.insert(t.name.to_string(), new_type)?;
                    }
                    Err(e) => errors.append(e),
                }
            } else {
                // Insert its annotations
                if !map_annotation_info(
                    &p.file,
                    t.name.clone(),
                    t,
                    &mut warnings,
                    &mut errors,
                    &mut ret,
                ) {
                    continue;
                }
            }
        }
    }
    errors.into_result(WithWarnings::new(ret, warnings))
}

// Verify that all uses of the extend keyword correspond to types declared elsewhere
pub fn verify_extends(p: &PolicyFile, type_map: &TypeMap) -> Result<(), CascadeErrors> {
    let mut errors = CascadeErrors::new();
    for e in &p.policy.exprs {
        if let Expression::Decl(Declaration::Type(td)) = e {
            if td.is_extension && type_map.get(td.name.as_ref()).is_none() {
                errors.append(ErrorItem::make_compile_or_internal_error(
                        &format!("{} is undeclared", td.name),
                        Some(&p.file),
                        td.name.get_range(),
                        "In order to extend this type, it must be declared elsewhere (maybe you want to declare it instead?)").into());
            }
        }
    }
    errors.into_result(())
}

pub fn insert_extend_annotations(
    type_map: &mut TypeMap,
    extend_annotations: &BTreeMap<CascadeString, BTreeSet<AnnotationInfo>>,
    timing: InsertExtendTiming,
) {
    for (annotated_type, annotations) in extend_annotations {
        // If get_mut() returns None, that means we added an annotation on an extend for a type
        // that doesn't exist.  That case will return an error in verify_extends() regardless of
        // whether we added an annotation, so we can just skip silently for now
        if let Some(t) = type_map.get_mut(annotated_type.as_ref()) {
            for a in annotations {
                if a.insert_timing() == timing || a.insert_timing() == InsertExtendTiming::All {
                    // Ideally we would use drain_filter but that is currently unstable.
                    // TODO once drain_filter is stable convert to using that.
                    if let Some(inherits) = a.as_inherit() {
                        t.inherits.append(&mut inherits.clone());
                    } else {
                        t.annotations.insert(a.clone());
                    }
                }
                // We only insert Associate annotations early, but we should add them to
                // associated_resources regardless.  It's a BTreeSet, so it automatically dedups,
                // which we want, since we'll be re-adding the Early ones during Late
                // This is because association adds new annotations on TypeDecls for inherited
                // annotations
                if let AnnotationInfo::Associate(associations) = a {
                    t.associated_resources
                        .append(&mut associations.resources.clone());
                }
            }
        }
    }
}

pub fn get_built_in_types_map() -> Result<TypeMap, CascadeErrors> {
    let mut built_in_types = TypeMap::new();
    let list_coercions = constants::BUILT_IN_TYPES
        .iter()
        .map(|t| *t == "perm" || *t == "*" || *t == "class");

    for (built_in, list_coercion) in constants::BUILT_IN_TYPES.iter().zip(list_coercions) {
        let built_in = built_in.to_string();
        built_in_types.insert(
            built_in.clone(),
            TypeInfo::make_built_in(built_in, list_coercion),
        )?;
    }

    // '*' is a special case.  It can be used to mean "all" of the things.  For now, the meaning of
    // "all" is only defined for strings (in annotation contexts where the annotation is
    // responsible for figuring it out) and perms (all permissions for a given object)
    if let Some(t) = built_in_types.get_mut("*") {
        t.inherits = vec![
            CascadeString::from("string"),
            CascadeString::from(constants::PERM),
        ];
    }

    //Special handling for sids.  These are temporary built in types that are handled differently
    let kernel_sid = TypeInfo {
        name: CascadeString::from("kernel_sid"),
        inherits: vec![CascadeString::from(constants::DOMAIN)],
        variant: TypeVar::Domain,
        is_virtual: false,
        is_trait: false,
        list_coercion: false,
        declaration_file: None,
        annotations: BTreeSet::new(),
        associated_resources: BTreeSet::new(),
        decl: None,
        non_virtual_children: BTreeSet::new(),
    };

    let security_sid = TypeInfo {
        name: CascadeString::from("security_sid"),
        inherits: vec![CascadeString::from(constants::RESOURCE)],
        variant: TypeVar::Resource,
        is_virtual: false,
        is_trait: false,
        list_coercion: false,
        declaration_file: None,
        annotations: BTreeSet::new(),
        associated_resources: BTreeSet::new(),
        decl: None,
        non_virtual_children: BTreeSet::new(),
    };

    let unlabeled_sid = TypeInfo {
        name: CascadeString::from("unlabeled_sid"),
        inherits: vec![CascadeString::from(constants::RESOURCE)],
        variant: TypeVar::Resource,
        is_virtual: false,
        is_trait: false,
        list_coercion: false,
        declaration_file: None,
        annotations: BTreeSet::new(),
        associated_resources: BTreeSet::new(),
        decl: None,
        non_virtual_children: BTreeSet::new(),
    };

    for sid in [kernel_sid, security_sid, unlabeled_sid] {
        built_in_types.insert(sid.name.to_string(), sid)?;
    }

    // Add self as child of resource
    if let Some(i) = built_in_types.get_mut(constants::SELF) {
        i.inherits = vec![CascadeString::from(constants::RESOURCE)];
    }
    // Add xattr, task, trans, and genfscon as children of fs_type
    if let Some(i) = built_in_types.get_mut("xattr") {
        i.inherits = vec![CascadeString::from(constants::FS_TYPE)];
    }
    if let Some(i) = built_in_types.get_mut("task") {
        i.inherits = vec![CascadeString::from(constants::FS_TYPE)];
    }
    if let Some(i) = built_in_types.get_mut("trans") {
        i.inherits = vec![CascadeString::from(constants::FS_TYPE)];
    }
    if let Some(i) = built_in_types.get_mut("genfscon") {
        i.inherits = vec![CascadeString::from(constants::FS_TYPE)];
    }

    Ok(built_in_types)
}

pub fn get_global_bindings<'a>(
    p: &PolicyFile,
    types: &'a TypeMap,
    classlist: &ClassList,
    file: &'a SimpleFile<String, String>,
) -> Result<BlockContext<'a>, CascadeErrors> {
    let mut ret = BlockContext::new(BlockType::Global, None, None);
    for e in &p.policy.exprs {
        if let Expression::Stmt(Statement::LetBinding(l)) = e {
            ret.insert_from_argument(&l.name, &l.value, classlist, types, file)?;
        }
    }
    Ok(ret)
}

pub fn build_func_map<'a>(
    exprs: &'a [Expression],
    types: &'a TypeMap,
    classlist: &'a ClassList,
    parent_type: FunctionClass<'a>,
    file: &'a SimpleFile<String, String>,
) -> Result<FunctionMap<'a>, CascadeErrors> {
    let mut decl_map = FunctionMap::new();
    // TODO: This only allows declarations at the top level.
    for e in exprs {
        let d = match e {
            Expression::Decl(d) => d,
            _ => continue,
        };
        match d {
            Declaration::Type(t) => {
                let type_name = if let FunctionClass::Type(pt) = parent_type {
                    get_synthetic_resource_name(&pt.name, &t.name)
                } else {
                    t.name.clone()
                };
                let type_being_parsed = match types.get(type_name.as_ref()) {
                    Some(t) => t,
                    // If a type exists but is not in the machine, skip it for now
                    // TODO: Add extra validation for types defined, but not in the machine
                    None => continue,
                };
                decl_map.try_extend(build_func_map(
                    &t.expressions,
                    types,
                    classlist,
                    FunctionClass::Type(type_being_parsed),
                    file,
                )?)?;
            }
            Declaration::Collection(a) => {
                for f in &a.functions {
                    decl_map.insert(
                        f.get_cil_name(),
                        FunctionInfo::new(
                            f,
                            types,
                            classlist,
                            FunctionClass::Collection(&a.name),
                            file,
                        )?,
                    )?;
                }
            }
            Declaration::Func(f) => {
                let new_func = FunctionInfo::new(f, types, classlist, parent_type, file)?;
                decl_map.insert(new_func.get_cil_name(), new_func)?;
            }
            _ => continue,
        };
    }

    Ok(decl_map)
}

// Helper function to deal with the case where we need to either create a
// new error or add to an existing one, but specifically for this issue
// we need to create a new error and immediately add to it.
#[allow(clippy::too_many_arguments)]
fn new_error_helper(
    error: Option<CompileError>,
    msg: &str,
    file_a: &SimpleFile<String, String>,
    file_b: &SimpleFile<String, String>,
    range_a: Range<usize>,
    range_b: Range<usize>,
    help_a: &str,
    help_b: &str,
) -> CompileError {
    let mut ret;
    // error is not None so we have already found something, so we just
    // need to add a new error message
    if let Some(unwrapped_error) = error {
        ret = unwrapped_error.add_additional_message(file_a, range_a, help_a);
    } else {
        // error is none so we need to make a new one
        ret = CompileError::new(msg, file_b, range_b, help_b);
        ret = ret.add_additional_message(file_a, range_a, help_a);
    }

    ret
}

pub fn validate_fs_context_duplicates(
    fsc_rules: BTreeMap<String, BTreeSet<&FileSystemContextRule>>,
) -> Result<(), CascadeErrors> {
    let mut errors = CascadeErrors::new();

    'key_loop: for v in fsc_rules.values() {
        // We only have 1 or 0 elements, thus we cannot have a semi duplicate
        if v.len() <= 1 {
            continue;
        }
        let mut error: Option<CompileError> = None;
        for rule in v {
            match rule.fscontext_type {
                // If we ever see a duplicate of xattr task or trans we know something is wrong
                FSContextType::XAttr | FSContextType::Task | FSContextType::Trans => {
                    error = Some(add_or_create_compile_error(error,
                        "Duplicate filesystem context.",
                        rule.file.as_ref().ok_or_else(||CascadeErrors::from(InternalError::new()))?,
                        rule.fs_name.get_range().ok_or_else(||CascadeErrors::from(InternalError::new()))?,
                        &format!("Found multiple different filesystem type declarations for filesystem: {}", rule.fs_name)));
                }
                FSContextType::GenFSCon => {
                    // genfscon gets more complicated.  We can have similar rules as long as the paths are different.
                    // If we find a genfscon with the same path, they must have the same context and object type.
                    if let Some(path) = &rule.path {
                        // Look through the rules again
                        for inner_rule in v {
                            // Only check path if it was provided as part of the rule
                            if let Some(inner_path) = &inner_rule.path {
                                // If our paths match, check if our contexts match
                                if path == inner_path && rule.context != inner_rule.context {
                                    error = Some(new_error_helper(error,
                                        "Duplicate genfscon contexts",
                                        inner_rule.file.as_ref().ok_or_else(||CascadeErrors::from(InternalError::new()))?,
                                        rule.file.as_ref().ok_or_else(||CascadeErrors::from(InternalError::new()))?,
                                        inner_rule.context_range.clone(),
                                        rule.context_range.clone(),
                                        &format!("Found duplicate genfscon rules for filesystem {} with differing contexts: {}", inner_rule.fs_name, inner_rule.context),
                                        &format!("Found duplicate genfscon rules for filesystem {} with differing contexts: {}", rule.fs_name, rule.context)));
                                // Our paths are the same but our file types differ. We must also have a file type.
                                } else if path == inner_path
                                    && rule.file_type != inner_rule.file_type
                                    && rule.file_type.is_some()
                                {
                                    error = Some(new_error_helper(error,
                                        "Duplicate genfscon file types",
                                        inner_rule.file.as_ref().ok_or_else(||CascadeErrors::from(InternalError::new()))?,
                                        rule.file.as_ref().ok_or_else(||CascadeErrors::from(InternalError::new()))?,
                                        inner_rule.file_type_range.clone(),
                                        rule.file_type_range.clone(),
                                        &format!("Found duplicate genfscon rules for filesystem {} with differing file types", inner_rule.fs_name),
                                        &format!("Found duplicate genfscon rules for filesystem {} with differing file types", rule.fs_name)));
                                }
                            }
                        }
                        // If we have found an error we don't want to look through
                        // the inner loop again because it will cause duplicate errors
                        // in the "other" matching directions.
                        // So an error for A -> B and B -> A
                        if let Some(unwraped_error) = error {
                            errors.add_error(unwraped_error);
                            continue 'key_loop;
                        }
                    }
                }
            }
        }
        if let Some(unwraped_error) = error {
            errors.add_error(unwraped_error);
        }
    }
    errors.into_result(())
}

fn validate_sids(_sids: &BTreeSet<Sid>) -> Result<(), CascadeErrors> {
    // TODO
    Ok(())
}

pub fn validate_rules<'a>(
    statements: &'a BTreeSet<ValidatedStatement>,
) -> Result<BTreeSet<Sid<'a>>, CascadeErrors> {
    let mut errors = CascadeErrors::new();

    let mut fsc_rules: BTreeMap<String, BTreeSet<&FileSystemContextRule>> = BTreeMap::new();
    let mut sids: BTreeSet<Sid> = BTreeSet::new();
    for statement in statements {
        match statement {
            ValidatedStatement::FscRule(fs) => {
                fsc_rules
                    .entry(fs.fs_name.to_string())
                    .or_default()
                    .insert(fs);
            }
            ValidatedStatement::Sid(s) => {
                sids.insert(s.clone());
            }
            _ => (),
        }
    }

    if let Err(call_errors) = validate_fs_context_duplicates(fsc_rules) {
        errors.append(call_errors);
    }
    if let Err(call_errors) = validate_sids(&sids) {
        errors.append(call_errors);
    }
    errors.into_result(sids)
}

pub fn prevalidate_functions(
    functions: &mut FunctionMap,
    types: &TypeMap,
) -> Result<(), CascadeErrors> {
    initialize_castable(functions, types);
    // We initialize to 1 just to let the loop start once
    let mut num_changed: u64 = 1;
    while num_changed > 0 {
        num_changed = determine_castable(functions, types);
    }

    Ok(())
}

// Mutate hash map to set the validated body
pub fn validate_functions<'a>(
    mut functions: FunctionMap<'a>,
    types: &'a TypeMap,
    class_perms: &'a ClassList,
    context: &'a BlockContext<'a>,
) -> Result<WithWarnings<FunctionMap<'a>>, CascadeErrors> {
    let mut errors = CascadeErrors::new();
    let mut warnings = Warnings::new();
    let mut classes_to_required_functions: BTreeMap<&CascadeString, BTreeSet<&str>> =
        BTreeMap::new();
    let mut derived_function_error = false;

    let mut new_bodies = BTreeMap::new();

    // TODO: We pass the global context in here, but most function declarations are in a type
    // block, and should have bindings in that block exposed
    for function in functions.values() {
        match function.validate_body(&functions, types, class_perms, context) {
            Ok(ww) => {
                new_bodies.insert(function.get_cil_name(), ww.inner(&mut warnings));
            }
            Err(e) => {
                // If the function is derived and fails to validate one of two things have
                // happened:
                // 1. (Most likely) one of the parents its deriving from has a CompileError.  We'll
                //    report that elsewhere
                // 2. We have a Cascade bug
                // In case 1, we just report the derived parent error.  Once that's fixed, we
                // expect the derived function to validate as well.  In case it's case 2, we set
                // that we've seen a derived_function_error and if we don't encounter any other
                // errors, we'll throw an internal error
                if !function.is_derived {
                    errors.append(e);
                } else {
                    derived_function_error = true;
                }
            }
        }
    }

    for (k, v) in new_bodies {
        for statement in &v {
            if let ValidatedStatement::Call(c) = statement {
                if let Some(f) = functions.get_mut(&c.cil_name) {
                    f.callers.insert(CallerInfo::new(
                        CascadeString::from(k.clone()),
                        c.args.clone(),
                    ));
                }
            }
        }
        functions.get_mut(&k).and_then(|f| {
            f.body = Some(v);
            None::<FunctionInfo>
        });
    }

    if derived_function_error && errors.is_empty() {
        errors.append(InternalError::new().into());
    }

    for function in functions.values() {
        if let FunctionClass::Type(func_class) = function.class {
            if function.is_virtual || func_class.is_trait() {
                classes_to_required_functions
                    .entry(&func_class.name)
                    .or_default()
                    .insert(&function.name);
            }
        }
    }

    // Validate that all required functions exist
    for setype in types.values() {
        for parent in &setype.get_all_parent_names(types) {
            for required_function_name in classes_to_required_functions
                .get(parent)
                .unwrap_or(&BTreeSet::new())
            {
                if !setype.defines_function(required_function_name, &functions) {
                    // TODO: this can return an internal error if a synthetic type doesn't declare
                    // a required function.  Instead, we should return a CompileError that provides
                    // a suggestion to provide an implementation somewhere
                    errors.append(CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
                                &format!("{} does not define a function named {}", setype.name, required_function_name),
                                setype.declaration_file.as_ref(),
                                setype.name.get_range(),
                                &format!("All types inheriting {parent} are required to implement {required_function_name} because it is marked as virtual"))))
                }
            }
        }
    }

    errors.into_result(WithWarnings::new(functions, warnings))
}

fn postvalidate_functions(
    functions: &mut FunctionMap,
    types: &TypeMap,
) -> Result<(), CascadeErrors> {
    let mut deferrals = BTreeSet::new();
    let mut errors = CascadeErrors::new();

    let (mut terminated_functions, mut nonterm_functions) = initialize_terminated(functions);

    search_for_recursion(
        &mut terminated_functions,
        &mut nonterm_functions,
        types,
        functions,
    )?;

    for (name, fi) in functions.iter() {
        for statement in fi.body.as_ref().unwrap_or(&BTreeSet::new()) {
            if let ValidatedStatement::Deferred(defer) = statement {
                deferrals.insert((name.clone(), defer.clone()));
            }
        }
    }

    for deferral in deferrals {
        if let Err(e) = propagate(deferral.0, deferral.1, functions, types) {
            errors.append(e);
        }
    }

    errors.into_result(())
}

fn derive_functions<'a>(
    functions: &mut FunctionMap<'a>,
    types: &'a TypeMap,
    class_perms: &'a ClassList,
) -> Result<(), CascadeErrors> {
    let mut errors = CascadeErrors::new();
    let mut internal_error_on_no_errors = false;
    let organized_types = organize_type_map(types)?;
    for t in organized_types {
        let mut saw_derive = false;
        let mut saw_no_derive = false;
        for annotation in t.get_annotations() {
            if let AnnotationInfo::Derive(derive_args) = annotation {
                saw_derive = true;
                if let Err(e) = handle_derive(t, derive_args, functions, types, class_perms) {
                    // If the type we are deriving wasn't declared in source, then this derive
                    // is inherited from a parent, and that parent should have the same error.
                    // So we only add these errors for real types.  But if there are no errors
                    // on real types, then something weird has happened, and we throw an
                    // internal error so we can get a report and figure out what went wrong.
                    if !t.is_synthetic() {
                        errors.append(e)
                    } else {
                        internal_error_on_no_errors = true
                    }
                }
            }
            if let AnnotationInfo::NoDerive = annotation {
                saw_no_derive = true;
            }
        }
        if saw_derive && saw_no_derive {
            return Err(ErrorItem::make_compile_or_internal_error(
                "This type is marked both @derive and @noderive",
                t.get_file().as_ref(),
                t.name.get_range(),
                "@derive and @noderive are incompatible annotations. Remove one.",
            )
            .into());
        } else if !saw_derive && !saw_no_derive {
            // Do @derive(*,*)
            let derive_args = vec![Argument::Var("*".into()), Argument::Var("*".into())];
            if let Err(e) = handle_derive(t, &derive_args, functions, types, class_perms) {
                if !t.is_synthetic() {
                    errors.append(e)
                } else {
                    internal_error_on_no_errors = true
                }
            }
        }
    }
    if errors.is_empty() && internal_error_on_no_errors {
        // We discarded an error on a synthetic type, but never found the real error
        errors.append(InternalError::new().into());
    }
    errors.into_result(())
}

fn handle_derive<'a>(
    target_type: &'a TypeInfo,
    derive_args: &[Argument],
    functions: &mut FunctionMap<'a>,
    types: &'a TypeMap,
    class_perms: &ClassList,
) -> Result<(), CascadeErrors> {
    let (selected_parents, mut func_names) =
        validate_derive_args(target_type, derive_args, types, class_perms)?;

    let all_parents = target_type
        .inherits
        .iter()
        .filter_map(|name| types.get(name.as_ref()).map(|ti| &ti.name))
        .collect();

    if vec![CascadeString::from("*")] == func_names {
        func_names = get_all_function_names(&all_parents, &*functions)
            .iter()
            .filter(|f_name| !target_type.defines_function(f_name.as_ref(), functions))
            .cloned()
            .collect()
    }

    let mut errors = CascadeErrors::new();
    for f in &func_names {
        // If the explicitly listed parents define the function, use only ones that are listed.  If they
        // don't, get it from all of the types parents
        let this_func_parents = if selected_parents.iter().any(|p| {
            types
                .get(p.as_ref())
                .is_some_and(|parent_type| parent_type.defines_function(f.as_ref(), functions))
        }) {
            &selected_parents
        } else {
            &all_parents
        };
        match FunctionInfo::new_derived_function(
            f,
            target_type,
            this_func_parents,
            functions,
            &func_names,
            target_type.declaration_file.as_ref(),
        ) {
            Ok(derived_function) => {
                let df_cil_name = derived_function.get_cil_name();
                let mut aliases = BTreeSet::new();
                for ann in &derived_function.annotations {
                    if let AnnotationInfo::Alias(alias) = ann {
                        aliases.insert(alias.clone());
                    }
                }
                if functions
                    .insert(df_cil_name.clone(), derived_function)
                    .is_err()
                {
                    // This would return an internal error, since derived_function is synthetic.  Turn it
                    // into a real one, since we know how we derived it
                    let mut error = ErrorItem::make_compile_or_internal_error(
                        "Derived function is also declared explicitly",
                        target_type.declaration_file.as_ref(),
                        f.get_range(),
                        "Deriving a function here...",
                    );

                    if let ErrorItem::Compile(e) = error {
                        let explicit_function =
                            functions.get(&df_cil_name).ok_or_else(InternalError::new)?;
                        let range = explicit_function
                            .get_name_range()
                            .ok_or_else(InternalError::new)?;
                        let file = explicit_function
                            .declaration_file
                            .ok_or_else(InternalError::new)?;

                        error = ErrorItem::Compile(e.add_additional_message(
                            file,
                            range,
                            "...but it was explicitly defined here",
                        ));
                    }
                    return Err(error.into());
                }
                for alias in aliases {
                    let mut files_map = BTreeMap::new();
                    if let Some(file) = target_type.declaration_file.clone() {
                        files_map.insert(alias.clone(), file);
                    }
                    functions.validate_aliases(
                        &BTreeMap::from([(alias.clone(), df_cil_name.clone())]),
                        &files_map,
                    )?;
                    functions.add_alias(alias, df_cil_name.clone());
                }
            }
            Err(e) => errors.append(e),
        }
    }
    errors.into_result(())
}

pub fn validate_modules<'a>(
    policies: &'a [PolicyFile],
    types: &'a TypeMap,
    module_map: &mut ModuleMap<'a>,
) -> Result<(), CascadeErrors> {
    let mut errors = CascadeErrors::new();

    // Store all modules across files in a vector
    let mut modules_vec: Vec<(&SimpleFile<String, String>, &Module)> = Vec::new();
    let mut module_aliases = Vec::new();
    for p in policies {
        for e in &p.policy.exprs {
            if let Expression::Decl(Declaration::Mod(m)) = e {
                modules_vec.push((&p.file, m));
                for ann in &m.annotations.annotations {
                    if ann.name == "alias" {
                        for arg in &ann.arguments {
                            if let Argument::Var(a) = arg {
                                module_aliases.push(a);
                            }
                        }
                    }
                }
            }
        }
    }

    // Make sure there are no cycles in the modules
    for m in &modules_vec {
        match find_module_cycles(m.1, &modules_vec, HashSet::new()) {
            Ok(()) => (),
            Err(e) => errors.append(e),
        }
        errors = errors.into_result_self()?;
    }

    // Validate that module contents exist and create validated modules
    for (file, module) in &modules_vec {
        let mut type_infos = BTreeSet::new();
        let mut child_modules = BTreeSet::new();
        type_infos.append(&mut validate_module_contents(
            constants::DOMAIN.to_string(),
            &module.domains,
            file,
            types,
            &mut errors,
        ));
        type_infos.append(&mut validate_module_contents(
            constants::RESOURCE.to_string(),
            &module.resources,
            file,
            types,
            &mut errors,
        ));
        for m in &module.modules {
            if !&modules_vec.iter().any(|&x| x.1.name == m.as_ref())
                && !&module_aliases.iter().any(|x| x.as_ref() == m.as_ref())
            {
                errors.append(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        &format!("Module {} does not exist", m.as_ref()),
                        Some(file),
                        m.get_range(),
                        "modules within modules must be declared elsewhere",
                    ),
                ))
            } else {
                child_modules.insert(m);
            }
        }
        module_map.insert(
            module.name.to_string(),
            ValidatedModule::new(
                module.name.clone(),
                type_infos,
                child_modules,
                Some(module),
                Some((*file).clone()),
            )?,
        )?;
    }
    errors.into_result(())
}

fn find_module_cycles(
    module_to_check: &Module,
    modules_vec: &[(&SimpleFile<String, String>, &Module)],
    visited_modules: HashSet<&str>,
) -> Result<(), CascadeErrors> {
    let mut ret = CascadeErrors::new();
    for m in &module_to_check.modules {
        if let Some(module_info) = modules_vec
            .iter()
            .find(|&module_info| module_info.1.name == m.as_ref())
        {
            if visited_modules.contains(m.as_ref()) || *m == module_to_check.name {
                // Cycle
                return Err(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        "Cycle detected",
                        Some(module_info.0),
                        m.get_range(),
                        "This module contains itself or has a descendent that contains it",
                    ),
                ));
            }
            let child_module = module_info.1;

            let mut new_visited_modules = visited_modules.clone();
            new_visited_modules.insert(module_to_check.name.as_ref());

            match find_module_cycles(child_module, modules_vec, new_visited_modules) {
                Ok(()) => (),
                Err(e) => ret.append(e),
            }
        }
    }
    ret.into_result(())
}

fn validate_module_contents<'a>(
    content_type: String,
    module_contents: &[CascadeString],
    file: &SimpleFile<String, String>,
    types: &'a TypeMap,
    errors: &mut CascadeErrors,
) -> BTreeSet<&'a TypeInfo> {
    let mut ret = BTreeSet::new();
    for content in module_contents {
        match types.get(content.as_ref()) {
            Some(x) => {
                let mut err: bool = false;
                if content_type == constants::DOMAIN {
                    err = !x.is_domain(types);
                } else if content_type == constants::RESOURCE {
                    err = !x.is_resource(types);
                } else {
                    errors.append(InternalError::new().into());
                }
                if err {
                    errors.append(CascadeErrors::from(
                        ErrorItem::make_compile_or_internal_error(
                            &format!(
                                "A declaration of {} exists, but is not a {}",
                                content.as_ref(),
                                content_type
                            ),
                            Some(file),
                            content.get_range(),
                            &format!("{content_type}s within modules must be declared elsewhere",),
                        ),
                    ))
                }
                ret.insert(x);
            }
            None => errors.append(CascadeErrors::from(
                ErrorItem::make_compile_or_internal_error(
                    &format!("{} {} does not exist", content_type, content.as_ref()),
                    Some(file),
                    content.get_range(),
                    &format!("{content_type}s within modules must be declared elsewhere",),
                ),
            )),
        }
    }
    ret
}

pub fn validate_machines<'a>(
    policies: &'a [PolicyFile],
    module_map: &'a ModuleMap,
    machine_map: &mut MachineMap<'a>,
) -> Result<(), CascadeErrors> {
    let mut errors = CascadeErrors::new();

    // Store all machines across files in a vector
    let mut machines_vec: Vec<(&SimpleFile<String, String>, &Machine)> = Vec::new();
    for p in policies {
        for e in &p.policy.exprs {
            if let Expression::Decl(Declaration::Machine(s)) = e {
                machines_vec.push((&p.file, s));
            }
        }
    }

    for (file, machine) in &machines_vec {
        let mut machine_modules = BTreeSet::new();
        let mut configs = BTreeMap::new();

        // Check that a machine has at least 1 module
        if machine.modules.is_empty() {
            errors.append(CascadeErrors::from(
                ErrorItem::make_compile_or_internal_error(
                    &format!(
                        "Machine {} cannot be declared with no modules",
                        machine.name.as_ref()
                    ),
                    Some(file),
                    machine.name.get_range(),
                    "Add a module to the machine",
                ),
            ));
        }

        // Validate that the modules of a machine exist
        for m in &machine.modules {
            match module_map.get(m.as_ref()) {
                Some(module) => {
                    machine_modules.insert(module);
                }
                None => errors.append(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        &format!("Module {} does not exist", m.as_ref()),
                        Some(file),
                        m.get_range(),
                        "modules within machines must be declared elsewhere",
                    ),
                )),
            }
        }
        // Validate the machine's configurations
        for c in &machine.configurations {
            let config = c.name.as_ref();
            let options = match config {
                constants::SYSTEM_TYPE => vec!["standard"],
                constants::MONOLITHIC => vec!["true", "false"],
                constants::HANDLE_UNKNOWN_PERMS => vec!["allow", "deny", "reject"],
                _ => {
                    errors.append(CascadeErrors::from(
                        ErrorItem::make_compile_or_internal_error(
                            &format!("{} is not a supported configuration", c.name.as_ref()),
                            Some(file),
                            c.name.get_range(),
                            &format!(
                                "The supported configurations are {}, {}, and {}",
                                constants::SYSTEM_TYPE,
                                constants::MONOLITHIC,
                                constants::HANDLE_UNKNOWN_PERMS
                            ),
                        ),
                    ));
                    continue;
                }
            };
            match insert_config(file, machine, &mut configs, c, config, options) {
                Ok(()) => (),
                Err(e) => errors.append(e),
            }
        }
        // Check for required configurations
        match check_required_config(file, machine, &configs, constants::HANDLE_UNKNOWN_PERMS) {
            Ok(()) => (),
            Err(e) => errors.append(e),
        }

        match machine_map.insert(
            machine.name.to_string(),
            ValidatedMachine::new(
                machine.name.clone(),
                machine_modules,
                configs,
                Some((*file).clone()),
            ),
        ) {
            Ok(()) => {}
            Err(e) => errors.append(e),
        }
    }
    errors.into_result(())
}

fn insert_config<'a>(
    file: &SimpleFile<String, String>,
    machine: &Machine,
    configs: &mut BTreeMap<String, &'a Argument>,
    config: &'a LetBinding,
    config_name: &str,
    valid_values: Vec<&str>,
) -> Result<(), CascadeErrors> {
    let mut ret = CascadeErrors::new();
    if configs.contains_key(&config_name.to_string()) {
        ret.append(CascadeErrors::from(
            ErrorItem::make_compile_or_internal_error(
                &format!(
                    "The configuration {} is included more than once in machine {}",
                    config_name, machine.name
                ),
                Some(file),
                config.name.get_range(),
                "Each configuration can only be included once in each machine",
            ),
        ))
    } else if let std::collections::btree_map::Entry::Vacant(e) =
        configs.entry(config_name.to_string())
    {
        if let Argument::Var(a) = &config.value {
            if valid_values.contains(&a.as_ref()) {
                e.insert(&config.value);
            } else {
                ret.append(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        "Invalid configuration option",
                        Some(file),
                        a.get_range(),
                        &format!("The supported options for {config_name} are {valid_values:?}"),
                    ),
                ))
            }
        }
    }
    ret.into_result(())
}

fn check_required_config(
    file: &SimpleFile<String, String>,
    machine: &Machine,
    configs: &BTreeMap<String, &Argument>,
    config_name: &str,
) -> Result<(), CascadeErrors> {
    let mut ret = CascadeErrors::new();
    if !configs.contains_key(&config_name.to_string()) {
        ret.append(CascadeErrors::from(
            ErrorItem::make_compile_or_internal_error(
                &format!("{config_name} configuration must be included in the machine",),
                Some(file),
                machine.name.get_range(),
                &format!(
                    "Add a {} configuration to machine {}",
                    config_name, machine.name
                ),
            ),
        ));
    }
    ret.into_result(())
}

// Get the types, functions, and policy rules for the machine.
pub fn get_reduced_infos(
    policies: &[PolicyFile],
    classlist: &ClassList,
    machine: &ValidatedMachine,
    type_map: &TypeMap,
    module_map: &ModuleMap,
    global_context: &BlockContext<'_>,
) -> Result<WithWarnings<Vec<sexp::Sexp>>, CascadeErrors> {
    let ret = CascadeErrors::new();
    let mut warnings = Warnings::new();
    let mut new_type_map = get_built_in_types_map()?;

    // Get the reduced type infos
    for module in &machine.modules {
        get_reduced_types(module, &mut new_type_map, type_map, module_map)?;
    }

    mark_non_virtual_children(&mut new_type_map);

    // Generate type aliases for the new reduced type map
    let (new_t_aliases, alias_files) = collect_aliases(new_type_map.iter())?;
    new_type_map.validate_aliases(&new_t_aliases, &alias_files)?;
    new_type_map.set_aliases(new_t_aliases);

    // Get the function infos
    let mut new_func_map = get_funcs(policies, &new_type_map, classlist)?;

    derive_functions(&mut new_func_map, &new_type_map, classlist)?;

    prevalidate_functions(&mut new_func_map, &new_type_map)?;

    // Validate functions, including deriving functions from annotations
    let mut new_func_map =
        validate_functions(new_func_map, &new_type_map, classlist, global_context)?
            .inner(&mut warnings);

    postvalidate_functions(&mut new_func_map, &new_type_map)?;

    // Get the policy rules
    let mut new_policy_rules = get_policy_rules(
        policies,
        &new_type_map,
        classlist,
        &new_func_map,
        global_context,
    )?
    .inner(&mut warnings);

    // TODO: This is a hack to work around the fact that SIDs contain Contexts, which *might*
    // contain a reference that is only valid for the lifetime of rules.  In fact, the Contexts in
    // the SIDs, are all owned, so there's no issue, but I can't figure out how to convince the
    // compiler of that.  Probably the better solution is to convert the Contexts to pure owned
    // types instead of Cows, so that we can just clone the SIDs here, but this is the expedient
    // approach for 0.1
    let orig_policy_rules = new_policy_rules.clone();
    let mut sids = validate_rules(&orig_policy_rules)?;

    if sids.is_empty() {
        sids = generate_sids("kernel_sid", "security_sid", "unlabeled_sid");
    } else {
        new_policy_rules.retain(|rule| !matches!(rule, ValidatedStatement::Sid(_)))
    }

    // generate_sexp(...) is called at this step because new_func_map and new_policy_rules,
    // which are needed for the generate_sexp call, cannot be returned from this function.
    // This is because they reference the local variable, new_func_map_copy, which cannot be
    // moved out due to the lifetimes in validate_functions(...).
    let new_cil_tree = generate_sexp(
        &new_type_map,
        classlist,
        &new_policy_rules,
        &new_func_map,
        &sids,
        &Some(&machine.configurations),
    )?;

    ret.into_result(WithWarnings::new(new_cil_tree, warnings))
}

// This is a recursive function that gets only the relevant types from the type map.
// The reduced types are the types in the module and the types in any of that modules' child modules.
// Parents of those types are also automatically included.
// The types are cloned so that each machine TypeMap can own its own types.
pub fn get_reduced_types(
    module: &ValidatedModule,
    reduced_type_map: &mut TypeMap,
    type_map: &TypeMap,
    module_map: &ModuleMap,
) -> Result<(), CascadeErrors> {
    for t in &module.types {
        if let Some(type_info) = type_map.get(t.name.as_ref()) {
            if !reduced_type_map.iter().any(|(k, _v)| k == t.name.as_ref()) {
                reduced_type_map.insert(t.name.to_string(), type_info.clone())?;
            }
        }
        for parent in &t.inherits {
            if let Some(parent_type_info) = type_map.get(parent.as_ref()) {
                // The parent name may be an alias, so get the real name from the TypeInfo
                let real_parent_name = parent_type_info.name.as_ref();
                if !reduced_type_map.iter().any(|(k, _v)| k == real_parent_name) {
                    reduced_type_map
                        .insert(real_parent_name.to_string(), parent_type_info.clone())?;
                }
            }
        }
    }
    for vm in &module.validated_modules {
        if let Some(child_module) = module_map.get(vm.as_ref()) {
            get_reduced_types(child_module, reduced_type_map, type_map, module_map)?;
        }
    }
    Ok(())
}

pub fn mark_non_virtual_children(type_map: &mut TypeMap) {
    let mut non_virtual_types = BTreeMap::new();
    for t in type_map.values() {
        if !t.is_virtual {
            non_virtual_types.insert(t.name.to_string(), BTreeSet::new());
        }
    }

    for t in type_map.values() {
        for parent in t.get_all_parent_names(type_map) {
            if let Some(val) = non_virtual_types.get_mut(parent.as_ref()) {
                val.insert(t.name.clone());
            }
        }
    }

    for (type_name, children) in non_virtual_types.into_iter() {
        if let Some(ti) = type_map.get_mut(type_name.as_ref()) {
            ti.non_virtual_children = children;
        }
    }
}

pub fn get_funcs<'a>(
    policies: &'a [PolicyFile],
    reduced_type_map: &'a TypeMap,
    classlist: &'a ClassList,
) -> Result<FunctionMap<'a>, CascadeErrors> {
    let mut ret = CascadeErrors::new();
    let mut reduced_func_map = FunctionMap::new();
    // Collect all function declarations
    for p in policies {
        let mut m = match build_func_map(
            &p.policy.exprs,
            reduced_type_map,
            classlist,
            FunctionClass::Global,
            &p.file,
        ) {
            Ok(m) => m,
            Err(e) => {
                ret.append(e);
                continue;
            }
        };
        reduced_func_map.append(&mut m);
    }
    // Stops if something went wrong for this major step.
    ret = ret.into_result_self()?;
    // Get function aliases
    let (f_aliases, alias_files) = collect_aliases(reduced_func_map.iter())?;
    reduced_func_map.validate_aliases(&f_aliases, &alias_files)?;
    reduced_func_map.set_aliases(f_aliases);
    ret.into_result(reduced_func_map)
}

pub fn get_policy_rules<'a>(
    policies: &'a [PolicyFile],
    reduced_type_map: &'a TypeMap,
    classlist: &'a ClassList<'a>,
    reduced_func_map: &'a FunctionMap<'a>,
    global_context: &'a BlockContext<'a>,
) -> Result<WithWarnings<BTreeSet<ValidatedStatement<'a>>>, CascadeErrors> {
    let mut ret = CascadeErrors::new();
    let mut warnings = Warnings::new();
    let mut reduced_policy_rules = BTreeSet::new();

    // Add derived and nested associated calls
    let mut calls =
        call_associated_calls(reduced_type_map, reduced_func_map, classlist)?.inner(&mut warnings);
    reduced_policy_rules.append(&mut calls);

    for p in policies {
        let mut r = match compile_rules_one_file(
            p,
            classlist,
            reduced_type_map,
            reduced_func_map,
            global_context,
        ) {
            Ok(r) => r.inner(&mut warnings),
            Err(e) => {
                ret.append(e);
                continue;
            }
        };
        reduced_policy_rules.append(&mut r);
    }
    // Stops if something went wrong for this major step.
    ret.into_result(WithWarnings::new(reduced_policy_rules, warnings))
}

// Gets all function names which are members of types in the type_names list
fn get_all_function_names(
    type_names: &BTreeSet<&CascadeString>,
    functions: &FunctionMap,
) -> Vec<CascadeString> {
    let mut ret = Vec::new();
    for f in functions.values() {
        if let FunctionClass::Type(class) = f.class {
            if type_names.contains(&&class.name)
                && !ret.contains(&CascadeString::from(&f.name as &str))
            {
                ret.push(CascadeString::from(&f.name as &str));
            }
        }
    }
    ret
}

// If a type couldn't be organized, it is either a cycle or a non-existent parent somewhere
// The claim that a type must have at least one parent is enforced by the parser
// This function walks the tree from a given type and determines which of these cases we are in
// Return a Vector of found errors.  This Vector can be empty in internal calls, but should not be
// when called from another function.
fn find_cycles_or_bad_types(
    type_to_check: &TypeInfo,
    types: &TypeMap,
    visited_types: HashSet<&str>,
) -> Result<(), CascadeErrors> {
    let mut ret = CascadeErrors::new();

    for p in &type_to_check.inherits {
        if visited_types.contains(p.as_ref()) || *p == type_to_check.name {
            // cycle
            return Err(CascadeErrors::from(
                ErrorItem::make_compile_or_internal_error(
                    "Cycle detected",
                    type_to_check.declaration_file.as_ref(),
                    p.get_range(),
                    "This type inherits itself",
                ),
            ));
        }
        let parent_ti = match types.get(p.as_ref()) {
            Some(t) => t,
            None => {
                return Err(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        "Not a valid identifier",
                        type_to_check.declaration_file.as_ref(),
                        p.get_range(),
                        "Expected a valid type",
                    ),
                ));
            }
        };

        let mut new_visited_types = visited_types.clone();
        new_visited_types.insert(type_to_check.name.as_ref());

        match find_cycles_or_bad_types(parent_ti, types, new_visited_types) {
            Ok(()) => (),
            Err(e) => ret.append(e),
        }
    }

    ret.into_result(())
}

fn generate_type_no_parent_errors(missed_types: Vec<&TypeInfo>, types: &TypeMap) -> CascadeErrors {
    let mut ret = CascadeErrors::new();
    for t in &missed_types {
        match find_cycles_or_bad_types(t, types, HashSet::new()) {
            Ok(()) => {
                ret.add_error(InternalError::new());
                return ret;
            }
            Err(e) => ret.append(e),
        }
    }
    // TODO: Deduplication
    ret
}

pub fn get_synthetic_resource_name(
    dom_name: &CascadeString,
    associated_resource: &CascadeString,
) -> CascadeString {
    let cs_name = format!("{}.{}", dom_name, associated_resource);
    // We keep the range of the *resource* part specifically, which should always be where this
    // resource was defined
    match associated_resource.get_range() {
        Some(range) => CascadeString::new(cs_name, range),
        None => CascadeString::from(cs_name),
    }
}

fn create_synthetic_resource(
    types: &TypeMap,
    dom_info: &TypeInfo,
    associated_parents: &[&TypeInfo],
    classes: Vec<&TypeInfo>,
    class_string: &CascadeString,
    global_exprs: &mut HashSet<Expression>,
    extend_annotations: &BTreeMap<CascadeString, BTreeSet<AnnotationInfo>>,
) -> Result<CascadeString, ErrorItem> {
    if !classes.iter().all(|c| c.is_resource(types)) {
        let mut non_resource_classes = classes.iter().filter(|c| !c.is_resource(types));
        let mut error = ErrorItem::make_compile_or_internal_error(
            "not a resource",
            dom_info.declaration_file.as_ref(),
            non_resource_classes.next().and_then(|c| c.name.get_range()),
            "This should be a resource, not a domain.",
        );

        for c in non_resource_classes {
            error = error.maybe_add_additional_message(
                dom_info.declaration_file.as_ref(),
                c.name.get_range(),
                "This should be a resource, not a domain.",
            );
        }
        return Err(error);
    }

    // Creates a synthetic resource declaration.
    let res_name = get_synthetic_resource_name(&dom_info.name, class_string);
    if types.get(res_name.as_ref()).is_some() {
        // A synthetic type with this name already exists, due to a nested association
        return Err(
            match make_duplicate_associate_error(types, dom_info, class_string) {
                Some(e) => e.into(),
                None => ErrorItem::Internal(InternalError::new()),
            },
        );
    }
    // See TypeDecl::new() in parser.lalrpop for resource inheritance.
    let mut parent_names: Vec<CascadeString> = if associated_parents.is_empty() {
        // This is the full parent.resource name because resource may not exist and parent.resource
        // is the true parent anyways
        classes.iter().map(|c| c.name.clone()).collect()
    } else {
        associated_parents
            .iter()
            .map(|parent| get_synthetic_resource_name(&parent.name, class_string))
            .collect()
    };

    parent_names.push(constants::RESOURCE.into());

    for inherit_ann in extend_annotations
        .get(&res_name)
        .iter()
        .flat_map(|anns| anns.iter().filter_map(|ann| ann.as_inherit()))
    {
        parent_names.append(&mut inherit_ann.clone());
    }

    let mut new_decl = TypeDecl::new(res_name.clone(), parent_names, Vec::new());
    // Virtual resources become concrete when associated to concrete types
    new_decl.is_virtual = classes.iter().all(|c| c.is_virtual) && dom_info.is_virtual;
    new_decl.is_trait = false;
    new_decl.is_extension = false;
    // The synthetic resource keeps some, but not all annotations from its parent.
    // Specifically, Makelist and derive are kept from the parent
    // TODO: This would be cleaner if we convert to AnnotationInfos first and implement the logic as
    // a member function in AnnotationInfo
    // See https://github.com/dburgener/cascade/pull/39#discussion_r999510493 for fuller discussion
    new_decl.annotations.annotations = classes
        .iter()
        .flat_map(|c| c.decl.iter().flat_map(|d| d.annotations.annotations.iter()))
        .filter(|a| a.name.as_ref() == "makelist" || a.name.as_ref() == "derive")
        .cloned()
        .collect(); // TODO: dedup?

    if !global_exprs.insert(Expression::Decl(Declaration::Type(Box::new(new_decl)))) {
        // The callers should be handling the situation where the same resource was declared at the
        // same level of inheritance, but this can arise if a parent associated a resource and a
        // child associated the same resource.  We should find them and return and error message
        return match make_duplicate_associate_error(types, dom_info, class_string) {
            Some(e) => Err(e.into()),
            None => Err(InternalError::new().into()),
        };
    }
    Ok(res_name)
}

fn make_duplicate_associate_error(
    types: &TypeMap,
    child_domain: &TypeInfo,
    res_name: &CascadeString,
) -> Option<CompileError> {
    let mut parent_ti = None;
    let mut parent_associate_range = None;
    for p in child_domain.get_all_parent_names(types) {
        if let Some(p_ti) = types.get(p.as_ref()) {
            parent_associate_range = p_ti.explicitly_associates(res_name.as_ref());
            if parent_associate_range.is_some() {
                parent_ti = Some(p_ti);
                break;
            }
        }
    }
    let current_associate_range: Range<usize> =
        match child_domain.explicitly_associates(res_name.as_ref()) {
            Some(r) => r,
            None => {
                return None;
            }
        };

    // If anything we need for a real error is None, all we can do is InternalError, so unwrap
    // everything, returning InternalError on failure
    let child_file = child_domain.declaration_file.as_ref()?;
    let parent_file = parent_ti?.declaration_file.as_ref()?;
    let parent_associate_range = parent_associate_range?;
    let parent_name_range = parent_ti?.name.get_range()?;

    Some(CompileError::new(
                "This resource is explicitly associated to both the parent and child.  (Perhaps you meant to extend the existing resource in the child?)",
                child_file,
                current_associate_range,
                "Associated in the child here")
            .add_additional_message(
                parent_file,
                parent_name_range,
                "But it was already associated in this parent")
            .add_additional_message(
                parent_file,
                parent_associate_range,
                "Note: parent association was here"))
}

#[allow(clippy::too_many_arguments)]
fn interpret_associate(
    global_exprs: &mut HashSet<Expression>,
    types: &TypeMap,
    associate: &Associated,
    associated_parents: &[&TypeInfo],
    dom_info: &TypeInfo,
    extend_annotations: &BTreeMap<CascadeString, BTreeSet<AnnotationInfo>>,
) -> Result<(), CascadeErrors> {
    // Only allow a set of specific annotation names and strictly check their arguments.
    // TODO: Add tests to verify these checks.

    let mut errors = CascadeErrors::new();
    let potential_resources: BTreeMap<_, _> = associate
        .resources
        .iter()
        .map(|r| (r.name().as_ref(), (r, false)))
        .collect();

    for (_, (res, _)) in potential_resources.iter().filter(|(_, (_, seen))| !seen) {
        let mut classes = Vec::new();
        for real_parent_resource in res.get_class_names() {
            match types.get(&real_parent_resource) {
                Some(class) => classes.push(class),
                None => errors.add_error(ErrorItem::make_compile_or_internal_error(
                    "unknown resource",
                    dom_info.declaration_file.as_ref(),
                    res.get_range(&real_parent_resource),
                    "didn't find this resource in the policy",
                )),
            }
        }

        errors = errors.into_result_self()?;

        match create_synthetic_resource(
            types,
            dom_info,
            associated_parents,
            classes,
            &res.basename().into(),
            global_exprs,
            extend_annotations,
        ) {
            Ok(_) => {
                // If the associated call is derived, we'll need to add it in later.  If
                // the association is inherited, we need to make sure to mark it now so we
                // know to do that.
                let class_name = CascadeString::from(res.basename());
                global_exprs.insert(Expression::Decl(Declaration::Type(Box::new(TypeDecl {
                    name: dom_info.name.clone(),
                    inherits: Vec::new(),
                    is_virtual: dom_info.is_virtual,
                    is_trait: dom_info.is_trait,
                    is_extension: true,
                    expressions: Vec::new(),
                    annotations: Annotations {
                        annotations: vec![Annotation {
                            name: "associate".into(),
                            arguments: vec![Argument::List(vec![class_name])],
                        }],
                    },
                }))));
            }
            Err(e) => errors.add_error(e),
        }
    }

    errors.into_result(())
}

fn make_associated_call(resource_name: CascadeString, func_info: &FunctionInfo) -> FuncCall {
    FuncCall::new(
        Some((resource_name, None)),
        func_info.name.clone().into(),
        vec![Argument::Var("this".into())],
    )
}

// domain -> related expressions
type AssociateExprs = HashMap<CascadeString, HashSet<Expression>>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct InheritedAnnotation<'a> {
    annotation: AnnotationInfo,
    // If we inherit the same annotation from multiple parents, we collapse to one
    // InheritedAnnotation with multiple parents
    parents: Vec<&'a TypeInfo>,
}

impl<'a> InheritedAnnotation<'a> {
    // Call intersect on the annotation and combine the parents
    fn intersection(self, other: InheritedAnnotation<'a>) -> Option<InheritedAnnotation<'a>> {
        match self.annotation.intersection(&other.annotation) {
            Some(intersect) => Some(InheritedAnnotation {
                annotation: intersect,
                parents: {
                    let mut ret: Vec<&TypeInfo> =
                        self.parents.into_iter().chain(other.parents).collect();
                    ret.sort();
                    ret.dedup();
                    ret
                },
            }),
            None => None,
        }
    }

    // Call difference on the annotation and return just the left parents
    fn difference(self, other: InheritedAnnotation<'a>) -> Option<InheritedAnnotation<'a>> {
        match self.annotation.difference(&other.annotation) {
            Some(difference) => Some(InheritedAnnotation {
                annotation: difference,
                parents: self.parents.clone(),
            }),
            None => None,
        }
    }
}

fn dedup_inherited_annotations(anns: Vec<InheritedAnnotation<'_>>) -> Vec<InheritedAnnotation<'_>> {
    let mut out = Vec::new();
    for a in anns {
        out = dedup_inherited_annotations_one(out, a);
    }
    out
}

// Take a list of annotations and a new one to append.  Return a list with that included and
// deduped
fn dedup_inherited_annotations_one<'a>(
    existing_anns: Vec<InheritedAnnotation<'a>>,
    new_ann: InheritedAnnotation<'a>,
) -> Vec<InheritedAnnotation<'a>> {
    let mut out = Vec::new();
    // We may merge chunks into existing_anns
    let mut remaining_new_ann = Some(new_ann);
    for a in existing_anns {
        match remaining_new_ann {
            Some(new) => {
                let left_diff = a.clone().difference(new.clone());
                let right_diff = new.clone().difference(a.clone());
                let intersect = a.intersection(new.clone());
                for set in [left_diff, intersect] {
                    if let Some(set) = set {
                        out.push(set);
                    }
                }
                remaining_new_ann = right_diff;
            }
            None => out.push(a),
        }
    }
    // If we fully combined it with previous elements, it's None now.  Otherwise there's something
    // left to append
    if let Some(new) = remaining_new_ann {
        out.push(new);
    }

    out
}

fn interpret_inherited_annotations<'a, T>(
    global_exprs: &mut HashSet<Expression>,
    associate_exprs: &mut AssociateExprs,
    types: &TypeMap,
    dom_info: &'a TypeInfo,
    extend_annotations: &BTreeMap<CascadeString, BTreeSet<AnnotationInfo>>,
    extra_annotations: T,
) -> Result<(), CascadeErrors>
where
    T: Iterator<Item = InheritedAnnotation<'a>>,
{
    let mut errors = CascadeErrors::new();

    match associate_exprs.entry(dom_info.name.clone()) {
        // Ignores already processed domains.
        Entry::Occupied(_) => return Ok(()),
        vacant => vacant.or_default(),
    };
    for inherited in dom_info
        .annotations
        .iter()
        .map(|a| InheritedAnnotation {
            annotation: a.clone(),
            parents: Vec::new(),
        })
        .chain(extra_annotations)
    {
        if let AnnotationInfo::Associate(ref associate) = inherited.annotation {
            match interpret_associate(
                global_exprs,
                types,
                associate,
                &inherited.parents,
                dom_info,
                extend_annotations,
            ) {
                Ok(()) => {}
                Err(e) => errors.append(e),
            }
        }
    }

    errors.into_result(())
}

fn inherit_annotations<'a>(
    global_exprs: &mut HashSet<Expression>,
    associate_exprs: &mut AssociateExprs,
    types: &'a TypeMap,
    dom_info: &'a TypeInfo,
    extend_annotations: &BTreeMap<CascadeString, BTreeSet<AnnotationInfo>>,
) -> Result<Vec<InheritedAnnotation<'a>>, CascadeErrors> {
    let mut errors = CascadeErrors::new();

    let inherited_annotations = {
        let mut ret = Vec::new();
        for parent_name in &dom_info.inherits {
            let parent_ti = match types.get(parent_name.as_ref()) {
                Some(p) => p,
                // Ignores inheritance issues for now, see bad_type_error_test().
                None => continue,
            };
            ret.extend(
                match inherit_annotations(
                    global_exprs,
                    associate_exprs,
                    types,
                    parent_ti,
                    extend_annotations,
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        // Can generate duplicated errors because of nested calls.
                        // TODO: Deduplicate errors and sort them by file and line.
                        errors.append(e);
                        continue;
                    }
                },
            );
        }
        ret
    };
    // We may have inherited the same annotation from mulitiple parents, so dedup, combining
    // parents
    let inherited_annotations = dedup_inherited_annotations(inherited_annotations);

    match interpret_inherited_annotations(
        global_exprs,
        associate_exprs,
        types,
        dom_info,
        extend_annotations,
        inherited_annotations.iter().cloned(),
    ) {
        Ok(()) => {}
        Err(e) => errors.append(e),
    }

    errors.into_result_with(|| {
        dom_info
            .annotations
            .iter()
            .map(|a| {
                let ann = if let AnnotationInfo::NestAssociate(r) = a {
                    AnnotationInfo::Associate(r.clone())
                } else {
                    a.clone()
                };
                InheritedAnnotation {
                    annotation: ann,
                    parents: vec![dom_info],
                }
            })
            .chain(inherited_annotations.into_iter().map(|mut a| {
                a.parents = vec![dom_info];
                a
            }))
            .collect()
    })
}

pub fn apply_associate_annotations(
    types: &TypeMap,
    extend_annotations: &BTreeMap<CascadeString, BTreeSet<AnnotationInfo>>,
) -> Result<Vec<Expression>, CascadeErrors> {
    let mut errors = CascadeErrors::new();

    // Makes sure that there is no cycle.
    organize_type_map(types)?;

    let mut associate_exprs = HashMap::new();
    let mut global_exprs = HashSet::new();
    for type_info in types.values() {
        match inherit_annotations(
            &mut global_exprs,
            &mut associate_exprs,
            types,
            type_info,
            extend_annotations,
        ) {
            Ok(_) => {}
            Err(e) => errors.append(e),
        }
    }

    match associate_exprs
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| {
            // TODO: Avoid cloning all expressions.
            let mut new_domain = types
                .get(k.as_ref())
                .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
                .decl
                .as_ref()
                .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
                .clone();
            new_domain.set_extend();
            new_domain.expressions = v.into_iter().collect();
            Ok(Expression::Decl(Declaration::Type(Box::new(new_domain))))
        })
        .chain(global_exprs.into_iter().map(Ok))
        .collect::<Result<_, CascadeErrors>>()
    {
        Ok(r) => errors.into_result(r),
        Err(e) => {
            errors.append(e);
            Err(errors)
        }
    }
}

// This function validates that the relationships in the map are valid, and organizes a Vector
// of type declarations in a reasonable order to be output into CIL.
// In order to be valid, the types must meet the following properties:
// 1. All types have at least one parent
// 2. All listed parents are themselves types (or "domain" or "resource")
// 3. No cycles exist
fn organize_type_map(types: &TypeMap) -> Result<Vec<&TypeInfo>, CascadeErrors> {
    let mut tmp_types: BTreeMap<&String, &TypeInfo> = types.iter().collect();

    let mut out: Vec<&TypeInfo> = Vec::new();

    let mut errors = CascadeErrors::new();

    while !tmp_types.is_empty() {
        let mut current_pass_types: Vec<&TypeInfo> = Vec::new();

        for ti in tmp_types.values() {
            let mut wait = false;

            // TODO: Do we need to consider the case when inherits is empty?  Theoretically it
            // should have always been populated with at least domain or resource by the parser.
            // Should probably return an internal error if that hasn't happened
            for key in &ti.inherits {
                if key == constants::SELF {
                    errors.add_error(ErrorItem::make_compile_or_internal_error(
                        "Inheriting from self is not supported",
                        ti.declaration_file.as_ref(),
                        key.get_range(),
                        "Cannot inherit self",
                    ));
                    continue;
                }

                // key may be an alias
                let key = types.get(key.as_ref()).map(|t| &t.name).unwrap_or(key);

                if !out.iter().any(|&x| &x.name == key) {
                    wait = true;
                    continue;
                }
            }
            if !wait {
                // This means all the parents are previously listed
                current_pass_types.push(ti);
            }
        }
        if current_pass_types.is_empty() && !tmp_types.is_empty() {
            // We can't satisfy the parents for all types
            return Err(generate_type_no_parent_errors(
                tmp_types.values().copied().collect(),
                types,
            ));
        }
        for t in &current_pass_types {
            if tmp_types.remove(&t.name.to_string()).is_none() {
                // If remove failed, something has gone wrong, and we'll keep trying to remove this
                // forever, so bail out
                return Err(ErrorItem::Internal(InternalError::new()).into());
            }
        }
        out.append(&mut current_pass_types);

        if !errors.is_empty() {
            break;
        }
    }
    errors.into_result(out)
}

// Gather all the alias annotations for types and functions and return them so they can be stored
// in the maps
// We gather files, because we aren't storing file info in CascadeStrings yet.  That can go away
// once we store file info in CascadeStrings
// Silence the clippy warning about the return type.  It's not *that* complex, and it will get
// simpler naturally once we do the above
#[allow(clippy::type_complexity)]
pub fn collect_aliases<'a, I, T>(
    aliasable_map: I,
) -> Result<
    (
        BTreeMap<CascadeString, String>,
        BTreeMap<CascadeString, SimpleFile<String, String>>,
    ),
    CascadeErrors,
>
where
    I: Iterator<Item = (&'a String, &'a T)>,
    T: Declared + 'a,
    &'a T: Annotated,
{
    let mut aliases = BTreeMap::new();
    let mut alias_files = BTreeMap::new();
    let mut errors = CascadeErrors::new();
    for (k, v) in aliasable_map {
        for a in v.get_annotations() {
            if let AnnotationInfo::Alias(a) = a {
                if aliases.insert(a.clone(), k.clone()).is_some() {
                    errors.append(
                        ErrorItem::make_compile_or_internal_error(
                            "Alias name conflicts with an existing alias",
                            v.get_file().as_ref(),
                            a.get_range(),
                            "",
                        )
                        .maybe_add_additional_message(
                            alias_files.get(a),
                            // This is the range of the *existing* key.  Insert updates the
                            // value, but not the key when we overwrite.  Since our PartialEq
                            // isn't identical (it just compares the strings, not the ranges),
                            // we still have the old range in the key
                            // https://doc.rust-lang.org/std/collections/struct.BTreeMap.html#method.insert
                            aliases.get_key_value(a).and_then(|(a, _)| a.get_range()),
                            "Existing alias found here",
                        )
                        .into(),
                    );
                }
                if let Some(file) = v.get_file().clone() {
                    alias_files.insert(a.clone(), file);
                }
            }
        }
    }

    errors.into_result((aliases, alias_files))
}

pub fn call_associated_calls<'a>(
    types: &TypeMap,
    funcs: &FunctionMap<'a>,
    class_perms: &ClassList,
) -> Result<WithWarnings<BTreeSet<ValidatedStatement<'a>>>, CascadeErrors> {
    let mut ret = BTreeSet::new();
    let mut warnings = Warnings::new();
    let mut errors = CascadeErrors::new();
    for t in types.values() {
        if !t.is_domain(types) {
            continue;
        }

        for f in funcs.values() {
            if f.is_associated_call {
                let resource_name = match f.class {
                    FunctionClass::Type(n) => n.name.clone(),
                    _ => {
                        // Can't derive from Global or API
                        continue;
                    }
                };
                // Calls from annotations were already added if they weren't derived.  If the call
                // was derived AND via an annotation, we add it.  If it was via nest, we add it
                // unconditionally
                let mut nested_associate = false;
                let mut regular_associate = false;
                for ann in &t.annotations {
                    match ann {
                        AnnotationInfo::Associate(associations) => {
                            if associations.resources.iter().any(|r| {
                                get_synthetic_resource_name(&t.name, &r.basename().into())
                                    == resource_name
                            }) {
                                regular_associate = true;
                            }
                        }
                        AnnotationInfo::NestAssociate(associations) => {
                            if associations
                                .resources
                                .iter()
                                .any(|r| r.string_is_instance(&resource_name))
                            {
                                nested_associate = true;
                            }
                        }
                        _ => (),
                    }
                }
                if regular_associate || nested_associate {
                    let r_basename = match resource_name.as_ref().split_once('.') {
                        Some((_, r)) => r,
                        None => resource_name.as_ref(),
                    };
                    let call = make_associated_call(
                        get_synthetic_resource_name(&t.name, &r_basename.into()),
                        f,
                    );
                    let args = vec![FunctionArgument::new_this_argument(t)];
                    // TODO: Should there be a parent_context here?  I think this is
                    // effectively a "fake" context since we're not really parsing the tree
                    let mut local_context = BlockContext::new(BlockType::Domain, Some(t), None);
                    local_context.insert_function_args(&args);

                    let validated_calls = match ValidatedCall::new(
                        &call,
                        funcs,
                        types,
                        class_perms,
                        &local_context,
                        f.declaration_file,
                    ) {
                        Ok(c) => c.inner(&mut warnings),
                        Err(e) => {
                            errors.append(e);
                            continue;
                        }
                    };

                    // These are definitely ValidatedCalls, but ValidatedCall::new()
                    // returns ValidatedStatements, so they can be inserted directly
                    for c in validated_calls {
                        ret.insert(c);
                    }
                }
            }
        }
    }
    errors.into_result(WithWarnings::new(ret, warnings))
}

fn do_rules_pass<'a>(
    exprs: &'a [Expression],
    types: &'a TypeMap,
    funcs: &'a FunctionMap<'a>,
    class_perms: &ClassList<'a>,
    parent_type: FunctionClass<'a>,
    parent_context: Option<&BlockContext<'_>>,
    file: &'a SimpleFile<String, String>,
) -> Result<WithWarnings<BTreeSet<ValidatedStatement<'a>>>, CascadeErrors> {
    let mut ret = BTreeSet::new();
    let mut errors = CascadeErrors::new();
    let mut warnings = Warnings::new();
    let func_args = match parent_type {
        FunctionClass::Type(t) => vec![FunctionArgument::new_this_argument(t)],
        _ => Vec::new(),
    };

    let block_type = match parent_type {
        FunctionClass::Type(parent) => match parent.get_built_in_variant(types) {
            Some("resource") => BlockType::Resource,
            Some("domain") => BlockType::Domain,
            _ => {
                return Err(ErrorItem::Internal(InternalError::new()).into());
            }
        },
        FunctionClass::Collection(_) => BlockType::Collection,
        FunctionClass::Global => BlockType::Global,
    };

    let mut local_context = BlockContext::new(block_type, parent_type.into(), parent_context);
    local_context.insert_function_args(&func_args);

    for e in exprs {
        match e {
            Expression::Stmt(Statement::LetBinding(l)) => {
                // Need to handle this special case here, otherwise ValidatedStatement::new()
                // confuses the borrow checker because it might mutate local_context, or return
                // data that references the context
                if parent_type != FunctionClass::Global {
                    match local_context.insert_from_argument(
                        &l.name,
                        &l.value,
                        class_perms,
                        types,
                        file,
                    ) {
                        Ok(()) => (),
                        Err(e) => errors.append(e),
                    }
                }
            }
            Expression::Stmt(s) => {
                match ValidatedStatement::new(
                    s,
                    funcs,
                    types,
                    class_perms,
                    &local_context,
                    parent_type,
                    Some(file),
                ) {
                    Ok(s) => {
                        let mut statement_set = s.inner(&mut warnings);
                        for s in &statement_set {
                            if let ValidatedStatement::Call(c) = s {
                                let call_fi = match funcs.get(&c.cil_name) {
                                    Some(fi) => fi,
                                    None => {
                                        // We're ready to write this out to CIL as though its a
                                        // real call.  Something has gone very wrong if we can't
                                        // find it
                                        errors.append(
                                            ErrorItem::Internal(InternalError::new()).into(),
                                        );
                                        continue;
                                    }
                                };
                                // Below unwrap is safe, because the functions have all been
                                // previously validated
                                for call_statement in call_fi.body.as_ref().unwrap() {
                                    if let ValidatedStatement::Deferred(DeferredStatement::Call(
                                        dc,
                                    )) = call_statement
                                    {
                                        // It's okay to use a fake caller name, because
                                        // make_parent_statment only uses the caller name if
                                        // deferring further
                                        let caller_info =
                                            CallerInfo::new("global".into(), c.args.clone());
                                        let parent_dc =
                                            dc.parent_copy(&caller_info.passed_args, call_fi);
                                        let to_insert = parent_dc.make_parent_statement(
                                            types,
                                            call_fi,
                                            &caller_info,
                                        );
                                        if matches!(to_insert, ValidatedStatement::Call(_)) {
                                            ret.insert(to_insert);
                                        } else {
                                            // We can't defer anymore, something has gone wrong
                                            errors.append(
                                                ErrorItem::Internal(InternalError::new()).into(),
                                            )
                                        }
                                    }
                                }
                            }
                        }

                        ret.append(&mut statement_set);
                    }
                    Err(e) => errors.append(e),
                }
            }
            Expression::Decl(Declaration::Type(t)) => {
                let type_name = if let Some(p) = Option::<&TypeInfo>::from(parent_type) {
                    get_synthetic_resource_name(&p.name, &t.name)
                } else {
                    t.name.clone()
                };
                let type_being_parsed = match types.get(type_name.as_ref()) {
                    Some(t) => t,
                    // If a type exists but is not in the machine, skip it for now
                    None => continue,
                };
                match do_rules_pass(
                    &t.expressions,
                    types,
                    funcs,
                    class_perms,
                    FunctionClass::Type(type_being_parsed),
                    Some(&local_context),
                    file,
                ) {
                    Ok(r) => ret.append(&mut r.inner(&mut warnings)),
                    Err(e) => errors.append(e),
                }
                if parent_type.is_type() {
                    // This is a nested declaration, create a local binding for it
                    local_context.insert_binding(
                        t.name.clone(),
                        BindableObject::Type(TypeInstance::new(
                            &ArgForValidation::Var(&type_name),
                            type_being_parsed,
                            Some(file),
                            &local_context,
                        )),
                    );
                }
            }
            _ => {}
        }
    }

    let mut nv_rules = create_non_virtual_child_rules(&ret, types);
    ret.append(&mut nv_rules);
    errors.into_result(WithWarnings::new(ret, warnings))
}

fn type_list_to_sexp(type_list: Vec<&TypeInfo>, type_map: &TypeMap) -> Vec<sexp::Sexp> {
    let mut ret = Vec::new();
    for t in type_list {
        if let Some(s) = Option::<sexp::Sexp>::from(t) {
            ret.extend(get_rules_vec_for_type(t, s, type_map));
        }
    }
    ret
}

fn get_rules_vec_for_type(ti: &TypeInfo, s: sexp::Sexp, type_map: &TypeMap) -> Vec<sexp::Sexp> {
    let mut ret = vec![s];
    if !ti.is_virtual {
        let role_assoc = if ti.is_resource(type_map) {
            "object_r"
        } else {
            "system_r"
        };

        ret.push(list(&[
            atom_s("roletype"),
            atom_s(role_assoc),
            atom_s(ti.name.get_cil_name().as_ref()),
        ]));
    }

    for i in &ti.inherits {
        if let Some(t) = type_map.get(i.as_ref()) {
            if t.is_trait() || !t.is_virtual {
                continue;
            }
        }
        ret.push(list(&[
            atom_s("typeattributeset"),
            atom_s(i.get_cil_name().as_ref()),
            list(&[atom_s(ti.name.get_cil_name().as_ref())]),
        ]));
    }

    // CIL only supports aliases on types.
    // Since an attribute is just a name for a group of types, and attribute on aliases is just a
    // new attribute
    let alias_declaration_keyword = if !ti.is_virtual {
        "typealias"
    } else {
        "typeattribute"
    };
    let alias_association_keyword = if !ti.is_virtual {
        "typealiasactual"
    } else {
        "typeattributeset"
    };

    for a in &ti.annotations {
        if let AnnotationInfo::Alias(a) = a {
            ret.push(list(&[
                atom_s(alias_declaration_keyword),
                atom_s(a.as_ref()),
            ]));
            ret.push(list(&[
                atom_s(alias_association_keyword),
                atom_s(a.as_ref()),
                atom_s(ti.name.get_cil_name().as_ref()),
            ]));
        }
    }
    ret
}

fn rules_list_to_sexp<'a, T>(rules: T) -> Result<Vec<sexp::Sexp>, ErrorItem>
where
    T: IntoIterator<Item = &'a ValidatedStatement<'a>>,
{
    let ret: Result<Vec<_>, _> = rules.into_iter().map(Sexp::try_from).collect();
    ret
}

fn generate_sids<'a>(
    kernel_sid: &'a str,
    security_sid: &'a str,
    unlabeled_sid: &'a str,
) -> BTreeSet<Sid<'a>> {
    BTreeSet::from([
        Sid::new(
            "kernel".to_string(),
            Context::new(true, None, None, Cow::Borrowed(kernel_sid), None, None),
        ),
        Sid::new(
            "security".to_string(),
            Context::new(false, None, None, Cow::Borrowed(security_sid), None, None),
        ),
        Sid::new(
            "unlabeled".to_string(),
            Context::new(false, None, None, Cow::Borrowed(unlabeled_sid), None, None),
        ),
    ])
}

fn func_map_to_sexp(funcs: &FunctionMap<'_>) -> Result<Vec<sexp::Sexp>, CascadeErrors> {
    let mut ret = Vec::new();
    let mut errors = CascadeErrors::new();
    for f in funcs.values() {
        if f.is_virtual {
            continue;
        }
        match Sexp::try_from(f) {
            Ok(func_sexp) => {
                ret.push(func_sexp);
                for ann in &f.annotations {
                    if let AnnotationInfo::Alias(a) = ann {
                        ret.push(f.generate_synthetic_alias_call(a.as_ref()));
                    }
                }
            }
            Err(e) => errors.add_error(e),
        }
    }
    errors.into_result(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{CascadeString, Declaration, Expression, Policy, TypeDecl};
    use crate::internal_rep::TypeInfo;

    #[test]
    fn extend_type_map_test() {
        let exprs = vec![Expression::Decl(Declaration::Type(Box::new(
            TypeDecl::new(
                CascadeString::from("foo"),
                vec![CascadeString::from(constants::DOMAIN)],
                Vec::new(),
            ),
        )))];
        let p = Policy::new(exprs);
        let pf = PolicyFile::new(p, SimpleFile::new(String::new(), String::new()));
        let mut types = get_built_in_types_map().unwrap();
        extend_type_map(&pf, &mut types).unwrap();
        match types.get("foo") {
            Some(foo) => assert_eq!(foo.name, "foo"),
            None => panic!("Foo is not in hash map"),
        }
        match types.get(constants::DOMAIN) {
            Some(foo) => assert_eq!(foo.name, "domain"),
            None => panic!("Domain is not in hash map"),
        }
    }

    #[test]
    fn organize_type_map_test() {
        let mut types = get_built_in_types_map().unwrap();
        let mut warnings = Warnings::new();
        let mut foo_type = TypeInfo::new(
            TypeDecl::new(
                CascadeString::from("foo"),
                vec![CascadeString::from(constants::DOMAIN)],
                Vec::new(),
            ),
            &SimpleFile::new(String::new(), String::new()),
        )
        .unwrap()
        .inner(&mut warnings);
        foo_type.is_virtual = true;

        let mut bar_type = TypeInfo::new(
            TypeDecl::new(
                CascadeString::from("bar"),
                vec![
                    CascadeString::from(constants::DOMAIN),
                    CascadeString::from("foo"),
                ],
                Vec::new(),
            ),
            &SimpleFile::new(String::new(), String::new()),
        )
        .unwrap()
        .inner(&mut warnings);
        bar_type.is_virtual = true;

        let baz_type = TypeInfo::new(
            TypeDecl::new(
                CascadeString::from("baz"),
                vec![
                    CascadeString::from(constants::DOMAIN),
                    CascadeString::from("foo"),
                    CascadeString::from("bar"),
                ],
                Vec::new(),
            ),
            &SimpleFile::new(String::new(), String::new()),
        )
        .unwrap()
        .inner(&mut warnings);

        types.insert("foo".to_string(), foo_type).unwrap();
        types.insert("bar".to_string(), bar_type).unwrap();
        types.insert("baz".to_string(), baz_type).unwrap();

        let _type_vec = organize_type_map(&types).unwrap();

        // TODO: re-enable this.  The built in sid types break the ordering assumptions here
        // Once they have been removed, the below checks should work again
        // Skip built in types
        //assert_eq!(type_vec[type_vec.len() - 3].name, "foo");
        //assert_eq!(type_vec[type_vec.len() - 2].name, "bar");
        //assert_eq!(type_vec[type_vec.len() - 1].name, "baz");

        assert!(warnings.is_empty());
    }

    #[test]
    fn dedup_inherited_annotations_test() {
        let types = get_built_in_types_map().unwrap();
        let inherited_anns = vec![
            InheritedAnnotation {
                annotation: AnnotationInfo::MakeList,
                parents: Vec::new(),
            },
            InheritedAnnotation {
                annotation: AnnotationInfo::MakeList,
                parents: vec![types.get("domain").unwrap()],
            },
            InheritedAnnotation {
                annotation: AnnotationInfo::Associate(Associated {
                    resources: BTreeSet::from([
                        CascadeString::from("foo").into(),
                        CascadeString::from("bar").into(),
                    ]),
                }),
                parents: vec![types.get("resource").unwrap()],
            },
            InheritedAnnotation {
                annotation: AnnotationInfo::Associate(Associated {
                    resources: BTreeSet::from([
                        CascadeString::from("bar").into(),
                        CascadeString::from("baz").into(),
                    ]),
                }),
                parents: vec![types.get("domain").unwrap()],
            },
            InheritedAnnotation {
                annotation: AnnotationInfo::Alias(CascadeString::from("alias")),
                parents: vec![types.get("domain").unwrap()],
            },
            InheritedAnnotation {
                annotation: AnnotationInfo::Alias(CascadeString::from("alias")),
                parents: vec![types.get("domain").unwrap()],
            },
            // derive never dedups
            InheritedAnnotation {
                annotation: AnnotationInfo::Derive(vec![Argument::Var(CascadeString::from("foo"))]),
                parents: vec![types.get("domain").unwrap()],
            },
            InheritedAnnotation {
                annotation: AnnotationInfo::Derive(vec![Argument::Var(CascadeString::from("foo"))]),
                parents: vec![types.get("resource").unwrap()],
            },
        ];

        // Note that dedup sorts the parents
        let expected_dedup = vec![
            InheritedAnnotation {
                annotation: AnnotationInfo::MakeList,
                parents: vec![types.get("domain").unwrap()],
            },
            InheritedAnnotation {
                annotation: AnnotationInfo::Associate(Associated {
                    resources: BTreeSet::from([CascadeString::from("foo").into()]),
                }),
                parents: vec![types.get("resource").unwrap()],
            },
            InheritedAnnotation {
                annotation: AnnotationInfo::Associate(Associated {
                    resources: BTreeSet::from([CascadeString::from("bar").into()]),
                }),
                parents: vec![types.get("domain").unwrap(), types.get("resource").unwrap()],
            },
            InheritedAnnotation {
                annotation: AnnotationInfo::Associate(Associated {
                    resources: BTreeSet::from([CascadeString::from("baz").into()]),
                }),
                parents: vec![types.get("domain").unwrap()],
            },
            InheritedAnnotation {
                annotation: AnnotationInfo::Alias(CascadeString::from("alias")),
                parents: vec![types.get("domain").unwrap()],
            },
            // Not deduped, because derive doesn't dedup by design
            InheritedAnnotation {
                annotation: AnnotationInfo::Derive(vec![Argument::Var(CascadeString::from("foo"))]),
                parents: vec![types.get("domain").unwrap()],
            },
            InheritedAnnotation {
                annotation: AnnotationInfo::Derive(vec![Argument::Var(CascadeString::from("foo"))]),
                parents: vec![types.get("resource").unwrap()],
            },
        ];

        let inherited_anns = dedup_inherited_annotations(inherited_anns);

        assert_eq!(inherited_anns, expected_dedup);
    }
}
