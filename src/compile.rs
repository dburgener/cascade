// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use sexp::{atom_s, list, Sexp};
use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::TryFrom;

use crate::ast::{
    Annotations, Argument, CascadeString, Declaration, Expression, FuncCall, Module, PolicyFile,
    Statement,
};
use crate::constants;
use crate::context::Context as BlockContext;
use crate::error::{CascadeErrors, CompileError, ErrorItem, InternalError};
use crate::internal_rep::{
    argument_to_typeinfo, argument_to_typeinfo_vec, generate_sid_rules, type_slice_to_variant,
    Annotated, AnnotationInfo, ArgForValidation, Associated, BoundTypeInfo, ClassList, Context,
    FunctionArgument, FunctionInfo, FunctionMap, ModuleMap, Sid, TypeInfo, TypeMap,
    ValidatedModule, ValidatedStatement,
};

use codespan_reporting::files::SimpleFile;

pub fn compile_rules_one_file<'a>(
    p: &'a PolicyFile,
    classlist: &'a ClassList<'a>,
    type_map: &'a TypeMap,
    func_map: &'a FunctionMap<'a>,
) -> Result<BTreeSet<ValidatedStatement<'a>>, CascadeErrors> {
    do_rules_pass(
        &p.policy.exprs,
        type_map,
        func_map,
        classlist,
        None,
        &p.file,
    )
}

pub fn generate_sexp(
    type_map: &TypeMap,
    classlist: &ClassList,
    policy_rules: BTreeSet<ValidatedStatement>,
    func_map: &FunctionMap<'_>,
) -> Result<Vec<sexp::Sexp>, CascadeErrors> {
    let type_decl_list = organize_type_map(type_map)?;
    // TODO: The rest of compilation
    let cil_types = type_list_to_sexp(type_decl_list, type_map);
    let headers = generate_cil_headers(classlist);
    let cil_rules = rules_list_to_sexp(policy_rules);
    let cil_macros = func_map_to_sexp(func_map)?;
    let sid_statements =
        generate_sid_rules(generate_sids("kernel_sid", "security_sid", "unlabeled_sid"));

    let mut ret = headers;
    ret.extend(cil_types);
    ret.extend(cil_macros);
    ret.extend(cil_rules);
    ret.extend(sid_statements);
    Ok(ret)
}

// These are hardcoded, at least for now.
// This sets up MLS, UBAC, and RBAC properties of the system.
// Version 0.1 won't allow any language control of these properties, but that will come later.
// Until we can actually set these things in the language, we need some sensible defaults to make
// secilc happy. As we add the above listed security models, this should be refactored to set them
// in accordance with the policy
fn generate_cil_headers(classlist: &ClassList) -> Vec<sexp::Sexp> {
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

    ret
}

// TODO: Refactor below nearly identical functions to eliminate redundant code
pub fn extend_type_map(p: &PolicyFile, type_map: &mut TypeMap) -> Result<(), CascadeErrors> {
    // TODO: This only allows declarations at the top level.
    // Nested declarations are legal, but auto-associate with the parent, so they'll need special
    // handling when association is implemented
    let mut errors = CascadeErrors::new();
    for e in &p.policy.exprs {
        let d = match e {
            Expression::Decl(d) => d,
            _ => continue,
        };
        match d {
            Declaration::Type(t) => match TypeInfo::new(*t.clone(), &p.file) {
                Ok(new_type) => type_map.insert(t.name.to_string(), new_type),
                Err(e) => errors.append(e),
            },
            _ => continue,
        };
    }
    errors.into_result(())
}

pub fn get_built_in_types_map() -> TypeMap {
    let mut built_in_types = TypeMap::new();
    let list_coercions = constants::BUILT_IN_TYPES.iter().map(|t| *t == "perm");

    for (built_in, list_coercion) in constants::BUILT_IN_TYPES.iter().zip(list_coercions) {
        let built_in = built_in.to_string();
        built_in_types.insert(
            built_in.clone(),
            TypeInfo::make_built_in(built_in, list_coercion),
        );
    }

    //Special handling for sids.  These are temporary built in types that are handled differently
    let kernel_sid = TypeInfo {
        name: CascadeString::from("kernel_sid"),
        inherits: vec![CascadeString::from(constants::DOMAIN)],
        is_virtual: false,
        list_coercion: false,
        declaration_file: None,
        annotations: BTreeSet::new(),
        decl: None,
        bound_type: BoundTypeInfo::Unbound,
    };

    let security_sid = TypeInfo {
        name: CascadeString::from("security_sid"),
        inherits: vec![CascadeString::from(constants::RESOURCE)],
        is_virtual: false,
        list_coercion: false,
        declaration_file: None,
        annotations: BTreeSet::new(),
        decl: None,
        bound_type: BoundTypeInfo::Unbound,
    };

    let unlabeled_sid = TypeInfo {
        name: CascadeString::from("unlabeled_sid"),
        inherits: vec![CascadeString::from(constants::RESOURCE)],
        is_virtual: false,
        list_coercion: false,
        declaration_file: None,
        annotations: BTreeSet::new(),
        decl: None,
        bound_type: BoundTypeInfo::Unbound,
    };

    for sid in [kernel_sid, security_sid, unlabeled_sid] {
        built_in_types.insert(sid.name.to_string(), sid);
    }

    built_in_types
}

// TODO: Rewrite entirely with context.  Clones are temporary
pub fn get_global_bindings(
    p: &PolicyFile,
    types: &mut TypeMap,
    classlist: &mut ClassList,
    file: &SimpleFile<String, String>,
) -> Result<(), CascadeErrors> {
    let tm_clone = &types.clone(); // Temporary workaround to get it compiling
    for e in &p.policy.exprs {
        if let Expression::Stmt(Statement::LetBinding(l)) = e {
            let let_rvalue = ArgForValidation::from(&l.value);
            let (variant, bound_type) = match let_rvalue {
                ArgForValidation::List(v) => {
                    let ti_vec = argument_to_typeinfo_vec(
                        &v,
                        types,
                        classlist,
                        &BlockContext::new(tm_clone),
                        file,
                    )?;
                    let variant = type_slice_to_variant(&ti_vec, types)?;
                    (
                        variant.name.as_ref(),
                        BoundTypeInfo::List(v.iter().map(|s| s.to_string()).collect()),
                    )
                }
                a => {
                    let ti = argument_to_typeinfo(
                        &a,
                        types,
                        classlist,
                        &BlockContext::new(tm_clone),
                        file,
                    )?;
                    if ti.name.as_ref() == "perm" {
                        (
                            "perm",
                            match a {
                                ArgForValidation::Var(s) => BoundTypeInfo::Single(s.to_string()),
                                _ => return Err(InternalError::new().into()),
                            },
                        )
                    } else {
                        (
                            ti.name.as_ref(),
                            BoundTypeInfo::Single(ti.name.to_string().clone()),
                        )
                    }
                }
            };
            if variant == "perm" {
                classlist.insert_perm_set(&l.name.to_string(), bound_type.get_contents_as_vec())
            } else {
                let new_type = TypeInfo::new_bound_type(
                    l.name.clone(),
                    variant,
                    file,
                    bound_type,
                    &l.annotations,
                )?;
                types.insert(l.name.to_string(), new_type);
            }
        }
    }
    Ok(())
}

pub fn build_func_map<'a>(
    exprs: &'a [Expression],
    types: &'a TypeMap,
    parent_type: Option<&'a TypeInfo>,
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
                let type_being_parsed = match types.get(&t.name.to_string()) {
                    Some(t) => t,
                    None => return Err(ErrorItem::Internal(InternalError::new()).into()),
                };
                decl_map.extend(build_func_map(
                    &t.expressions,
                    types,
                    Some(type_being_parsed),
                    file,
                )?);
            }
            Declaration::Func(f) => {
                // FIXME: error out for duplicate entries
                decl_map.insert(
                    f.get_cil_name(),
                    FunctionInfo::new(&**f, types, parent_type, file)?,
                );
            }
            Declaration::Mod(_) => continue,
        };
    }

    Ok(decl_map)
}

// Mutate hash map to set the validated body
pub fn validate_functions<'a, 'b>(
    functions: &'a mut FunctionMap<'b>,
    types: &'b TypeMap,
    class_perms: &'b ClassList,
    functions_copy: &'b FunctionMap<'b>,
) -> Result<(), CascadeErrors> {
    let mut errors = CascadeErrors::new();
    let mut classes_to_virtual_functions = BTreeMap::new();
    for function in functions.values_mut() {
        match function.validate_body(
            functions_copy,
            types,
            class_perms,
            function.declaration_file,
        ) {
            Ok(_) => (),
            Err(e) => errors.append(e),
        }
        if function.is_virtual {
            if let Some(func_class) = function.class {
                classes_to_virtual_functions
                    .entry(&func_class.name)
                    .or_insert(BTreeSet::new())
                    .insert(&function.name);
            }
        }
    }
    // Validate that all required functions exist
    for setype in types.values() {
        for parent in &setype.inherits {
            for virtual_function_name in classes_to_virtual_functions
                .get(&parent)
                .unwrap_or(&BTreeSet::new())
            {
                if !setype.defines_function(virtual_function_name, functions_copy) {
                    errors.append(CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
                                &format!("{} does not define a function named {}", setype.name, virtual_function_name),
                                setype.declaration_file.as_ref(),
                                parent.get_range(),
                                &format!("All types inheriting {} are required to implement {} because it is marked as virtual", parent, virtual_function_name))))
                }
            }
        }
    }

    errors.into_result(())
}

pub fn validate_modules<'a>(
    policies: &'a [PolicyFile],
    types: &'a TypeMap,
    all_validated_modules: &'a mut ModuleMap<'a>,
) -> Result<(), CascadeErrors> {
    let mut errors = CascadeErrors::new();

    // Store all modules across files in a vector
    let mut modules_vec: Vec<(&SimpleFile<String, String>, &Module)> = Vec::new();
    for p in policies {
        for e in &p.policy.exprs {
            if let Expression::Decl(Declaration::Mod(m)) = e {
                modules_vec.push((&p.file, m));
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
            if !&modules_vec.iter().any(|&x| x.1.name == m.as_ref()) {
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
        all_validated_modules.insert(
            module.name.to_string(),
            ValidatedModule::new(module.name.clone(), type_infos, child_modules),
        );
    }
    errors.into_result(())
}

fn find_module_cycles<'a>(
    module_to_check: &Module,
    modules_vec: &[(&SimpleFile<String, String>, &'a Module)],
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
                            &format!(
                                "{}s within modules must be declared elsewhere",
                                content_type
                            ),
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
                    &format!(
                        "{}s within modules must be declared elsewhere",
                        content_type
                    ),
                ),
            )),
        }
    }
    ret
}

// If a type couldn't be organized, it is either a cycle or a non-existant parent somewhere
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

fn get_synthetic_resource_name(
    dom_info: &TypeInfo,
    associated_resource: &CascadeString,
) -> CascadeString {
    format!("{}-{}", dom_info.name, associated_resource).into()
}

fn create_synthetic_resource(
    types: &TypeMap,
    dom_info: &TypeInfo,
    associated_parent: Option<&TypeInfo>,
    class: &TypeInfo,
    class_string: &CascadeString,
    global_exprs: &mut HashSet<Expression>,
) -> Result<CascadeString, ErrorItem> {
    if !class.is_resource(types) {
        return Err(CompileError::new(
            "not a resource",
            dom_info
                .declaration_file
                .as_ref()
                .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?,
            class_string.get_range(),
            "This should be a resource, not a domain.",
        )
        .into());
    }

    // Creates a synthetic resource declaration.
    let mut dup_res_decl = class.decl.as_ref().ok_or_else(InternalError::new)?.clone();
    let res_name = get_synthetic_resource_name(dom_info, &class.name);
    dup_res_decl.name = res_name.clone();
    // See TypeDecl::new() in parser.lalrpop for resource inheritance.
    let parent_name = match associated_parent {
        None => class.name.clone(),
        Some(parent) => get_synthetic_resource_name(parent, &class.name),
    };
    dup_res_decl.inherits = vec![parent_name, constants::RESOURCE.into()];
    // Virtual resources become concrete when associated to concrete types
    dup_res_decl.is_virtual = dup_res_decl.is_virtual && dom_info.is_virtual;
    let dup_res_is_virtual = dup_res_decl.is_virtual;
    dup_res_decl.annotations = Annotations::new();
    dup_res_decl
        .expressions
        .iter_mut()
        .for_each(|e| e.set_class_name_if_decl(res_name.clone()));

    dup_res_decl.expressions = dup_res_decl
        .expressions
        .into_iter()
        // If dup_res_decl is concrete, do not inherit virtual functions
        .filter(|e| dup_res_is_virtual || !e.is_virtual_function())
        .collect();
    if !global_exprs.insert(Expression::Decl(Declaration::Type(Box::new(dup_res_decl)))) {
        return Err(InternalError::new().into());
    }
    Ok(res_name)
}

fn interpret_associate(
    global_exprs: &mut HashSet<Expression>,
    local_exprs: &mut HashSet<Expression>,
    funcs: &FunctionMap<'_>,
    types: &TypeMap,
    associate: &Associated,
    associated_parent: Option<&TypeInfo>,
    dom_info: &TypeInfo,
) -> Result<(), CascadeErrors> {
    // Only allow a set of specific annotation names and strictly check their arguments.
    // TODO: Add tests to verify these checks.

    let mut errors = CascadeErrors::new();
    let mut potential_resources: BTreeMap<_, _> = associate
        .resources
        .iter()
        .map(|r| (r.as_ref(), (r, false)))
        .collect();

    // Finds the associated call.
    for func_info in funcs.values().filter(|f| f.is_associated_call) {
        if let Some(class) = func_info.class {
            if let Some((res, seen)) = potential_resources.get_mut(class.name.as_ref()) {
                *seen = if *seen {
                    errors.add_error(ErrorItem::Compile(CompileError::new(
                        "multiple @associated_call in the same resource",
                        func_info.declaration_file,
                        func_info.decl.name.get_range(),
                        "Only one function in the same resource can be annotated with @associated_call.",
                    )));
                    continue;
                } else {
                    true
                };

                let res_name = match create_synthetic_resource(
                    types,
                    dom_info,
                    associated_parent,
                    class,
                    res,
                    global_exprs,
                ) {
                    Ok(n) => n,
                    Err(e) => {
                        errors.add_error(e);
                        continue;
                    }
                };

                // Creates a synthetic call.
                let new_call = Expression::Stmt(Statement::Call(Box::new(FuncCall::new(
                    Some(res_name),
                    func_info.name.clone().into(),
                    vec![Argument::Var("this".into())],
                ))));
                if !local_exprs.insert(new_call) {
                    return Err(ErrorItem::Internal(InternalError::new()).into());
                }
            }
        }
    }

    for (_, (res, _)) in potential_resources.iter().filter(|(_, (_, seen))| !seen) {
        match types.get(res.as_ref()) {
            Some(class) => {
                match create_synthetic_resource(
                    types,
                    dom_info,
                    associated_parent,
                    class,
                    res,
                    global_exprs,
                ) {
                    Ok(_) => {}
                    Err(e) => errors.add_error(e),
                }
            }
            None => errors.add_error(CompileError::new(
                "unknown resource",
                dom_info
                    .declaration_file
                    .as_ref()
                    .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?,
                res.get_range(),
                "didn't find this resource in the policy",
            )),
        }
    }

    errors.into_result(())
}

// domain -> related expressions
type AssociateExprs = HashMap<CascadeString, HashSet<Expression>>;

#[derive(Clone)]
struct InheritedAnnotation<'a> {
    annotation: &'a AnnotationInfo,
    parent: Option<&'a TypeInfo>,
}

fn interpret_inherited_annotations<'a, T>(
    global_exprs: &mut HashSet<Expression>,
    associate_exprs: &mut AssociateExprs,
    funcs: &FunctionMap<'_>,
    types: &TypeMap,
    dom_info: &'a TypeInfo,
    extra_annotations: T,
) -> Result<(), CascadeErrors>
where
    T: Iterator<Item = InheritedAnnotation<'a>>,
{
    let mut errors = CascadeErrors::new();

    let local_exprs = match associate_exprs.entry(dom_info.name.clone()) {
        // Ignores already processed domains.
        Entry::Occupied(_) => return Ok(()),
        vacant => vacant.or_default(),
    };
    for inherited in dom_info
        .annotations
        .iter()
        .map(|a| InheritedAnnotation {
            annotation: a,
            parent: None,
        })
        .chain(extra_annotations)
    {
        if let AnnotationInfo::Associate(ref associate) = inherited.annotation {
            match interpret_associate(
                global_exprs,
                local_exprs,
                funcs,
                types,
                associate,
                inherited.parent,
                dom_info,
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
    funcs: &FunctionMap<'_>,
    types: &'a TypeMap,
    dom_info: &'a TypeInfo,
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
                match inherit_annotations(global_exprs, associate_exprs, funcs, types, parent_ti) {
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
    match interpret_inherited_annotations(
        global_exprs,
        associate_exprs,
        funcs,
        types,
        dom_info,
        inherited_annotations.iter().cloned(),
    ) {
        Ok(()) => {}
        Err(e) => errors.append(e),
    }

    errors.into_result_with(|| {
        dom_info
            .annotations
            .iter()
            .map(|a| InheritedAnnotation {
                annotation: a,
                parent: Some(dom_info),
            })
            .chain(inherited_annotations.into_iter().map(|mut a| {
                a.parent = Some(dom_info);
                a
            }))
            .collect()
    })
}

pub fn apply_associate_annotations<'a>(
    types: &'a TypeMap,
    funcs: &FunctionMap<'_>,
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
            funcs,
            types,
            type_info,
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
                .get(&k.to_string())
                .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
                .decl
                .as_ref()
                .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
                .clone();
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

// Temporary check for non-virtual inheritance
// TODO: remove when adding support for non-virtual inheritance
fn check_non_virtual_inheritance(types: &TypeMap) -> Result<(), CascadeErrors> {
    for t in types.values() {
        for parent in &t.inherits {
            if let Some(p) = types.get(parent.as_ref()) {
                if !p.is_virtual {
                    return Err(ErrorItem::make_compile_or_internal_error(
                        "Inheriting from a non-virtual type is not yet supported",
                        t.declaration_file.as_ref(),
                        parent.get_range(),
                        "This type is not virtual",
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
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

    // TODO: This should be allowed, but isn't yet supported.  Remove this check once support for
    // non-virtual inheritance is added
    check_non_virtual_inheritance(types)?;

    while !tmp_types.is_empty() {
        let mut current_pass_types: Vec<&TypeInfo> = Vec::new();

        for ti in tmp_types.values() {
            let mut wait = false;

            // TODO: Do we need to consider the case when inherits is empty?  Theoretically it
            // should have always been populated with at least domain or resource by the parser.
            // Should probably return an internal error if that hasn't happened
            for key in &ti.inherits {
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
            // We can't satify the parents for all types
            return Err(generate_type_no_parent_errors(
                tmp_types.values().copied().collect(),
                types,
            ));
        }
        for t in &current_pass_types {
            tmp_types.remove(&t.name.to_string());
        }
        out.append(&mut current_pass_types);
    }
    Ok(out)
}

// Gather all the alias annotations for types and functions and return them so they can be stored
// in the maps
pub fn collect_aliases<'a, I, T>(aliasable_map: I) -> BTreeMap<String, String>
where
    I: Iterator<Item = (&'a String, T)>,
    T: Annotated,
{
    let mut aliases = BTreeMap::new();
    for (k, v) in aliasable_map {
        for a in v.get_annotations() {
            if let AnnotationInfo::Alias(a) = a {
                aliases.insert(a.to_string(), k.clone());
            }
        }
    }

    aliases
}

fn do_rules_pass<'a>(
    exprs: &'a [Expression],
    types: &'a TypeMap,
    funcs: &'a FunctionMap<'a>,
    class_perms: &ClassList<'a>,
    parent_type: Option<&'a TypeInfo>,
    file: &'a SimpleFile<String, String>,
) -> Result<BTreeSet<ValidatedStatement<'a>>, CascadeErrors> {
    let mut ret = BTreeSet::new();
    let mut errors = CascadeErrors::new();
    let func_args = match parent_type {
        Some(t) => vec![FunctionArgument::new_this_argument(t)],
        None => Vec::new(),
    };
    let mut local_context = BlockContext::new_from_args(&func_args, types);
    for e in exprs {
        match e {
            Expression::Stmt(s) => {
                match ValidatedStatement::new(
                    s,
                    funcs,
                    types,
                    class_perms,
                    &mut local_context,
                    parent_type,
                    file,
                ) {
                    Ok(mut s) => ret.append(&mut s),
                    Err(e) => errors.append(e),
                }
            }
            Expression::Decl(Declaration::Type(t)) => {
                let type_being_parsed = match types.get(&t.name.to_string()) {
                    Some(t) => t,
                    None => return Err(ErrorItem::Internal(InternalError::new()).into()),
                };
                match do_rules_pass(
                    &t.expressions,
                    types,
                    funcs,
                    class_perms,
                    Some(type_being_parsed),
                    file,
                ) {
                    Ok(mut r) => ret.append(&mut r),
                    Err(e) => errors.append(e),
                }
            }
            _ => {}
        }
    }

    errors.into_result(ret)
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
            atom_s(ti.name.as_ref()),
        ]));
    }

    for i in &ti.inherits {
        ret.push(list(&[
            atom_s("typeattributeset"),
            atom_s(i.as_ref()),
            list(&[atom_s(ti.name.as_ref())]),
        ]));
    }

    for a in &ti.annotations {
        if let AnnotationInfo::Alias(a) = a {
            ret.push(list(&[atom_s("typealias"), atom_s(a.as_ref())]));
            ret.push(list(&[
                atom_s("typealiasactual"),
                atom_s(a.as_ref()),
                atom_s(ti.name.as_ref()),
            ]));
        }
    }
    ret
}

fn rules_list_to_sexp<'a, T>(rules: T) -> Vec<sexp::Sexp>
where
    T: IntoIterator<Item = ValidatedStatement<'a>>,
{
    rules.into_iter().map(|r| Sexp::from(&r)).collect()
}

fn generate_sids<'a>(
    kernel_sid: &'a str,
    security_sid: &'a str,
    unlabeled_sid: &'a str,
) -> Vec<Sid<'a>> {
    vec![
        Sid::new(
            "kernel",
            Context::new(true, None, None, Cow::Borrowed(kernel_sid), None, None),
        ),
        Sid::new(
            "security",
            Context::new(false, None, None, Cow::Borrowed(security_sid), None, None),
        ),
        Sid::new(
            "unlabeled",
            Context::new(false, None, None, Cow::Borrowed(unlabeled_sid), None, None),
        ),
    ]
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
        let mut types = get_built_in_types_map();
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
        let mut types = get_built_in_types_map();
        let mut foo_type = TypeInfo::new(
            TypeDecl::new(
                CascadeString::from("foo"),
                vec![CascadeString::from(constants::DOMAIN)],
                Vec::new(),
            ),
            &SimpleFile::new(String::new(), String::new()),
        )
        .unwrap();
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
        .unwrap();
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
        .unwrap();

        types.insert("foo".to_string(), foo_type);
        types.insert("bar".to_string(), bar_type);
        types.insert("baz".to_string(), baz_type);

        let _type_vec = organize_type_map(&types).unwrap();

        // TODO: reenable this.  The built in sid types break the ordering assumptions here
        // Once they have been removed, the below checks should work again
        // Skip built in types
        //assert_eq!(type_vec[type_vec.len() - 3].name, "foo");
        //assert_eq!(type_vec[type_vec.len() - 2].name, "bar");
        //assert_eq!(type_vec[type_vec.len() - 1].name, "baz");
    }
}
