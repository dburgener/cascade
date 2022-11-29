// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use sexp::{atom_s, list, Sexp};
use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::TryFrom;

use crate::ast::{
    Argument, CascadeString, Declaration, Expression, FuncCall, LetBinding, Module, PolicyFile,
    Statement, System,
};
use crate::constants;
use crate::context::{BlockType, Context as BlockContext};
use crate::error::{CascadeErrors, CompileError, ErrorItem, InternalError};
use crate::internal_rep::{
    argument_to_typeinfo, argument_to_typeinfo_vec, generate_sid_rules, type_slice_to_variant,
    validate_derive_args, Annotated, AnnotationInfo, ArgForValidation, Associated, BoundTypeInfo,
    ClassList, Context, FunctionArgument, FunctionInfo, FunctionMap, ModuleMap, Sid, SystemMap,
    TypeInfo, TypeMap, ValidatedCall, ValidatedModule, ValidatedStatement, ValidatedSystem,
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
    system_configurations: &Option<&BTreeMap<String, &Argument>>,
) -> Result<Vec<sexp::Sexp>, CascadeErrors> {
    let type_decl_list = organize_type_map(type_map)?;
    // TODO: The rest of compilation
    let cil_types = type_list_to_sexp(type_decl_list, type_map);
    let headers = generate_cil_headers(classlist, *system_configurations);
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
fn generate_cil_headers(
    classlist: &ClassList,
    system_configurations: Option<&BTreeMap<String, &Argument>>,
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
    if let Some(c) = system_configurations {
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
            Declaration::Type(t) => {
                if !t.is_extension {
                    match TypeInfo::new(*t.clone(), &p.file) {
                        Ok(new_type) => type_map.insert(t.name.to_string(), new_type)?,
                        Err(e) => errors.append(e),
                    }
                }
            }
            _ => continue,
        };
    }
    errors.into_result(())
}

// Verify that all uses of the extend keyword correspond to types declared elsewhere
pub fn verify_extends(p: &PolicyFile, type_map: &TypeMap) -> Result<(), CascadeErrors> {
    let mut errors = CascadeErrors::new();
    for e in &p.policy.exprs {
        if let Expression::Decl(Declaration::Type(td)) = e {
            if td.is_extension && type_map.get(td.name.as_ref()).is_none() {
                errors.append(CompileError::new(
                        &format!("{} is undeclared", td.name),
                        &p.file,
                        td.name.get_range(),
                        "In order to extend this type, it must be declared elsewhere (maybe you want to declare it instead?)").into());
            }
        }
    }
    errors.into_result(())
}

pub fn get_built_in_types_map() -> Result<TypeMap, CascadeErrors> {
    let mut built_in_types = TypeMap::new();
    let list_coercions = constants::BUILT_IN_TYPES
        .iter()
        .map(|t| *t == "perm" || *t == "*");

    for (built_in, list_coercion) in constants::BUILT_IN_TYPES.iter().zip(list_coercions) {
        let built_in = built_in.to_string();
        built_in_types.insert(
            built_in.clone(),
            TypeInfo::make_built_in(built_in, list_coercion),
        )?;
    }

    // '*' is a special case.  It can be used to mean "all" of the things.  For now, the meaning of
    // "all" is only defined for strings (in annotation contexts where the annotation is
    // responsible for figuring it out) and perms (all permissions for a given object
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
        is_virtual: false,
        is_trait: false,
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
        is_trait: false,
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
        is_trait: false,
        list_coercion: false,
        declaration_file: None,
        annotations: BTreeSet::new(),
        decl: None,
        bound_type: BoundTypeInfo::Unbound,
    };

    for sid in [kernel_sid, security_sid, unlabeled_sid] {
        built_in_types.insert(sid.name.to_string(), sid)?;
    }

    // Add self as children of resource
    if let Some(i) = built_in_types.get_mut("self") {
        i.inherits = vec![CascadeString::from(constants::RESOURCE)];
    }

    Ok(built_in_types)
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
                        &BlockContext::new(BlockType::Global, tm_clone, None),
                        Some(file),
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
                        &BlockContext::new(BlockType::Global, tm_clone, None),
                        Some(file),
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
                classlist.insert_perm_set(l.name.as_ref(), bound_type.get_contents_as_vec())
            } else {
                let new_type = TypeInfo::new_bound_type(
                    l.name.clone(),
                    variant,
                    file,
                    bound_type,
                    &l.annotations,
                )?;
                types.insert(l.name.to_string(), new_type)?;
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
                let type_being_parsed = match types.get(t.name.as_ref()) {
                    Some(t) => t,
                    // If a type exists but is not in the system, skip it for now
                    // TODO: Add extra validation for types defined, but not in the system
                    None => continue,
                };
                decl_map.try_extend(build_func_map(
                    &t.expressions,
                    types,
                    Some(type_being_parsed),
                    file,
                )?)?;
            }
            Declaration::Func(f) => {
                decl_map.insert(
                    f.get_cil_name(),
                    FunctionInfo::new(f, types, parent_type, file)?,
                )?;
            }
            _ => continue,
        };
    }

    Ok(decl_map)
}

// Mutate hash map to set the validated body
pub fn validate_functions<'a>(
    mut functions: FunctionMap<'a>,
    types: &'a TypeMap,
    class_perms: &'a ClassList,
    functions_copy: &'a FunctionMap<'a>,
) -> Result<FunctionMap<'a>, CascadeErrors> {
    let mut errors = CascadeErrors::new();
    let mut classes_to_required_functions: BTreeMap<&CascadeString, BTreeSet<&str>> =
        BTreeMap::new();
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
    }

    derive_functions(&mut functions, types, class_perms)?;

    for function in functions.values() {
        if let Some(func_class) = function.class {
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
        for parent in &setype.inherits {
            for required_function_name in classes_to_required_functions
                .get(&parent)
                .unwrap_or(&BTreeSet::new())
            {
                if !setype.defines_function(required_function_name, &functions) {
                    errors.append(CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
                                &format!("{} does not define a function named {}", setype.name, required_function_name),
                                setype.declaration_file.as_ref(),
                                parent.get_range(),
                                // TODO: fix message
                                &format!("All types inheriting {} are required to implement {} because it is marked as virtual", parent, required_function_name))))
                }
            }
        }
    }

    errors.into_result(functions)
}

fn derive_functions<'a, 'b>(
    functions: &'a mut FunctionMap<'b>,
    types: &'b TypeMap,
    class_perms: &'b ClassList,
) -> Result<(), CascadeErrors> {
    for t in types.values() {
        for annotation in t.get_annotations() {
            if let AnnotationInfo::Derive(derive_args) = annotation {
                handle_derive(t, derive_args, functions, types, class_perms)?;
            }
        }
    }
    Ok(())
}

fn handle_derive<'a>(
    target_type: &'a TypeInfo,
    derive_args: &[Argument],
    functions: &mut FunctionMap<'a>,
    types: &'a TypeMap,
    class_perms: &ClassList,
) -> Result<(), CascadeErrors> {
    let (parents, mut func_names) =
        validate_derive_args(target_type, derive_args, types, class_perms)?;

    if vec![CascadeString::from("*")] == func_names {
        func_names = get_all_function_names(&parents, &*functions);
    }

    for f in func_names {
        let derived_function = FunctionInfo::new_derived_function(
            &f,
            target_type,
            &parents,
            functions,
            target_type.declaration_file.as_ref().unwrap(),
        )?;
        functions.insert(derived_function.get_cil_name(), derived_function)?;
    }
    Ok(())
}

pub fn validate_modules<'a, 'b>(
    policies: &'b [PolicyFile],
    types: &'b TypeMap,
    module_map: &'a mut ModuleMap<'b>,
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

pub fn validate_systems<'a, 'b>(
    policies: &'b [PolicyFile],
    module_map: &'b ModuleMap,
    system_map: &'a mut SystemMap<'b>,
) -> Result<(), CascadeErrors> {
    let mut errors = CascadeErrors::new();

    // Store all systems across files in a vector
    let mut systems_vec: Vec<(&SimpleFile<String, String>, &System)> = Vec::new();
    for p in policies {
        for e in &p.policy.exprs {
            if let Expression::Decl(Declaration::System(s)) = e {
                systems_vec.push((&p.file, s));
            }
        }
    }

    for (file, system) in &systems_vec {
        let mut system_modules = BTreeSet::new();
        let mut configs = BTreeMap::new();

        // Check that a system has at least 1 module
        if system.modules.is_empty() {
            errors.append(CascadeErrors::from(
                ErrorItem::make_compile_or_internal_error(
                    &format!(
                        "System {} cannot be declared with no modules",
                        system.name.as_ref()
                    ),
                    Some(file),
                    system.name.get_range(),
                    "Add a module to the system",
                ),
            ));
        }

        // Validate that the modules of a system exist
        for m in &system.modules {
            match module_map.get(m.as_ref()) {
                Some(module) => {
                    system_modules.insert(module);
                }
                None => errors.append(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        &format!("Module {} does not exist", m.as_ref()),
                        Some(file),
                        m.get_range(),
                        "modules within systems must be declared elsewhere",
                    ),
                )),
            }
        }
        // Validate the system's configurations
        for c in &system.configurations {
            let config = c.name.as_ref();
            let options = match config {
                constants::SYSTEM_TYPE => vec!["standard"],
                constants::MONOLITHIC => vec!["true", "false"],
                constants::HANDLE_UNKNOWN_PERMS => vec!["allow", "deny", "reject"],
                _ => {
                    errors.append(CascadeErrors::from(
                        ErrorItem::make_compile_or_internal_error(
                            &format!("{} is not a supprted configuration", c.name.as_ref()),
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
            match insert_config(file, system, &mut configs, c, config, options) {
                Ok(()) => (),
                Err(e) => errors.append(e),
            }
        }
        // Check for required configurations
        match check_required_config(file, system, &configs, constants::HANDLE_UNKNOWN_PERMS) {
            Ok(()) => (),
            Err(e) => errors.append(e),
        }

        match system_map.insert(
            system.name.to_string(),
            ValidatedSystem::new(
                system.name.clone(),
                system_modules,
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
    system: &System,
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
                    "The configuration {} is included more than once in system {}",
                    config_name, system.name
                ),
                Some(file),
                config.name.get_range(),
                "Each configuration can only be included once in each system",
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
                        &format!(
                            "The supported options for {} are {:?}",
                            config_name, valid_values
                        ),
                    ),
                ))
            }
        }
    }
    ret.into_result(())
}

fn check_required_config<'a>(
    file: &SimpleFile<String, String>,
    system: &System,
    configs: &BTreeMap<String, &'a Argument>,
    config_name: &str,
) -> Result<(), CascadeErrors> {
    let mut ret = CascadeErrors::new();
    if !configs.contains_key(&config_name.to_string()) {
        ret.append(CascadeErrors::from(
            ErrorItem::make_compile_or_internal_error(
                &format!(
                    "{} configuration must be included in the system",
                    config_name
                ),
                Some(file),
                None,
                &format!(
                    "Add a {} configuration to system {}",
                    config_name, system.name
                ),
            ),
        ));
    }
    ret.into_result(())
}

// Get the types, functions, and policy rules for the system.
pub fn get_reduced_infos<'a>(
    policies: &'a [PolicyFile],
    classlist: &'a ClassList,
    system: &'a ValidatedSystem,
    type_map: &'a TypeMap,
    module_map: &'a ModuleMap,
) -> Result<Vec<sexp::Sexp>, CascadeErrors> {
    let ret = CascadeErrors::new();
    let mut new_type_map = get_built_in_types_map()?;

    // Get the reduced type infos
    for module in &system.modules {
        get_reduced_types(module, &mut new_type_map, type_map, module_map)?;
    }

    // Generate type aliases for the new reduced type map
    let new_t_aliases = collect_aliases(new_type_map.iter());
    new_type_map.set_aliases(new_t_aliases);

    // Get the function infos
    let new_func_map = get_funcs(policies, &new_type_map)?;

    // Validate functions, including deriving functions from annotations
    let new_func_map_copy = new_func_map.clone(); // In order to read function info while mutating
    let new_func_map =
        validate_functions(new_func_map, &new_type_map, classlist, &new_func_map_copy)?;

    // Get the policy rules
    let new_policy_rules = get_policy_rules(policies, &new_type_map, classlist, &new_func_map)?;

    // generate_sexp(...) is called at this step because new_func_map and new_policy_rules,
    // which are needed for the generate_sexp call, cannot be returned from this function.
    // This is because they reference the local variable, new_func_map_copy, which cannot be
    // moved out due to the lifetimes in validate_functions(...).
    let new_cil_tree = generate_sexp(
        &new_type_map,
        classlist,
        new_policy_rules,
        &new_func_map,
        &Some(&system.configurations),
    )?;

    ret.into_result(new_cil_tree)
}

// This is a recusive function that gets only the relevant types from the type map.
// The reduced types are the types in the module and the types in any of that modules' child modules.
// Parents of those types are also automatically included.
// The types are cloned so that each system TypeMap can own its own types.
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
                if !reduced_type_map.iter().any(|(k, _v)| k == parent.as_ref()) {
                    reduced_type_map.insert(parent.to_string(), parent_type_info.clone())?;
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

pub fn get_funcs<'a>(
    policies: &'a [PolicyFile],
    reduced_type_map: &'a TypeMap,
) -> Result<FunctionMap<'a>, CascadeErrors> {
    let mut ret = CascadeErrors::new();
    let mut reduced_func_map = FunctionMap::new();
    // Collect all function declarations
    for p in policies {
        let mut m = match build_func_map(&p.policy.exprs, reduced_type_map, None, &p.file) {
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
    let f_aliases = collect_aliases(reduced_func_map.iter());
    reduced_func_map.set_aliases(f_aliases);
    ret.into_result(reduced_func_map)
}

pub fn get_policy_rules<'a>(
    policies: &'a [PolicyFile],
    reduced_type_map: &'a TypeMap,
    classlist: &'a ClassList<'a>,
    reduced_func_map: &'a FunctionMap<'a>,
) -> Result<BTreeSet<ValidatedStatement<'a>>, CascadeErrors> {
    let mut ret = CascadeErrors::new();
    let mut reduced_policy_rules = BTreeSet::new();

    // Add derived associated calls
    let mut calls = call_derived_associated_calls(reduced_type_map, reduced_func_map, classlist)?;
    reduced_policy_rules.append(&mut calls);

    for p in policies {
        let mut r = match compile_rules_one_file(p, classlist, reduced_type_map, reduced_func_map) {
            Ok(r) => r,
            Err(e) => {
                ret.append(e);
                continue;
            }
        };
        reduced_policy_rules.append(&mut r);
    }
    // Stops if something went wrong for this major step.
    ret.into_result(reduced_policy_rules)
}

fn get_all_function_names(
    type_names: &BTreeSet<&CascadeString>,
    functions: &FunctionMap,
) -> Vec<CascadeString> {
    let mut ret = Vec::new();
    for f in functions.values() {
        if let Some(class) = f.class {
            if type_names.contains(&&class.name)
                && !ret.contains(&CascadeString::from(&f.name as &str))
            {
                ret.push(CascadeString::from(&f.name as &str));
            }
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
    format!("{}.{}", dom_info.name, associated_resource).into()
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
    // The synthetic resource keeps some, but not all annotations from its parent.
    // Specifically, Makelist and derive are kept from the parent
    // TODO: This would be cleaner if we convert to AnnotationInfos first and implent the logic as
    // a member funtion in AnnotationInfo
    // See https://github.com/dburgener/cascade/pull/39#discussion_r999510493 for fuller discussion
    dup_res_decl
        .annotations
        .annotations
        .retain(|a| a.name.as_ref() == "makelist" || a.name.as_ref() == "derive");

    dup_res_decl
        .expressions
        .iter_mut()
        .for_each(|e| e.set_class_name_if_decl(res_name.clone()));

    dup_res_decl
        .expressions
        // If dup_res_decl is concrete, do not inherit virtual functions
        .retain(|e| dup_res_is_virtual || !e.is_virtual_function());
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
                        func_info.get_declaration_range(),
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
                let new_call = make_associated_call(res_name, func_info);
                if !local_exprs.insert(Expression::Stmt(Statement::Call(Box::new(new_call)))) {
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

fn make_associated_call(resource_name: CascadeString, func_info: &FunctionInfo) -> FuncCall {
    FuncCall::new(
        Some(resource_name),
        func_info.name.clone().into(),
        vec![Argument::Var("this".into())],
    )
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

    let mut errors = CascadeErrors::new();

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
                if key == "self" {
                    errors.add_error(ErrorItem::make_compile_or_internal_error(
                        "Inheriting from self is not supported",
                        ti.declaration_file.as_ref(),
                        key.get_range(),
                        "Cannot inherit self",
                    ));
                    continue;
                }
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
    errors.into_result(out)
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

pub fn call_derived_associated_calls<'a>(
    types: &TypeMap,
    funcs: &FunctionMap<'a>,
    class_perms: &ClassList,
) -> Result<BTreeSet<ValidatedStatement<'a>>, CascadeErrors> {
    let mut ret = BTreeSet::new();
    let mut errors = CascadeErrors::new();
    for t in types.values() {
        if !t.is_domain(types) {
            continue;
        }
        for a in &t.annotations {
            if let AnnotationInfo::Associate(associations) = a {
                for f in funcs.values() {
                    if f.is_derived && f.is_associated_call {
                        let resource_name = match f.class {
                            Some(n) => n.name.clone(),
                            None => {
                                continue;
                            }
                        };
                        if associations.resources.iter().any(|r| {
                            [t.name.as_ref(), r.as_ref()].join(".") == resource_name.as_ref()
                        }) {
                            let call = make_associated_call(resource_name, f);
                            let args = vec![FunctionArgument::new_this_argument(t)];
                            let mut local_context =
                                BlockContext::new(BlockType::Domain, types, Some(t));
                            local_context.insert_function_args(&args);

                            let validated_call = match ValidatedCall::new(
                                &call,
                                funcs,
                                types,
                                class_perms,
                                None,
                                &local_context,
                                f.declaration_file,
                            ) {
                                Ok(c) => c,
                                Err(e) => {
                                    errors.append(e);
                                    continue;
                                }
                            };

                            ret.insert(ValidatedStatement::Call(Box::new(validated_call)));
                        }
                    }
                }
            }
        }
    }
    errors.into_result(ret)
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

    let block_type = match parent_type {
        Some(parent) => match parent.get_built_in_variant(types) {
            Some("resource") => BlockType::Resource,
            Some("domain") => BlockType::Domain,
            _ => {
                return Err(ErrorItem::Internal(InternalError::new()).into());
            }
        },
        None => BlockType::Global,
    };

    let mut local_context = BlockContext::new(block_type, types, parent_type);
    local_context.insert_function_args(&func_args);

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
                let type_being_parsed = match types.get(t.name.as_ref()) {
                    Some(t) => t,
                    // If a type exists but is not in the system, skip it for now
                    None => continue,
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
            atom_s(ti.name.get_cil_name().as_ref()),
        ]));
    }

    for i in &ti.inherits {
        if let Some(t) = type_map.get(i.as_ref()) {
            if t.is_trait() {
                continue;
            }
        }
        ret.push(list(&[
            atom_s("typeattributeset"),
            atom_s(i.get_cil_name().as_ref()),
            list(&[atom_s(ti.name.get_cil_name().as_ref())]),
        ]));
    }

    for a in &ti.annotations {
        if let AnnotationInfo::Alias(a) = a {
            ret.push(list(&[atom_s("typealias"), atom_s(a.as_ref())]));
            ret.push(list(&[
                atom_s("typealiasactual"),
                atom_s(a.as_ref()),
                atom_s(ti.name.get_cil_name().as_ref()),
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

        types.insert("foo".to_string(), foo_type).unwrap();
        types.insert("bar".to_string(), bar_type).unwrap();
        types.insert("baz".to_string(), baz_type).unwrap();

        let _type_vec = organize_type_map(&types).unwrap();

        // TODO: reenable this.  The built in sid types break the ordering assumptions here
        // Once they have been removed, the below checks should work again
        // Skip built in types
        //assert_eq!(type_vec[type_vec.len() - 3].name, "foo");
        //assert_eq!(type_vec[type_vec.len() - 2].name, "bar");
        //assert_eq!(type_vec[type_vec.len() - 1].name, "baz");
    }
}
