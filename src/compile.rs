// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use sexp::{atom_s, list, Sexp};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::TryFrom;

use crate::ast::{
    Annotations, Argument, Declaration, Expression, FuncCall, HLLString, PolicyFile, Statement,
};
use crate::constants;
use crate::error::{HLLCompileError, HLLErrorItem, HLLErrors, HLLInternalError};
use crate::internal_rep::{
    generate_sid_rules, AnnotationInfo, Associated, ClassList, Context, FunctionArgument,
    FunctionInfo, FunctionMap, Sid, TypeInfo, TypeMap, ValidatedStatement,
};

use codespan_reporting::files::SimpleFile;

pub fn compile_rules_one_file<'a>(
    p: &'a PolicyFile,
    classlist: &'a ClassList<'a>,
    type_map: &'a TypeMap,
    func_map: &'a FunctionMap<'a>,
) -> Result<BTreeSet<ValidatedStatement<'a>>, HLLErrors> {
    Ok(do_rules_pass(
        &p.policy.exprs,
        &type_map,
        &func_map,
        &classlist,
        None,
        &p.file,
    )?)
}

pub fn generate_sexp(
    type_map: &TypeMap,
    classlist: &ClassList,
    policy_rules: BTreeSet<ValidatedStatement>,
    func_map: &FunctionMap<'_>,
) -> Result<Vec<sexp::Sexp>, HLLErrors> {
    let type_decl_list = organize_type_map(type_map)?;
    // TODO: The rest of compilation
    let cil_types = type_list_to_sexp(type_decl_list, type_map);
    let headers = generate_cil_headers(&classlist);
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
pub fn extend_type_map(p: &PolicyFile, type_map: &mut TypeMap) -> Result<(), HLLErrors> {
    // TODO: This only allows declarations at the top level.
    // Nested declarations are legal, but auto-associate with the parent, so they'll need special
    // handling when association is implemented
    for e in &p.policy.exprs {
        let d = match e {
            Expression::Decl(d) => d,
            _ => continue,
        };
        match d {
            Declaration::Type(t) => {
                type_map.insert(t.name.to_string(), TypeInfo::new(*t.clone(), &p.file)?)
            }
            Declaration::Func(_) => continue,
        };
    }
    Ok(())
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
        name: HLLString::from("kernel_sid"),
        inherits: vec![HLLString::from("domain")],
        is_virtual: false,
        list_coercion: false,
        declaration_file: None,
        annotations: BTreeSet::new(),
        decl: None,
    };

    let security_sid = TypeInfo {
        name: HLLString::from("security_sid"),
        inherits: vec![HLLString::from("resource")],
        is_virtual: false,
        list_coercion: false,
        declaration_file: None,
        annotations: BTreeSet::new(),
        decl: None,
    };

    let unlabeled_sid = TypeInfo {
        name: HLLString::from("unlabeled_sid"),
        inherits: vec![HLLString::from("resource")],
        is_virtual: false,
        list_coercion: false,
        declaration_file: None,
        annotations: BTreeSet::new(),
        decl: None,
    };

    for sid in [kernel_sid, security_sid, unlabeled_sid] {
        built_in_types.insert(sid.name.to_string(), sid);
    }

    built_in_types
}

pub fn build_func_map<'a>(
    exprs: &'a Vec<Expression>,
    types: &'a TypeMap,
    parent_type: Option<&'a TypeInfo>,
    file: &'a SimpleFile<String, String>,
) -> Result<FunctionMap<'a>, HLLErrors> {
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
                    None => Err(HLLErrorItem::Internal(HLLInternalError {}))?,
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
) -> Result<(), HLLErrors> {
    let mut errors = HLLErrors::new();
    for function in functions.values_mut() {
        match function.validate_body(
            &functions_copy,
            types,
            class_perms,
            function.declaration_file,
        ) {
            Ok(_) => (),
            Err(e) => errors.append(e),
        }
    }
    errors.into_result(())
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
) -> Result<(), HLLErrors> {
    let mut ret = HLLErrors::new();

    for p in &type_to_check.inherits {
        if visited_types.contains(&p.to_string() as &str) || *p == type_to_check.name {
            // cycle
            return Err(HLLErrors::from(
                HLLErrorItem::make_compile_or_internal_error(
                    "Cycle detected",
                    type_to_check.declaration_file.as_ref(),
                    p.get_range(),
                    "This type inherits itself",
                ),
            ));
        }
        let parent_ti = match types.get(&p.to_string()) {
            Some(t) => t,
            None => {
                return Err(HLLErrors::from(
                    HLLErrorItem::make_compile_or_internal_error(
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

        match find_cycles_or_bad_types(&parent_ti, types, new_visited_types) {
            Ok(()) => (),
            Err(e) => ret.append(e),
        }
    }

    ret.into_result(())
}

fn generate_type_no_parent_errors(missed_types: Vec<&TypeInfo>, types: &TypeMap) -> HLLErrors {
    let mut ret = HLLErrors::new();
    for t in &missed_types {
        match find_cycles_or_bad_types(&t, types, HashSet::new()) {
            Ok(()) => {
                ret.add_error(HLLInternalError {});
                return ret;
            }
            Err(e) => ret.append(e),
        }
    }
    // TODO: Deduplication
    ret
}

fn get_synthetic_resource_name(dom_info: &TypeInfo, associated_resource: &HLLString) -> HLLString {
    format!("{}-{}", dom_info.name, associated_resource).into()
}

fn create_synthetic_resource(
    types: &TypeMap,
    dom_info: &TypeInfo,
    associated_parent: Option<&TypeInfo>,
    class: &TypeInfo,
    class_string: &HLLString,
    global_exprs: &mut HashSet<Expression>,
) -> Result<HLLString, HLLErrorItem> {
    if !class.is_resource(types) {
        Err(HLLCompileError::new(
            "not a resource",
            dom_info
                .declaration_file
                .as_ref()
                .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?,
            class_string.get_range(),
            "This should not be a domain but a resource.",
        ))?;
    }

    // Creates a synthetic resource declaration.
    let mut dup_res_decl = class.decl.as_ref().ok_or(HLLInternalError {})?.clone();
    let res_name = get_synthetic_resource_name(dom_info, &class.name);
    dup_res_decl.name = res_name.clone();
    // See TypeDecl::new() in parser.lalrpop for resource inheritance.
    let parent_name = match associated_parent {
        None => class.name.clone(),
        Some(parent) => get_synthetic_resource_name(parent, &class.name),
    };
    dup_res_decl.inherits = vec![parent_name, "resource".into()];
    dup_res_decl.annotations = Annotations::new();
    dup_res_decl
        .expressions
        .iter_mut()
        .for_each(|e| e.set_class_name_if_decl(res_name.clone()));
    if !global_exprs.insert(Expression::Decl(Declaration::Type(Box::new(dup_res_decl)))) {
        Err(HLLInternalError {})?;
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
) -> Result<(), HLLErrors> {
    // Only allow a set of specific annotation names and strictly check their arguments.
    // TODO: Add tests to verify these checks.

    let mut errors = HLLErrors::new();
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
                    errors.add_error(HLLErrorItem::Compile(HLLCompileError::new(
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
                    Err(HLLErrorItem::Internal(HLLInternalError {}))?;
                }
            }
        }
    }

    for (_, (res, _)) in potential_resources.iter().filter(|(_, (_, seen))| !seen) {
        match types.get(&res.to_string()) {
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
            None => errors.add_error(HLLCompileError::new(
                "unknown resource",
                dom_info
                    .declaration_file
                    .as_ref()
                    .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?,
                res.get_range(),
                "didn't find this resource in the policy",
            )),
        }
    }

    errors.into_result(())
}

// domain -> related expressions
type AssociateExprs = HashMap<HLLString, HashSet<Expression>>;

#[derive(Clone)]
struct InheritedAnnotation<'a> {
    annotation: &'a AnnotationInfo,
    parent: Option<&'a TypeInfo>,
}

fn interpret_annotations<'a, T>(
    global_exprs: &mut HashSet<Expression>,
    associate_exprs: &mut AssociateExprs,
    funcs: &FunctionMap<'_>,
    types: &TypeMap,
    dom_info: &'a TypeInfo,
    extra_annotations: T,
) -> Result<(), HLLErrors>
where
    T: Iterator<Item = InheritedAnnotation<'a>>,
{
    let mut errors = HLLErrors::new();

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
                &dom_info,
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
) -> Result<Vec<InheritedAnnotation<'a>>, HLLErrors> {
    let mut errors = HLLErrors::new();

    let inherited_annotations = {
        let mut ret = Vec::new();
        for parent_name in &dom_info.inherits {
            let parent_ti = match types.get(&parent_name.to_string()) {
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
    match interpret_annotations(
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
                parent: Some(&dom_info),
            })
            .chain(inherited_annotations.into_iter().map(|mut a| {
                a.parent = Some(&dom_info);
                a
            }))
            .collect()
    })
}

pub fn apply_annotations<'a>(
    types: &'a TypeMap,
    funcs: &FunctionMap<'_>,
) -> Result<Vec<Expression>, HLLErrors> {
    let mut errors = HLLErrors::new();

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
        .filter(|(_, v)| v.len() != 0)
        .map(|(k, v)| {
            // TODO: Avoid cloning all expressions.
            let mut new_domain = types
                .get(&k.to_string())
                .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
                .decl
                .as_ref()
                .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
                .clone();
            new_domain.expressions = v.into_iter().collect();
            Ok(Expression::Decl(Declaration::Type(Box::new(new_domain))))
        })
        .chain(global_exprs.into_iter().map(|e| Ok(e)))
        .collect::<Result<_, HLLErrors>>()
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
fn check_non_virtual_inheritance(types: &TypeMap) -> Result<(), HLLErrors> {
    for t in types.values() {
        for parent in &t.inherits {
            match types.get(&parent.to_string()) {
                Some(p) => {
                    if !p.is_virtual {
                        return Err(HLLErrorItem::make_compile_or_internal_error(
                            "Inheriting from a non-virtual type is not yet supported",
                            t.declaration_file.as_ref(),
                            parent.get_range(),
                            "This type is not virtual",
                        )
                        .into());
                    }
                }
                None => (),
            };
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
fn organize_type_map<'a>(types: &'a TypeMap) -> Result<Vec<&'a TypeInfo>, HLLErrors> {
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
                tmp_types.values().map(|t| *t).collect(),
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

fn do_rules_pass<'a>(
    exprs: &'a Vec<Expression>,
    types: &'a TypeMap,
    funcs: &'a FunctionMap<'a>,
    class_perms: &ClassList<'a>,
    parent_type: Option<&'a TypeInfo>,
    file: &'a SimpleFile<String, String>,
) -> Result<BTreeSet<ValidatedStatement<'a>>, HLLErrors> {
    let mut ret = BTreeSet::new();
    let mut errors = HLLErrors::new();
    for e in exprs {
        match e {
            Expression::Stmt(s) => {
                let func_args = match parent_type {
                    Some(t) => vec![FunctionArgument::new_this_argument(t)],
                    None => Vec::new(),
                };
                match ValidatedStatement::new(
                    s,
                    funcs,
                    types,
                    class_perms,
                    &func_args,
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
                    None => Err(HLLErrorItem::Internal(HLLInternalError {}))?,
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
        match Option::<sexp::Sexp>::from(t) {
            Some(s) => {
                ret.extend(get_rules_vec_for_type(t, s, type_map));
            }
            None => (),
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
            atom_s(&ti.name.as_ref()),
        ]));
    }

    for i in &ti.inherits {
        ret.push(list(&[
            atom_s("typeattributeset"),
            atom_s(i.as_ref()),
            list(&[atom_s(&ti.name.as_ref())]),
        ]));
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
            Context::new(true, None, None, kernel_sid, None, None),
        ),
        Sid::new(
            "security",
            Context::new(false, None, None, security_sid, None, None),
        ),
        Sid::new(
            "unlabeled",
            Context::new(false, None, None, unlabeled_sid, None, None),
        ),
    ]
}

fn func_map_to_sexp(funcs: &FunctionMap<'_>) -> Result<Vec<sexp::Sexp>, HLLErrors> {
    let mut ret = Vec::new();
    let mut errors = HLLErrors::new();
    for f in funcs.values() {
        match Sexp::try_from(f) {
            Ok(f) => ret.push(f),
            Err(e) => errors.add_error(e),
        }
    }
    errors.into_result(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Declaration, Expression, HLLString, Policy, TypeDecl};
    use crate::internal_rep::TypeInfo;

    #[test]
    fn extend_type_map_test() {
        let mut exprs = Vec::new();
        exprs.push(Expression::Decl(Declaration::Type(Box::new(
            TypeDecl::new(
                HLLString::from("foo"),
                vec![HLLString::from("domain")],
                Vec::new(),
            ),
        ))));
        let p = Policy::new(exprs);
        let pf = PolicyFile::new(p, SimpleFile::new(String::new(), String::new()));
        let mut types = get_built_in_types_map();
        extend_type_map(&pf, &mut types).unwrap();
        match types.get("foo") {
            Some(foo) => assert_eq!(foo.name, "foo"),
            None => panic!("Foo is not in hash map"),
        }
        match types.get("domain") {
            Some(foo) => assert_eq!(foo.name, "domain"),
            None => panic!("Domain is not in hash map"),
        }
    }

    #[test]
    fn organize_type_map_test() {
        let mut types = get_built_in_types_map();
        let mut foo_type = TypeInfo::new(
            TypeDecl::new(
                HLLString::from("foo"),
                vec![HLLString::from("domain")],
                Vec::new(),
            ),
            &SimpleFile::new(String::new(), String::new()),
        )
        .unwrap();
        foo_type.is_virtual = true;

        let mut bar_type = TypeInfo::new(
            TypeDecl::new(
                HLLString::from("bar"),
                vec![HLLString::from("domain"), HLLString::from("foo")],
                Vec::new(),
            ),
            &SimpleFile::new(String::new(), String::new()),
        )
        .unwrap();
        bar_type.is_virtual = true;

        let baz_type = TypeInfo::new(
            TypeDecl::new(
                HLLString::from("baz"),
                vec![
                    HLLString::from("domain"),
                    HLLString::from("foo"),
                    HLLString::from("bar"),
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
