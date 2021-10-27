// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use sexp::{atom_s, list, Sexp};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;

use crate::ast::{
    Annotations, Argument, Declaration, Expression, FuncCall, HLLString, PolicyFile, Statement,
};
use crate::constants;
use crate::error::{HLLErrorItem, HLLErrors, HLLInternalError};
use crate::internal_rep::{
    generate_sid_rules, AnnotationInfo, ClassList, Context, FunctionArgument, FunctionInfo,
    HookCallAssociate, HookType, Sid, TypeInfo, TypeMap, ValidatedStatement,
};

use codespan_reporting::files::SimpleFile;

pub fn compile_rules_one_file<'a>(
    p: &'a PolicyFile,
    classlist: &'a ClassList<'a>,
    type_map: &'a HashMap<String, TypeInfo>,
    func_map: &'a HashMap<String, FunctionInfo<'a>>,
) -> Result<Vec<ValidatedStatement<'a>>, HLLErrors> {
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
    policy_rules: Vec<ValidatedStatement>,
    func_map: &HashMap<String, FunctionInfo>,
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
    ret.extend(cil_types.iter().cloned());
    ret.extend(cil_macros.iter().cloned());
    ret.extend(cil_rules.iter().cloned());
    ret.extend(sid_statements.iter().cloned());
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
                type_map.insert(t.name.to_string(), TypeInfo::new(&**t, &p.file)?)
            }
            Declaration::Func(_) => continue,
        };
    }
    Ok(())
}

pub fn get_built_in_types_map() -> TypeMap {
    let mut built_in_types = HashMap::new();
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
        annotations: vec![],
        decl: None,
    };

    let security_sid = TypeInfo {
        name: HLLString::from("security_sid"),
        inherits: vec![HLLString::from("resource")],
        is_virtual: false,
        list_coercion: false,
        declaration_file: None,
        annotations: vec![],
        decl: None,
    };

    let unlabeled_sid = TypeInfo {
        name: HLLString::from("unlabeled_sid"),
        inherits: vec![HLLString::from("resource")],
        is_virtual: false,
        list_coercion: false,
        declaration_file: None,
        annotations: vec![],
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
) -> Result<HashMap<String, FunctionInfo<'a>>, HLLErrors> {
    let mut decl_map = HashMap::new();
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
                    None => {
                        return Err(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {})))
                    }
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
                    f.get_cil_name().clone(),
                    FunctionInfo::new(&**f, types, parent_type, file)?,
                );
            }
        };
    }

    Ok(decl_map)
}

// Mutate hash map to set the validated body
pub fn validate_functions<'a, 'b>(
    functions: &'a mut HashMap<String, FunctionInfo<'b>>,
    types: &'b TypeMap,
    class_perms: &'b ClassList,
    functions_copy: &'b HashMap<String, FunctionInfo<'b>>,
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
            Err(mut e) => errors.append(&mut e),
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
            Err(mut e) => ret.append(&mut e),
        }
    }

    ret.into_result(())
}

fn generate_type_no_parent_errors(missed_types: Vec<&TypeInfo>, types: &TypeMap) -> HLLErrors {
    let mut ret = HLLErrors::new();
    for t in &missed_types {
        match find_cycles_or_bad_types(&t, types, HashSet::new()) {
            Ok(()) => {
                ret.add_error(HLLErrorItem::Internal(HLLInternalError {}));
                return ret;
            }
            Err(mut e) => ret.append(&mut e),
        }
    }
    // TODO: Deduplication
    ret
}

fn interpret_hooks(
    global_exprs: &mut HashSet<Expression>,
    local_exprs: &mut HashSet<Expression>,
    funcs: &HashMap<String, FunctionInfo>,
    types: &HashMap<String, TypeInfo>,
    associate: &HookCallAssociate,
    dom_info: &TypeInfo,
) -> Result<(), HLLErrors> {
    // Only allow a set of specific annotation names and strictly check their arguments.
    // TODO: Add tests to verify these checks.
    // TODO: Check for duplicate annotations.

    // Find the hooks
    for func_info in funcs
        .values()
        .filter(|f| f.hook_type == Some(HookType::Associate))
    {
        // Multiple calls for the same hook and resource are allowed, not sure if it is a good thing.
        if let Some(class) = func_info.class {
            if associate.resources.contains(&class.name) {
                // FIXME: is_resource() doesn't work (e.g. using a resource instead of a domain).
                if !class.is_resource(types) {
                    return Err(HLLErrors::from(
                        HLLErrorItem::make_compile_or_internal_error(
                            //format!("{} is not a resource in the hook_call annotation for {}", class.name, decl.name)
                            "not a resource in the hook_call annotation",
                            None,
                            None,
                            "TODO",
                        ),
                    ));
                }

                // Creates a synthetic resource declaration.
                let mut dup_res_decl = class
                    .decl
                    .as_ref()
                    .ok_or(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {})))?
                    .clone();
                let res_name: HLLString = format!("{}-{}", dom_info.name, class.name).into();
                dup_res_decl.name = res_name.clone();
                dup_res_decl.annotations = Annotations::new();
                dup_res_decl
                    .expressions
                    .iter_mut()
                    .for_each(|e| e.set_class_name_if_decl(res_name.clone()));
                // TODO: Check that it returns true.
                global_exprs.insert(Expression::Decl(Declaration::Type(Box::new(dup_res_decl))));

                // Creates a synthetic call.
                let new_call = Expression::Stmt(Statement::Call(Box::new(FuncCall::new(
                    Some(res_name),
                    func_info.name.clone().into(),
                    vec![Argument::Var("this".into())],
                ))));
                // TODO: Check that it returns true.
                local_exprs.insert(new_call);
            }
        }
    }
    Ok(())
}

// domain -> related expressions
type HookCallExprs = HashMap<HLLString, HashSet<Expression>>;

fn interpret_annotations<'a, T>(
    global_exprs: &mut HashSet<Expression>,
    hook_call_exprs: &mut HookCallExprs,
    funcs: &HashMap<String, FunctionInfo>,
    types: &HashMap<String, TypeInfo>,
    dom_info: &'a TypeInfo,
    extra_annotations: T,
) -> Result<(), HLLErrors>
where
    T: Iterator<Item = &'a AnnotationInfo>,
{
    use std::collections::hash_map::Entry;

    let local_exprs = match hook_call_exprs.entry(dom_info.name.clone()) {
        // Ignores already processed domains.
        Entry::Occupied(_) => return Ok(()),
        vacant => vacant.or_default(),
    };
    for annotation in dom_info.annotations.iter().chain(extra_annotations) {
        if let AnnotationInfo::HookCall(ref associate) = annotation {
            interpret_hooks(
                global_exprs,
                local_exprs,
                funcs,
                types,
                associate,
                &dom_info,
            )?;
        }
    }
    Ok(())
}

fn inherit_annotations(
    global_exprs: &mut HashSet<Expression>,
    hook_call_exprs: &mut HookCallExprs,
    funcs: &HashMap<String, FunctionInfo>,
    types: &HashMap<String, TypeInfo>,
    dom_info: &TypeInfo,
) -> Result<Vec<AnnotationInfo>, HLLErrors> {
    let inherited_annotations = {
        let mut ret = Vec::new();
        for parent_name in &dom_info.inherits {
            let parent_ti = match types.get(&parent_name.to_string()) {
                Some(p) => p,
                // Ignores inheritance issues for now, see bad_type_error_test().
                None => continue,
            };
            ret.extend(inherit_annotations(
                global_exprs,
                hook_call_exprs,
                funcs,
                types,
                parent_ti,
            )?);
        }
        ret
    };
    interpret_annotations(
        global_exprs,
        hook_call_exprs,
        funcs,
        types,
        dom_info,
        inherited_annotations.iter(),
    )?;
    Ok(dom_info
        .annotations
        .iter()
        .cloned()
        .chain(inherited_annotations)
        .collect())
}

pub fn apply_annotations<'a>(
    types: &'a TypeMap,
    funcs: &HashMap<String, FunctionInfo>,
) -> Result<Vec<Expression>, HLLErrors> {
    // Makes sure that there is no cycle.
    organize_type_map(types)?;

    let mut hook_call_exprs = HashMap::new();
    let mut global_exprs = HashSet::new();
    for type_info in types.values() {
        inherit_annotations(
            &mut global_exprs,
            &mut hook_call_exprs,
            funcs,
            types,
            type_info,
        )?;
    }

    Ok(hook_call_exprs
        .into_iter()
        .filter(|(_, v)| v.len() != 0)
        .map(|(k, v)| {
            // TODO: Avoid cloning all expressions.
            let mut new_domain = types
                .get(&k.to_string())
                .ok_or(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {})))?
                .decl
                .as_ref()
                .ok_or(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {})))?
                .clone();
            new_domain.expressions = v.into_iter().collect();
            Ok(Expression::Decl(Declaration::Type(Box::new(new_domain))))
        })
        .chain(global_exprs.into_iter().map(|e| Ok(e)))
        .collect::<Result<_, HLLErrors>>()?)
}

// This function validates that the relationships in the HashMap are valid, and organizes a Vector
// of type declarations in a reasonable order to be output into CIL.
// In order to be valid, the types must meet the following properties:
// 1. All types have at least one parent
// 2. All listed parents are themselves types (or "domain" or "resource")
// 3. No cycles exist
fn organize_type_map<'a>(types: &'a TypeMap) -> Result<Vec<&'a TypeInfo>, HLLErrors> {
    let mut tmp_types: HashMap<&String, &TypeInfo> = types.iter().collect();

    let mut out: Vec<&TypeInfo> = Vec::new();

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
    funcs: &'a HashMap<String, FunctionInfo>,
    class_perms: &ClassList<'a>,
    parent_type: Option<&'a TypeInfo>,
    file: &'a SimpleFile<String, String>,
) -> Result<Vec<ValidatedStatement<'a>>, HLLErrors> {
    let mut ret = Vec::new();
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
                    Err(mut e) => errors.append(&mut e),
                }
            }
            Expression::Decl(Declaration::Type(t)) => {
                let type_being_parsed = match types.get(&t.name.to_string()) {
                    Some(t) => t,
                    None => {
                        return Err(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {})))
                    }
                };
                match do_rules_pass(
                    &t.expressions,
                    types,
                    funcs,
                    class_perms,
                    Some(type_being_parsed),
                    file,
                ) {
                    Ok(r) => ret.extend(r.iter().cloned()),
                    Err(mut e) => errors.append(&mut e),
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

fn func_map_to_sexp(funcs: &HashMap<String, FunctionInfo>) -> Result<Vec<sexp::Sexp>, HLLErrors> {
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
        let foo_type = TypeInfo::new(
            &TypeDecl::new(
                HLLString::from("foo"),
                vec![HLLString::from("domain")],
                Vec::new(),
            ),
            &SimpleFile::new(String::new(), String::new()),
        )
        .unwrap();

        let bar_type = TypeInfo::new(
            &TypeDecl::new(
                HLLString::from("bar"),
                vec![HLLString::from("domain"), HLLString::from("foo")],
                Vec::new(),
            ),
            &SimpleFile::new(String::new(), String::new()),
        )
        .unwrap();

        let baz_type = TypeInfo::new(
            &TypeDecl::new(
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
