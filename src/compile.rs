use sexp::{atom_s, list, Sexp};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;

use crate::ast::{Declaration, Expression, Policy};
use crate::constants;
use crate::error::{HLLCompileError, HLLErrorItem, HLLErrors, HLLInternalError};
use crate::internal_rep::{
    generate_sid_rules, ClassList, Context, FunctionArgument, FunctionInfo, Sid, TypeInfo,
    ValidatedStatement,
};
use crate::obj_class::make_classlist;

pub fn compile(p: &Policy) -> Result<Vec<sexp::Sexp>, HLLErrors> {
    let classlist = make_classlist();
    let type_map = build_type_map(p);
    let mut func_map = build_func_map(&p.exprs, &type_map, None)?;
    let func_map_copy = func_map.clone(); // In order to read function info while mutating
    validate_functions(&mut func_map, &type_map, &classlist, &func_map_copy)?;

    let type_decl_list = organize_type_map(&type_map)?;

    let policy_rules = do_rules_pass(&p.exprs, &type_map, &func_map, &classlist, None)?;

    // TODO: The rest of compilation
    let cil_types = type_list_to_sexp(type_decl_list, &type_map);
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
fn build_type_map(p: &Policy) -> HashMap<String, TypeInfo> {
    let mut decl_map = get_built_in_types_map();
    // TODO: This only allows declarations at the top level.
    // Nested declarations are legal, but auto-associate with the parent, so they'll need special
    // handling when association is implemented
    for e in &p.exprs {
        let d = match e {
            Expression::Decl(d) => d,
            _ => continue,
        };
        match d {
            Declaration::Type(t) => decl_map.insert(t.name.clone(), TypeInfo::new(&**t)),
            Declaration::Func(_) => continue,
        };
    }

    decl_map
}

fn get_built_in_types_map() -> HashMap<String, TypeInfo> {
    let mut built_in_types = HashMap::new();
    for built_in in constants::BUILT_IN_TYPES {
        let built_in = built_in.to_string();
        built_in_types.insert(built_in.clone(), TypeInfo::make_built_in(built_in));
    }

    //Special handling for sids.  These are temporary built in types that are handled differently
    let kernel_sid = TypeInfo {
        name: "kernel_sid".to_string(),
        inherits: vec!["domain".to_string()],
        is_virtual: false,
    };

    let security_sid = TypeInfo {
        name: "security_sid".to_string(),
        inherits: vec!["resource".to_string()],
        is_virtual: false,
    };

    let unlabeled_sid = TypeInfo {
        name: "unlabeled_sid".to_string(),
        inherits: vec!["resource".to_string()],
        is_virtual: false,
    };

    for sid in [kernel_sid, security_sid, unlabeled_sid] {
        built_in_types.insert(sid.name.clone(), sid);
    }

    built_in_types
}

fn build_func_map<'a>(
    exprs: &'a Vec<Expression>,
    types: &'a HashMap<String, TypeInfo>,
    parent_type: Option<&'a TypeInfo>,
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
                let type_being_parsed = match types.get(&t.name) {
                    Some(t) => t,
                    None => {
                        return Err(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {})))
                    }
                };
                decl_map.extend(build_func_map(
                    &t.expressions,
                    types,
                    Some(type_being_parsed),
                )?);
            }
            Declaration::Func(f) => {
                decl_map.insert(
                    f.get_cil_name().clone(),
                    FunctionInfo::new(&**f, types, parent_type)?,
                );
            }
        };
    }

    Ok(decl_map)
}

// Mutate hash map to set the validated body
fn validate_functions<'a, 'b>(
    functions: &'a mut HashMap<String, FunctionInfo<'b>>,
    types: &'b HashMap<String, TypeInfo>,
    class_perms: &'b ClassList,
    functions_copy: &'b HashMap<String, FunctionInfo<'b>>,
) -> Result<(), HLLErrors> {
    let mut errors = HLLErrors::new();
    for function in functions.values_mut() {
        match function.validate_body(&functions_copy, types, class_perms) {
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
    type_to_check: &str,
    types: &HashMap<String, TypeInfo>,
    visited_types: HashSet<&str>,
) -> Result<(), HLLErrors> {
    let mut ret = HLLErrors::new();

    let ti = match types.get(&type_to_check.to_string()) {
        Some(i) => i,
        None => {
            return Err(HLLErrors::from(HLLErrorItem::Compile(HLLCompileError {
                filename: "TODO".to_string(),
                lineno: 0,
                msg: format!("{} is not a valid identifier", type_to_check),
            })));
        }
    };

    for p in &ti.inherits {
        if visited_types.contains(&p as &str) || p == type_to_check {
            // cycle
            return Err(HLLErrors::from(HLLErrorItem::Compile(HLLCompileError {
                filename: "TODO".to_string(),
                lineno: 0,
                msg: "TODO: Write cycle error message".to_string(),
            })));
        }
        let mut new_visited_types = visited_types.clone();
        new_visited_types.insert(type_to_check);

        match find_cycles_or_bad_types(&p, types, new_visited_types) {
            Ok(()) => (),
            Err(mut e) => ret.append(&mut e),
        }
    }

    ret.into_result(())
}

fn generate_type_no_parent_errors(
    missed_types: HashSet<&String>,
    types: &HashMap<String, TypeInfo>,
) -> HLLErrors {
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

// This function validates that the relationships in the HashMap are valid, and organizes a Vector
// of type declarations in a reasonable order to be output into CIL.
// In order to be valid, the types must meet the following properties:
// 1. All types have at least one parent
// 2. All listed parents are themselves types (or "domain" or "resource")
// 3. No cycles exist
fn organize_type_map<'a>(
    types: &'a HashMap<String, TypeInfo>,
) -> Result<Vec<&'a TypeInfo>, HLLErrors> {
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
            // TODO: Better error handling
            return Err(generate_type_no_parent_errors(
                tmp_types.keys().map(|s| *s).collect(),
                types,
            ));
        }
        for t in &current_pass_types {
            tmp_types.remove(&t.name);
        }
        out.append(&mut current_pass_types);
    }
    Ok(out)
}

fn do_rules_pass<'a>(
    exprs: &'a Vec<Expression>,
    types: &'a HashMap<String, TypeInfo>,
    funcs: &'a HashMap<String, FunctionInfo>,
    class_perms: &ClassList<'a>,
    parent_type: Option<&'a TypeInfo>,
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
                match ValidatedStatement::new(s, funcs, types, class_perms, &func_args, parent_type)
                {
                    Ok(mut s) => ret.append(&mut s),
                    Err(mut e) => errors.append(&mut e),
                }
            }
            Expression::Decl(Declaration::Type(t)) => {
                let type_being_parsed = match types.get(&t.name) {
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
                ) {
                    Ok(r) => ret.extend(r.iter().cloned()),
                    Err(mut e) => errors.append(&mut e),
                }
            }
            _ => continue,
        }
    }
    errors.into_result(ret)
}

fn type_list_to_sexp(
    type_list: Vec<&TypeInfo>,
    type_map: &HashMap<String, TypeInfo>,
) -> Vec<sexp::Sexp> {
    let mut ret = Vec::new();
    for t in type_list {
        match Option::<sexp::Sexp>::from(t) {
            Some(s) => {
                ret.push(s);
                if !t.is_virtual {
                    let role_assoc = if t.is_resource(type_map) {
                        "object_r"
                    } else {
                        "system_r"
                    };

                    ret.push(list(&[
                        atom_s("roletype"),
                        atom_s(role_assoc),
                        atom_s(&t.name),
                    ]));
                }
            }
            None => (),
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

fn func_map_to_sexp(funcs: HashMap<String, FunctionInfo>) -> Result<Vec<sexp::Sexp>, HLLErrors> {
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
    use crate::ast::{Declaration, Expression, Policy, TypeDecl};
    use crate::internal_rep::TypeInfo;

    #[test]
    fn build_type_map_test() {
        let mut exprs = Vec::new();
        exprs.push(Expression::Decl(Declaration::Type(Box::new(
            TypeDecl::new("foo".to_string(), vec!["domain".to_string()], Vec::new()),
        ))));
        let p = Policy::new(exprs);
        let types = build_type_map(&p);
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
        let foo_type = TypeInfo::new(&TypeDecl::new(
            "foo".to_string(),
            vec!["domain".to_string()],
            Vec::new(),
        ));
        let bar_type = TypeInfo::new(&TypeDecl::new(
            "bar".to_string(),
            vec!["domain".to_string(), "foo".to_string()],
            Vec::new(),
        ));
        let baz_type = TypeInfo::new(&TypeDecl::new(
            "baz".to_string(),
            vec!["domain".to_string(), "foo".to_string(), "bar".to_string()],
            Vec::new(),
        ));
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
