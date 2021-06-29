use std::error::Error;
use std::collections::HashMap;

use sexp::{Sexp, Atom};

use crate::ast::{Policy, Expression, Declaration, TypeDecl};
use crate::functions;

pub fn compile(p: &Policy) -> Result<sexp::Sexp, Box<dyn Error>> {
    let type_map = build_type_map(p);
    let type_decl_list = organize_type_map(&type_map)?;
    // TODO: The rest of compilation
    Ok(type_list_to_sexp(type_decl_list))
}

// TODO: Currently is domains only
fn build_type_map(p: &Policy) -> HashMap<String, &TypeDecl> {
    let mut decl_list: HashMap<String, &TypeDecl> = HashMap::new();
    // TODO: This only allows domain declarations at the top level.  Is that okay?  I'm too tired
    // to think about it
    for e in &p.exprs {
        let d = match e {
            Expression::Decl(d) => d,
            _ => continue,
        };
        match d {
            Declaration::Type(t) => { decl_list.insert(t.name.clone(), &**t); },
            Declaration::Func(_) => continue,
        }
    }

    return decl_list
}

//TODO: Centralize Error handling
use std::fmt;

#[derive(Clone, Debug)]
struct HLLCompileError {}

impl fmt::Display for HLLCompileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TODO")
    }
}

impl Error for HLLCompileError {}

// This function validates that the relationships in the HashMap are valid, and organizes a Vector
// of type declarations in a reasonable order to be output into CIL.
// In order to be valid, the types must meet the following properties:
// 1. All types have at least one parent
// 2. All listed parents are themselves types (or "domain" or "resource")
// 3. No cycles exist
fn organize_type_map<'a>(types: &HashMap<String, &'a TypeDecl>) -> Result<Vec<&'a TypeDecl>, Box<dyn Error>> {
    let mut tmp_map = types.clone();

    let mut out: Vec<&TypeDecl> = Vec::new();

    while !tmp_map.is_empty() {
        let mut current_pass_types: Vec<&TypeDecl> = Vec::new();

        for t in tmp_map.values() {
            let mut wait = false;
            // TODO: Do we need to consider the case when inherits is empty?  Theoretically it
            // should have always been populated with at least domain or resource by the parser.
            // Should probably return an internal error if that hasn't happened
            for key in &t.inherits {
                if key != "domain" && key != "resource" && out.iter().any(|&x| &x.name == key) {
                    wait = true;
                    continue;
                }
            }
            if !wait {
                // This means all the parents are previously listed
                current_pass_types.push(t);
            }
        }
        if current_pass_types.is_empty() && !tmp_map.is_empty() {
            // We can't satify the parents for all types
            // TODO: Better error handling
            return Err(Box::new(HLLCompileError {}));
        }
        for t in &current_pass_types {
            tmp_map.remove(&t.name);
        }
        out.append(&mut current_pass_types);
    }
    return Ok(out);
}

fn type_list_to_sexp(types: Vec<&TypeDecl>) -> sexp::Sexp {
    let mut ret: Vec<sexp::Sexp> = Vec::new();
    for t in types {
        ret.push(Sexp::List(vec![Sexp::Atom(Atom::S("type".to_string())),
                                Sexp::Atom(Atom::S(t.name.clone()))]))
    }
    return Sexp::List(ret);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Policy, Expression, Declaration, TypeDecl};

    #[test]
    fn build_type_map_test() {
        let mut exprs = Vec::new();
        exprs.push(Expression::Decl(Declaration::Type(Box::new(TypeDecl::new("foo".to_string(), vec!["domain".to_string()], Vec::new())))));
        let p = Policy::new(exprs);
        let types = build_type_map(&p);
        match types.get("foo") {
            Some(foo) => assert_eq!(foo.name, "foo"),
            None => panic!("Foo is not in hash map"),
        }
    }

    #[test]
    fn organize_type_map_test() {
        let mut types: HashMap<String, &TypeDecl>  = HashMap::new();
        let foo_type = TypeDecl::new("foo".to_string(), vec!["domain".to_string()], Vec::new());
        let bar_type = TypeDecl::new("bar".to_string(), vec!["domain".to_string(), "foo".to_string()], Vec::new());
        let baz_type = TypeDecl::new("baz".to_string(), vec!["domain".to_string(), "foo".to_string(), "bar".to_string()], Vec::new());
        types.insert("foo".to_string(), &foo_type);
        types.insert("bar".to_string(), &bar_type);
        types.insert("baz".to_string(), &baz_type);

        let type_vec = organize_type_map(&types).unwrap();
        //assert_eq!(types.name, "domain");
        //assert_eq!(*types.parent, None);
        //assert_eq!(types.children.len(), 1);
        //assert_eq!(types.children[0].name, "foo");
        // TODO: This is hard to satisfy the borrow checker with.  Let's get everything else
        // working and come back to it
        //assert_eq!(*types.children[0].parent, Some(types));
        //assert_eq!(types.children[0].children.len(), 0);
    }
}
