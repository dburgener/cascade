use std::error::Error;
use std::collections::HashMap;

use sexp::{Sexp, Atom};

use crate::ast::{Policy, Expression, Declaration, TypeDecl};

pub fn compile(p: &Policy) -> Result<sexp::Sexp, Box<dyn Error>> {
    build_type_map(p);
    Ok(Sexp::Atom(Atom::S("TODO".to_string())))
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

    fn organize_type_map_test() {
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
