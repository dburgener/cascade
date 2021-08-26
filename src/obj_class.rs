// Object class and permissions declarations live here

use crate::internal_rep::ClassList;

pub fn declare_class_perms() -> Vec<sexp::Sexp> {
    let mut classlist = ClassList::new();
    classlist.add_class("file", vec!["read", "write", "open", "getattr", "append"]);
    classlist.add_class("process", vec!["transition", "dyntransition"]);
    classlist.generate_class_perm_cil()
}

