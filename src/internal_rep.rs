use crate::ast::{TypeDecl};

#[derive(Clone)]
pub struct TypeInfo {
    pub name: String,
    pub inherits: Vec<String>,
    is_virtual: bool
}

impl TypeInfo {
    pub fn new(td: &TypeDecl) -> TypeInfo {
        TypeInfo { name: td.name.clone(), inherits: td.inherits.clone(), is_virtual: td.is_virtual }
    }
}
