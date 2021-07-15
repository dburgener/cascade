use crate::ast::{TypeDecl};

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub enum AvRuleFlavor {
    Allow,
    Dontaudit,
    Auditallow,
    Neverallow,
}

#[derive(Clone, Debug)]
pub struct AvRule<'a> {
    pub av_rule_flavor: AvRuleFlavor,
    pub source: &'a TypeInfo,
    pub target: &'a TypeInfo,
    pub class: &'a str,
    pub perms: Vec<&'a str>,
}
