use crate::internal_rep::{TypeInfo};

pub enum AvRuleFlavor {
    Allow,
    Dontaudit,
    Auditallow,
    Neverallow,
}

pub struct AvRule<'a> {
    pub av_rule_flavor: AvRuleFlavor,
    pub source: &'a TypeInfo,
    pub target: &'a TypeInfo,
    pub class: String,
    pub perms: Vec<String>,
}

