use sexp::{atom_s, list, Atom, Sexp};

use crate::ast::TypeDecl;
use crate::constants;

#[derive(Clone, Debug)]
pub struct TypeInfo {
    pub name: String,
    pub inherits: Vec<String>,
    is_virtual: bool,
}

impl TypeInfo {
    pub fn new(td: &TypeDecl) -> TypeInfo {
        TypeInfo {
            name: td.name.clone(),
            inherits: td.inherits.clone(),
            is_virtual: td.is_virtual,
        }
    }
}

impl From<&TypeInfo> for sexp::Sexp {
    fn from(typeinfo: &TypeInfo) -> sexp::Sexp {
        let flavor = if typeinfo.is_virtual {
            "attribute"
        } else {
            "type"
        };
        list(&[atom_s(flavor), atom_s(&typeinfo.name)])
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

impl From<AvRule<'_>> for sexp::Sexp {
    fn from(rule: AvRule) -> sexp::Sexp {
        let mut ret = Vec::new();

        ret.push(match rule.av_rule_flavor {
            AvRuleFlavor::Allow => Sexp::Atom(Atom::S(constants::ALLOW_FUNCTION_NAME.to_string())),
            AvRuleFlavor::Dontaudit => {
                Sexp::Atom(Atom::S(constants::DONTAUDIT_FUNCTION_NAME.to_string()))
            }
            AvRuleFlavor::Auditallow => {
                Sexp::Atom(Atom::S(constants::AUDITALLOW_FUNCTION_NAME.to_string()))
            }
            AvRuleFlavor::Neverallow => {
                Sexp::Atom(Atom::S(constants::NEVERALLOW_FUNCTION_NAME.to_string()))
            }
        });

        ret.push(Sexp::Atom(Atom::S(rule.source.name.clone())));
        ret.push(Sexp::Atom(Atom::S(rule.target.name.clone())));

        let mut classpermset = vec![Sexp::Atom(Atom::S(rule.class.to_string()))];

        let perms = rule
            .perms
            .into_iter()
            .map(|p| Sexp::Atom(Atom::S(p.to_string())))
            .collect();

        classpermset.push(Sexp::List(perms));

        ret.push(Sexp::List(classpermset));

        Sexp::List(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::TypeDecl;
    use crate::internal_rep::TypeInfo;

    #[test]
    fn generate_cil_for_av_rule_test() {
        let cil_sexp = Sexp::from(AvRule {
            av_rule_flavor: AvRuleFlavor::Allow,
            source: &TypeInfo::new(&TypeDecl::new("foo".to_string(), Vec::new(), Vec::new())),
            target: &TypeInfo::new(&TypeDecl::new("bar".to_string(), Vec::new(), Vec::new())),
            class: "file",
            perms: vec!["read", "getattr"],
        });

        let cil_expected = "(allow foo bar (file (read getattr)))";

        assert_eq!(cil_sexp.to_string(), cil_expected.to_string());
    }
}
