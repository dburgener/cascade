use sexp::{Sexp, Atom};

use crate::internal_rep::{AvRuleFlavor, AvRule};

pub fn generate_cil_for_av_rule(rule: AvRule) -> sexp::Sexp {
    let mut ret: Vec<sexp::Sexp> = Vec::new();

    ret.push(match rule.av_rule_flavor {
        AvRuleFlavor::Allow => Sexp::Atom(Atom::S("allow".to_string())),
        AvRuleFlavor::Dontaudit => Sexp::Atom(Atom::S("dontaudit".to_string())),
        AvRuleFlavor::Auditallow => Sexp::Atom(Atom::S("auditallow".to_string())),
        AvRuleFlavor::Neverallow => Sexp::Atom(Atom::S("neverallow".to_string())),
    });

    ret.push(Sexp::Atom(Atom::S(rule.source.name.clone())));
    ret.push(Sexp::Atom(Atom::S(rule.target.name.clone())));

    let mut classpermset = vec![Sexp::Atom(Atom::S(rule.class.to_string()))];

    let perms = rule.perms.into_iter().map(|p| Sexp::Atom(Atom::S(p.to_string()))).collect();

    classpermset.push(Sexp::List(perms));

    ret.push(Sexp::List(classpermset));

    Sexp::List(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::TypeDecl;
    use crate::internal_rep::TypeInfo;

    #[test]
    fn generate_cil_for_av_rule_test() {
        let cil_sexp = generate_cil_for_av_rule(AvRule { av_rule_flavor: AvRuleFlavor::Allow,
            source: &TypeInfo::new(&TypeDecl::new("foo".to_string(), Vec::new(), Vec::new())),
            target: &TypeInfo::new(&TypeDecl::new("bar".to_string(), Vec::new(), Vec::new())),
            class: "file",
            perms: vec!["read", "getattr"]});

        let cil_expected = "(allow foo bar (file (read getattr)))";

        assert_eq!(cil_sexp.to_string(), cil_expected.to_string());
    }
}
