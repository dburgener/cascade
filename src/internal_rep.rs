use sexp::{atom_s, list, Atom, Sexp};

use crate::ast::TypeDecl;
use crate::constants;

const DEFAULT_USER: &str = "system_u";
const DEFAULT_OBJECT_ROLE: &str = "object_r";
const DEFAULT_DOMAIN_ROLE: &str = "system_r";
const DEFAULT_MLS: &str = "s0";

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

#[derive(Copy, Clone)]
struct Context<'a> {
    user: &'a str,
    role: &'a str,
    setype: &'a str,
    mls_low: &'a str,
    mls_high: &'a str,
}

impl Context<'_> {
    // All fields except setype is optional.  User and role are replaced with defaults if set to None
    fn new<'a>(is_domain: bool, u: Option<&'a str>, r: Option<&'a str>, t: &'a str, ml: Option<&'a str>, mh: Option<&'a str>) -> Context<'a> {
        Context {
            user: u.unwrap_or(DEFAULT_USER),
            role: r.unwrap_or(if is_domain { DEFAULT_DOMAIN_ROLE } else { DEFAULT_OBJECT_ROLE }),
            setype: t,
            mls_low: ml.unwrap_or(DEFAULT_MLS),
            mls_high: mh.unwrap_or(DEFAULT_MLS),
        }
    }
}

impl From<Context<'_>> for sexp::Sexp {
    fn from(c: Context) -> sexp::Sexp {
        let mls_range = Sexp::List(vec![Sexp::List(vec![atom_s(c.mls_low)]),
                                        Sexp::List(vec![atom_s(c.mls_low)])]);
        Sexp::List(vec![atom_s(c.user),
                        atom_s(c.role),
                        atom_s(c.setype),
                        mls_range])
    }
}

struct Sid<'a> {
    name: &'a str,
    context: Context<'a>,
}

impl<'a> Sid<'a> {
    fn new(n: &'a str, c: Context<'a>) -> Self {
        Sid { name: n,
              context: c
        }
    }


    fn get_sid_statement(&self) -> Sexp {
        Sexp::List(vec![atom_s("sid"), atom_s(self.name)])
    }

    fn get_sidcontext_statement(&self) -> Sexp {
        Sexp::List(vec![atom_s("sidcontext"),
                        atom_s(self.name),
                        Sexp::from(self.context)])
    }

    fn get_name_as_sexp_atom(&self) -> Sexp {
        atom_s(self.name)
    }
}

fn generate_sid_rules(sids: Vec<Sid>) -> Vec<Sexp> {
    let mut ret = Vec::new();
    let mut order = Vec::new();
    for s in sids {
        ret.push(s.get_sid_statement());
        ret.push(s.get_sidcontext_statement());
        order.push(s.get_name_as_sexp_atom());
    }
    ret.push(Sexp::List(vec![atom_s("sidorder"),
                             Sexp::List(order)]));
    ret
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

    #[test]
    fn sexp_from_context() {
        let context_sexp = Sexp::from(Context::new(true, Some("u"), Some("r"), "t", Some("s0"), Some("s0")));
        let cil_expected = "(u r t ((s0) (s0)))";
        assert_eq!(context_sexp.to_string(), cil_expected.to_string());
    }

    #[test]
    fn sexp_from_context_defaults() {
        let context_sexp = Sexp::from(Context::new(true, None, None, "t", None, None));
        let cil_expected = "(system_u system_r t ((s0) (s0)))";
        assert_eq!(context_sexp.to_string(), cil_expected.to_string());
    }

    #[test]
    fn generate_sid_rules_test() {
        let sid1 = Sid::new("foo", Context::new(true, None, None, "foo_t", None, None));
        let sid2 = Sid::new("bar", Context::new(false, None, None, "bar_t", None, None));

        let rules = generate_sid_rules(vec![sid1, sid2]);
        let cil_expected = vec!["(sid foo)",
                                "(sidcontext foo (system_u system_r foo_t ((s0) (s0))))",
                                "(sid bar)",
                                "(sidcontext bar (system_u object_r bar_t ((s0) (s0))))",
                                "(sidorder (foo bar))"];
        assert_eq!(rules.len(), cil_expected.len());
        let mut iter = rules.iter().zip(cil_expected.iter());
        while let Some(i) = iter.next() {
            assert_eq!(i.0.to_string(), i.1.to_string());
        }
    }

}
