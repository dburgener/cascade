use sexp::{Sexp, Atom};

pub enum AvRule {
    Allow,
    Dontaudit,
    Auditallow,
    Neverallow,
}

// TODO: If we use arguments other than strings, can we get some compile time gaurantees that these
// are valid types?
pub fn generate_cil_for_av_rule(av: AvRule, s: String, t: String, c: String, p: Vec<String>) -> sexp::Sexp {
    let mut ret: Vec<sexp::Sexp> = Vec::new();

    ret.push(match av {
        AvRule::Allow => Sexp::Atom(Atom::S("allow".to_string())),
        AvRule::Dontaudit => Sexp::Atom(Atom::S("dontaudit".to_string())),
        AvRule::Auditallow => Sexp::Atom(Atom::S("auditallow".to_string())),
        AvRule::Neverallow => Sexp::Atom(Atom::S("neverallow".to_string())),
    });

    ret.push(Sexp::Atom(Atom::S(s)));
    ret.push(Sexp::Atom(Atom::S(t)));

    let mut classpermset: Vec<sexp::Sexp> = Vec::new();
    classpermset.push(Sexp::Atom(Atom::S(c)));
    // TODO: this can probably be a one-liner with map that would be cleaner
    let mut perms: Vec<sexp::Sexp> = Vec::new();
    for perm in p {
        perms.push(Sexp::Atom(Atom::S(perm)));
    }
    classpermset.push(Sexp::List(perms));

    ret.push(Sexp::List(classpermset));

    return Sexp::List(ret);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_cil_for_av_rule_test() {
        let cil_sexp = generate_cil_for_av_rule(AvRule::Allow, "foo".to_string(), "bar".to_string(), "file".to_string(), vec!["read".to_string(), "getattr".to_string()]);
        let cil_expected = "(allow foo bar (file (read getattr)))";

        assert_eq!(cil_sexp.to_string(), cil_expected.to_string());
    }
}
