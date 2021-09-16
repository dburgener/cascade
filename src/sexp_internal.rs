use sexp::*;

// the sexp crate doesn't treat foo and "foo" as separate strings, which we need
// The quoting behavior in the sexp crate automatically handles quoting in situations where the
// string contains a quote or a space, so we need to avoid those in order for this to work, but 1.
// We want to avoid those anyways and 2. The default behavior makes actually inserting a quoted
// string that wouldn't be automatically quoted impossible.
// https://github.com/cgaebel/sexp/issues/2
pub fn display_cil(expr: &sexp::Sexp) -> String {
    match expr {
        Sexp::List(l) => {
            format!(
                "({})",
                l.iter()
                    .map(|s| display_cil(s))
                    .collect::<Vec<String>>()
                    .join(" ")
            )
        }
        Sexp::Atom(a) => match a {
            Atom::S(s) => s.to_string(),
            _ => a.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_cil() {
        let cil = parse("(foo)").unwrap();
        assert_eq!(display_cil(&cil), cil.to_string());

        let cil = parse("(foo (bar baz))").unwrap();
        assert_eq!(display_cil(&cil), cil.to_string());

        let cil = parse("foo").unwrap();
        assert_eq!(display_cil(&cil), cil.to_string());

        let cil = parse("32").unwrap();
        assert_eq!(display_cil(&cil), cil.to_string());

        let cil = atom_s("\"/bin\"");
        assert_eq!(display_cil(&cil), "\"/bin\"".to_string());
    }
}
