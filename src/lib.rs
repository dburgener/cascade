#[macro_use]
extern crate lalrpop_util;

mod ast;
mod compile;
mod constants;
pub mod error;
mod functions;
mod internal_rep;

use error::{HLLErrorItem, HLLErrors};
use lalrpop_util::ParseError;

lalrpop_mod!(pub parser);

pub fn compile_system_policy(input_files: Vec<&str>) -> Result<String, error::HLLErrors> {
    let mut policies: Vec<Box<ast::Policy>> = Vec::new();
    // TODO: collect errors and return an HLLErrors at the end of the loop
    for f in input_files {
        let policy_str =
            std::fs::read_to_string(&f).map_err(|e| HLLErrors::from(HLLErrorItem::from(e)))?;
        let p = match parse_policy(&policy_str) {
            Ok(p) => p,
            Err(e) => {
                // TODO: avoid String duplication
                let err = error::HLLParseError::new(e, f.into(), policy_str.clone());
                return Err(HLLErrors::from(HLLErrorItem::Parse(err)));
            }
        };

        policies.push(p);
    }

    // TODO: Combine multiple files
    let cil_tree = compile::compile(&*policies[0])?;

    Ok(generate_cil(cil_tree))
}

fn parse_policy<'a>(
    policy: &'a str,
) -> Result<Box<ast::Policy>, ParseError<usize, lalrpop_util::lexer::Token<'a>, &'static str>> {
    // TODO: Probably should only construct once
    // Why though?
    parser::PolicyParser::new().parse(policy)
}

fn generate_cil(s: sexp::Sexp) -> String {
    s.to_string()
}

#[cfg(test)]
mod tests {
    lalrpop_mod!(pub parser);

    use std::fs;

    use super::*;

    const POLICIES_DIR: &str = "data/policies/";
    const ERROR_POLICIES_DIR: &str = "data/error_policies/";

    #[test]
    fn basic_expression_parse_test() {
        let res = parser::ExprParser::new().parse("domain foo {}");
        assert!(res.is_ok(), "Parse Error: {:?}", res);

        let res = parser::ExprParser::new().parse("virtual resource foo {}");
        assert!(res.is_ok(), "Parse Error: {:?}", res);

        let res = parser::ExprParser::new().parse("this.read();");
        assert!(res.is_ok(), "Parse Error: {:?}", res);
    }

    #[test]
    fn basic_policy_parse_test() {
        let policy_file = [POLICIES_DIR, "tmp_file.hll"].concat();
        let policy = fs::read_to_string(policy_file).unwrap();

        let res = parser::PolicyParser::new().parse(&policy);
        assert!(res.is_ok(), "Parse Error: {:?}", res);
    }

    #[test]
    fn cycle_error_test() {
        let policy_file = [ERROR_POLICIES_DIR, "cycle.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("Cycle compiled successfully"),
            Err(mut e) => {
                assert!(matches!(e.next(), Some(HLLErrorItem::Compile(_))));
                assert!(matches!(e.next(), Some(HLLErrorItem::Compile(_))));
                assert!(matches!(e.next(), None));
            }
        }
    }

    #[test]
    fn bad_type_error_test() {
        let policy_file = [ERROR_POLICIES_DIR, "nonexistent_inheritance.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("Nonexistent type compiled successfully"),
            Err(mut e) => {
                assert!(matches!(e.next(), Some(HLLErrorItem::Compile(_))));
                assert!(matches!(e.next(), None));
            }
        }
    }

    #[test]
    fn bad_allow_rules_test() {
        let policy_file = [ERROR_POLICIES_DIR, "bad_allow.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("Bad allow rules compiled successfully"),
            Err(e) => {
                for error in e {
                    assert!(matches!(error, HLLErrorItem::Compile(_)));
                }
            }
        }
    }
}
