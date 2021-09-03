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

fn generate_cil(v: Vec<sexp::Sexp>) -> String {
    v.iter()
        .map(|s| s.to_string())
        .collect::<Vec<String>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    lalrpop_mod!(pub parser);

    use crate::error::HLLParseError;
    use codespan_reporting::diagnostic::Diagnostic;
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
    fn attributes_test() {
        let policy_file = [POLICIES_DIR, "attribute.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(p) => {
                assert!(p.contains("attribute user_type"));
                assert!(p.contains("type staff"));
            }
            Err(e) => panic!("Attribute compilation failed with {:?}", e),
        }
    }

    #[test]
    fn simple_policy_build_test() {
        let policy_file = [POLICIES_DIR, "simple.hll"].concat();

        let res = compile_system_policy(vec![&policy_file]);

        assert!(res.is_ok(), "Failed to build simple policy: {:?}", res);
    }

    #[test]
    fn function_build_test() {
        let policy_file = [POLICIES_DIR, "function.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(p) => {
                assert!(p.contains("macro my_file.read"));
                assert!(p.contains("call my_file.read"));
            }
            Err(e) => panic!("Function compilation failed with {:?}", e),
        }
    }

    #[test]
    fn auditallow_test() {
        let policy_file = [POLICIES_DIR, "auditallow.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(p) => {
                assert!(p.contains("(auditallow my_domain foo"));
            }
            Err(e) => panic!("Auditallow compilation failed with {:?}", e),
        }
    }

    #[test]
    fn dontaudit_test() {
        let policy_file = [POLICIES_DIR, "dontaudit.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(p) => {
                assert!(p.contains("(dontaudit my_domain foo"));
            }
            Err(e) => panic!("Dontaudit compilation failed with {:?}", e),
        }
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

    #[test]
    fn parsing_unrecognized_token() {
        let policy_file = [ERROR_POLICIES_DIR, "parse_unrecognized_token.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("Bad grammar compiled successfully"),
            Err(e) => {
                for error in e {
                    assert!(matches!(
                                error,
                                HLLErrorItem::Parse(HLLParseError {
                                    diagnostic: Diagnostic {
                                        message: msg,
                                        ..
                                    },
                                    ..
                                })
                                if msg == "Unexpected character \".\"".to_string()));
                }
            }
        }
    }

    #[test]
    fn parsing_unknown_token() {
        let policy_file = [ERROR_POLICIES_DIR, "parse_unknown_token.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("Bad grammar compiled successfully"),
            Err(e) => {
                for error in e {
                    assert!(matches!(
                                error,
                                HLLErrorItem::Parse(HLLParseError {
                                    diagnostic: Diagnostic {
                                        message: msg,
                                        ..
                                    },
                                    ..
                                })
                                if msg == "Unknown character".to_string()));
                }
            }
        }
    }

    #[test]
    fn parsing_unexpected_eof() {
        let policy_file = [ERROR_POLICIES_DIR, "parse_unexpected_eof.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("Bad grammar compiled successfully"),
            Err(e) => {
                for error in e {
                    assert!(matches!(
                                error,
                                HLLErrorItem::Parse(HLLParseError {
                                    diagnostic: Diagnostic {
                                        message: msg,
                                        ..
                                    },
                                    ..
                                })
                                if msg == "Unexpected end of file".to_string()));
                }
            }
        }
    }
}
