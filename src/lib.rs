#[macro_use]
extern crate lalrpop_util;

mod ast;
mod compile;
mod constants;
pub mod error;
mod functions;
mod internal_rep;
mod obj_class;
mod sexp_internal;

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
        .map(|s| sexp_internal::display_cil(s))
        .collect::<Vec<String>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    lalrpop_mod!(pub parser);

    use crate::error::{HLLCompileError, HLLParseError};
    use codespan_reporting::diagnostic::Diagnostic;
    use std::fs;
    use std::io::Write;
    use std::process::Command;
    use std::str;

    use super::*;

    const POLICIES_DIR: &str = "data/policies/";
    const ERROR_POLICIES_DIR: &str = "data/error_policies/";

    fn valid_policy_test(filename: &str, expected_contents: &[&str]) {
        let policy_file = [POLICIES_DIR, filename].concat();
        let policy_contents = match compile_system_policy(vec![&policy_file]) {
            Ok(p) => p,
            Err(e) => panic!("Compilation of {} failed with {:?}", filename, e),
        };
        for query in expected_contents {
            assert!(
                policy_contents.contains(query),
                "Output policy does not contain {}",
                query
            );
        }
        let file_out_path = &[filename, "_test.cil"].concat();
        let cil_out_path = &[filename, "_test_out_policy"].concat();
        let mut out_file = fs::File::create(&file_out_path).unwrap();
        out_file.write_all(policy_contents.as_bytes()).unwrap();

        let output = Command::new("secilc")
            .arg(["--output=", cil_out_path].concat())
            .arg(file_out_path)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "secilc compilation of {} failed with {}",
            filename,
            str::from_utf8(&output.stderr).unwrap()
        );

        let mut err = false;
        for f in &[file_out_path, cil_out_path] {
            err |= fs::remove_file(f).is_err();
        }
        assert!(!err, "Error removing generated policy files");
    }

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
        valid_policy_test("attribute.hll", &["attribute user_type", "type staff"]);
    }

    #[test]
    fn simple_policy_build_test() {
        valid_policy_test("simple.hll", &[]);
    }

    #[test]
    fn function_build_test() {
        valid_policy_test("function.hll", &["macro my_file-read", "call my_file-read"]);
    }

    #[test]
    fn auditallow_test() {
        valid_policy_test("auditallow.hll", &["auditallow my_domain foo"]);
    }

    #[test]
    fn dontaudit_test() {
        valid_policy_test("dontaudit.hll", &["(dontaudit my_domain foo"]);
    }

    #[test]
    fn arguments_test() {
        valid_policy_test(
            "arguments.hll",
            &["(macro foo-some_func ((type this) (name a) (name b) (type c) (type d))"],
        );
    }

    #[test]
    fn filecon_test() {
        valid_policy_test(
            "filecon.hll",
            &["(filecon \"/bin\" file (", "(filecon \"/bin\" dir ("],
        );
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
                assert_eq!(e.error_count(), 4);
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

    #[test]
    fn domain_filecon_test() {
        let policy_file = [ERROR_POLICIES_DIR, "domain_filecon.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("file_context() in domain compiled successfully"),
            Err(e) => {
                for error in e {
                    assert!(
                        matches!(error, HLLErrorItem::Compile(HLLCompileError { msg: message, .. })
                                     if message.contains("File context statements are only allowed in resources"))
                    );
                }
            }
        }
    }
}
