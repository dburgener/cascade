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

use std::collections::HashMap;

use codespan_reporting::files::SimpleFile;
use error::{HLLErrorItem, HLLErrors};
use lalrpop_util::ParseError;

lalrpop_mod!(pub parser);

pub fn compile_system_policy(input_files: Vec<&str>) -> Result<String, error::HLLErrors> {
    let mut policies: Vec<ast::PolicyFile> = Vec::new();
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

        policies.push(ast::PolicyFile::new(
            *p,
            SimpleFile::new(f.into(), policy_str.clone()),
        ));
    }

    // Generic initialization
    let classlist = obj_class::make_classlist();
    let mut type_map = compile::get_built_in_types_map();
    let mut func_map = HashMap::new();
    let mut policy_rules = Vec::new();

    // Collect all type declarations
    for p in &policies {
        compile::extend_type_map(p, &mut type_map);
    }

    // Collect all function declarations
    for p in &policies {
        func_map.extend(
            compile::build_func_map(&p.policy.exprs, &type_map, None, &p.file)?.into_iter(),
        );
    }

    // Validate all functions
    let func_map_copy = func_map.clone(); // In order to read function info while mutating
    compile::validate_functions(&mut func_map, &type_map, &classlist, &func_map_copy)?;

    for p in &policies {
        policy_rules.extend(
            compile::compile_rules_one_file(&p, &classlist, &type_map, &func_map)?.into_iter(),
        );
    }

    let cil_tree = compile::generate_sexp(&type_map, &classlist, policy_rules, &func_map)?;

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
        valid_policy_test(
            "attribute.hll",
            &[
                "attribute user_type",
                "type staff",
                "typeattributeset user_type (staff)",
                "typeattributeset domain (user_type)",
            ],
        );
    }

    #[test]
    fn simple_policy_build_test() {
        valid_policy_test("simple.hll", &[]);
    }

    #[test]
    fn function_build_test() {
        valid_policy_test(
            "function.hll",
            &["macro my_file-read", "call my_file-read", "allow source"],
        );
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
    fn domtrans_test() {
        valid_policy_test("domtrans.hll", &["typetransition bar foo_exec process foo"]);
    }

    #[test]
    fn makelist_test() {
        let policy_file = [POLICIES_DIR, "makelist.hll"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_p) => {
                // TODO: reenable.  See note in data/policies/makelist.hll
                //assert!(p.contains(
                //    "(call foo.foo_func"
                //));
                ()
            }
            Err(e) => panic!("Makelist compilation failed with {:?}", e),
        }
    }

    #[test]
    fn multifiles_test() {
        // valid_policy_test() is somewhat tightly wound to the one file case, so we'll code our
        // own copy here
        let policy_files = vec![
            [POLICIES_DIR, "multifile1.hll"].concat(),
            [POLICIES_DIR, "multifile2.hll"].concat(),
        ];
        let policy_files: Vec<&str> = policy_files.iter().map(|s| s as &str).collect();
        let mut policy_files_reversed = policy_files.clone();
        policy_files_reversed.reverse();

        for files in [policy_files, policy_files_reversed] {
            match compile_system_policy(files) {
                Ok(p) => {
                    assert!(p.contains("(call foo-read"));
                }
                Err(e) => panic!("Multi file compilation failed with {:?}", e),
            }
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
                assert_eq!(e.error_count(), 3);
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
                        matches!(error, HLLErrorItem::Compile(HLLCompileError { diagnostic: Diagnostic {
                            message: msg, .. },
                            .. })
                                     if msg.contains("file_context() calls are only allowed in resources"))
                    );
                }
            }
        }
    }
}
