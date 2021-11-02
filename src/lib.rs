// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
#[macro_use]
extern crate lalrpop_util;

extern crate thiserror;

mod ast;
mod compile;
mod constants;
pub mod error;
mod functions;
mod internal_rep;
mod obj_class;
mod sexp_internal;

use std::collections::HashMap;

use ast::{Policy, PolicyFile};

use codespan_reporting::files::SimpleFile;
use error::HLLErrors;
use lalrpop_util::ParseError;

#[cfg(test)]
use error::HLLErrorItem;

lalrpop_mod!(pub parser);

/// Compile a complete system policy
/// The list of input files list should contain filenames of files containing policy to be
/// compiled.
/// Returns a Result containing either a string of CIL policy which is the compiled result or a
/// list of errors.
/// In order to convert the compiled CIL policy into a usable policy, you must use secilc
pub fn compile_system_policy(input_files: Vec<&str>) -> Result<String, error::HLLErrors> {
    let mut policies: Vec<PolicyFile> = Vec::new();
    let mut errors = HLLErrors::new();

    for f in input_files {
        let policy_str = match std::fs::read_to_string(&f) {
            Ok(s) => s,
            Err(e) => {
                errors.add_error(e);
                continue;
            }
        };
        let p = match parse_policy(&policy_str) {
            Ok(p) => p,
            Err(e) => {
                // TODO: avoid String duplication
                errors.add_error(error::HLLParseError::new(e, f.into(), policy_str.clone()));
                continue;
            }
        };

        policies.push(PolicyFile::new(*p, SimpleFile::new(f.into(), policy_str)));
    }
    // Stops if something went wrong for this major step.
    errors = errors.into_result_self()?;

    // Generic initialization
    let classlist = obj_class::make_classlist();
    let mut type_map = compile::get_built_in_types_map();
    let mut func_map = HashMap::new();
    let mut policy_rules = Vec::new();

    // Collect all type declarations
    for p in &policies {
        match compile::extend_type_map(p, &mut type_map) {
            Ok(()) => {}
            Err(e) => {
                errors.append(e);
                continue;
            }
        }
    }
    // Stops if something went wrong for this major step.
    errors = errors.into_result_self()?;

    // Applies annotations
    {
        let mut tmp_func_map = HashMap::new();

        // Collect all function declarations
        for p in &policies {
            tmp_func_map.extend(
                match compile::build_func_map(&p.policy.exprs, &type_map, None, &p.file) {
                    Ok(m) => m.into_iter(),
                    Err(e) => {
                        errors.append(e);
                        continue;
                    }
                },
            );
        }

        // TODO: Validate original functions before adding synthetic ones to avoid confusing errors for users.

        match compile::apply_annotations(&type_map, &tmp_func_map) {
            Ok(exprs) => {
                let pf = PolicyFile::new(
                    Policy::new(exprs),
                    SimpleFile::new(String::new(), String::new()),
                );
                match compile::extend_type_map(&pf, &mut type_map) {
                    Ok(()) => policies.push(pf),
                    Err(e) => errors.append(e),
                }
            }
            Err(e) => errors.append(e),
        }
    }
    // Stops if something went wrong for this major step.
    errors = errors.into_result_self()?;

    // Collect all function declarations
    for p in &policies {
        func_map.extend(
            match compile::build_func_map(&p.policy.exprs, &type_map, None, &p.file) {
                Ok(m) => m.into_iter(),
                Err(e) => {
                    errors.append(e);
                    continue;
                }
            },
        );
    }
    // Stops if something went wrong for this major step.
    errors = errors.into_result_self()?;

    // Validate all functions
    let func_map_copy = func_map.clone(); // In order to read function info while mutating
    compile::validate_functions(&mut func_map, &type_map, &classlist, &func_map_copy)?;

    for p in &policies {
        policy_rules.extend(
            match compile::compile_rules_one_file(&p, &classlist, &type_map, &func_map) {
                Ok(r) => r.into_iter(),
                Err(e) => {
                    errors.append(e);
                    continue;
                }
            },
        );
    }
    // Stops if something went wrong for this major step.
    errors = errors.into_result_self()?;

    let cil_tree = compile::generate_sexp(&type_map, &classlist, policy_rules, &func_map)?;

    errors.into_result(generate_cil(cil_tree))
}

fn parse_policy<'a>(
    policy: &'a str,
) -> Result<Box<Policy>, ParseError<usize, lalrpop_util::lexer::Token<'a>, &'static str>> {
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

    use crate::error::{Diag, HLLCompileError, HLLParseError};
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
            Err(e) => panic!("Compilation of {} failed with {}", filename, e),
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
        let policy_file = [POLICIES_DIR, "tmp_file.cas"].concat();
        let policy = fs::read_to_string(policy_file).unwrap();

        let res = parser::PolicyParser::new().parse(&policy);
        assert!(res.is_ok(), "Parse Error: {:?}", res);
    }

    #[test]
    fn attributes_test() {
        valid_policy_test(
            "attribute.cas",
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
        valid_policy_test("simple.cas", &[]);
    }

    #[test]
    fn function_build_test() {
        valid_policy_test(
            "function.cas",
            &["macro my_file-read", "call my_file-read", "allow source"],
        );
    }

    #[test]
    fn auditallow_test() {
        valid_policy_test("auditallow.cas", &["auditallow my_domain foo"]);
    }

    #[test]
    fn dontaudit_test() {
        valid_policy_test("dontaudit.cas", &["(dontaudit my_domain foo"]);
    }

    #[test]
    fn arguments_test() {
        valid_policy_test(
            "arguments.cas",
            &["(macro foo-some_func ((type this) (name a) (name b) (type c) (type d))"],
        );
    }

    #[test]
    fn filecon_test() {
        valid_policy_test(
            "filecon.cas",
            &["(filecon \"/bin\" file (", "(filecon \"/bin\" dir ("],
        );
    }

    #[test]
    fn domtrans_test() {
        valid_policy_test("domtrans.cas", &["typetransition bar foo_exec process foo"]);
    }

    #[test]
    fn makelist_test() {
        let policy_file = [POLICIES_DIR, "makelist.cas"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_p) => {
                // TODO: reenable.  See note in data/policies/makelist.cas
                //assert!(p.contains(
                //    "(call foo.foo_func"
                //));
                ()
            }
            Err(e) => panic!("Makelist compilation failed with {}", e),
        }
    }

    #[test]
    fn multifiles_test() {
        // valid_policy_test() is somewhat tightly wound to the one file case, so we'll code our
        // own copy here
        let policy_files = vec![
            [POLICIES_DIR, "multifile1.cas"].concat(),
            [POLICIES_DIR, "multifile2.cas"].concat(),
        ];
        let policy_files: Vec<&str> = policy_files.iter().map(|s| s as &str).collect();
        let mut policy_files_reversed = policy_files.clone();
        policy_files_reversed.reverse();

        for files in [policy_files, policy_files_reversed] {
            match compile_system_policy(files) {
                Ok(p) => {
                    assert!(p.contains("(call foo-read"));
                }
                Err(e) => panic!("Multi file compilation failed with {}", e),
            }
        }
    }

    #[test]
    fn cycle_error_test() {
        let policy_file = [ERROR_POLICIES_DIR, "cycle.cas"].concat();

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
        let policy_file = [ERROR_POLICIES_DIR, "nonexistent_inheritance.cas"].concat();

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
        let policy_file = [ERROR_POLICIES_DIR, "bad_allow.cas"].concat();

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
    fn non_virtual_inherit_test() {
        let policy_file = [ERROR_POLICIES_DIR, "non_virtual_inherit.cas"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("Non virtual inheritance compiled successfully"),
            Err(e) => {
                assert_eq!(e.error_count(), 1);
                for error in e {
                    assert!(matches!(error, HLLErrorItem::Compile(_)));
                }
            }
        }
    }

    #[test]
    fn parsing_unrecognized_token() {
        let policy_file = [ERROR_POLICIES_DIR, "parse_unrecognized_token.cas"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("Bad grammar compiled successfully"),
            Err(e) => {
                for error in e {
                    assert!(matches!(
                                error,
                                HLLErrorItem::Parse(HLLParseError {
                                    diagnostic: Diag {
                                        inner: Diagnostic {
                                            message: msg,
                                            ..
                                        }
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
        let policy_file = [ERROR_POLICIES_DIR, "parse_unknown_token.cas"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("Bad grammar compiled successfully"),
            Err(e) => {
                for error in e {
                    assert!(matches!(
                                error,
                                HLLErrorItem::Parse(HLLParseError {
                                    diagnostic: Diag {
                                        inner: Diagnostic {
                                            message: msg,
                                            ..
                                        }
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
        let policy_file = [ERROR_POLICIES_DIR, "parse_unexpected_eof.cas"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("Bad grammar compiled successfully"),
            Err(e) => {
                for error in e {
                    assert!(matches!(
                                error,
                                HLLErrorItem::Parse(HLLParseError {
                                    diagnostic: Diag {
                                        inner: Diagnostic {
                                            message: msg,
                                            ..
                                        }
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
        let policy_file = [ERROR_POLICIES_DIR, "domain_filecon.cas"].concat();

        match compile_system_policy(vec![&policy_file]) {
            Ok(_) => panic!("file_context() in domain compiled successfully"),
            Err(e) => {
                for error in e {
                    assert!(matches!(error, HLLErrorItem::Compile(HLLCompileError {
                                diagnostic: Diag {
                                    inner: Diagnostic {
                                        message: msg,
                                        ..
                                    }
                                },
                                ..
                            }) if msg.contains("file_context() calls are only allowed in resources")
                    ));
                }
            }
        }
    }

    #[test]
    fn associate_test() {
        valid_policy_test(
            "associate.cas",
            &[
                "call bar-tmp-associated_call_from_tmp (bar-tmp bar)",
                "call bar-var-associated_call_from_var (bar-var bar)",
                "call baz-tmp-associated_call_from_tmp (baz-tmp baz)",
                "call baz-var-associated_call_from_var (baz-var baz)",
                "call foo-tmp-associated_call_from_tmp (foo-tmp foo)",
                "call foo-var-associated_call_from_var (foo-var foo)",
                "call tmp-associated_call_from_tmp (tmp foo)",
                "call tmp-not_an_associated_call (tmp foo)",
                "macro bar-bin-not_an_associated_call_from_bin ((type this) (type source)) (allow source bin (file (read)))",
                "macro bar-tmp-associated_call_from_tmp ((type this) (type source)) (allow source tmp (file (read)))",
                "macro bar-tmp-not_an_associated_call ((type this) (type source)) (allow source tmp (file (write)))",
                "macro bar-var-associated_call_from_var ((type this) (type source)) (allow source var (file (read)))",
                "macro baz-bin-not_an_associated_call_from_bin ((type this) (type source)) (allow source bin (file (read)))",
                "macro baz-tmp-associated_call_from_tmp ((type this) (type source)) (allow source tmp (file (read)))",
                "macro baz-tmp-not_an_associated_call ((type this) (type source)) (allow source tmp (file (write)))",
                "macro baz-var-associated_call_from_var ((type this) (type source)) (allow source var (file (read)))",
                "macro bin-not_an_associated_call_from_bin ((type this) (type source)) (allow source bin (file (read)))",
                "macro foo-tmp-associated_call_from_tmp ((type this) (type source)) (allow source tmp (file (read)))",
                "macro foo-tmp-not_an_associated_call ((type this) (type source)) (allow source tmp (file (write)))",
                "macro foo-var-associated_call_from_var ((type this) (type source)) (allow source var (file (read)))",
                "macro tmp-associated_call_from_tmp ((type this) (type source)) (allow source tmp (file (read)))",
                "macro tmp-not_an_associated_call ((type this) (type source)) (allow source tmp (file (write)))",
                "macro var-associated_call_from_var ((type this) (type source)) (allow source var (file (read)))",
                "roletype object_r bar-bin",
                "roletype object_r bar-tmp",
                "roletype object_r bar-var",
                "roletype object_r baz-bin",
                "roletype object_r baz-tmp",
                "roletype object_r baz-var",
                "roletype object_r foo-tmp",
                "roletype object_r foo-var",
                "type bar-bin",
                "type bar-tmp",
                "type bar-var",
                "type baz-bin",
                "type baz-tmp",
                "type baz-var",
                "type foo-tmp",
                "type foo-var",
                "typeattributeset resource (bar-bin)",
                "typeattributeset resource (bar-tmp)",
                "typeattributeset resource (bar-var)",
                "typeattributeset resource (baz-bin)",
                "typeattributeset resource (baz-tmp)",
                "typeattributeset resource (baz-var)",
                "typeattributeset resource (foo-tmp)",
                "typeattributeset resource (foo-var)",
            ],
        );
    }
}
