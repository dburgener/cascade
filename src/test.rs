lalrpop_mod!(#[allow(clippy::all)] pub parser);

use crate::error::{CompileError, Diag, ParseError};
use codespan_reporting::diagnostic::Diagnostic;
use std::fs;
use std::io::Write;
use std::process::Command;
use std::str;

use walkdir::WalkDir;

use super::*;

const POLICIES_DIR: &str = "data/policies/";
const ERROR_POLICIES_DIR: &str = "data/error_policies/";
const EXPECTED_CIL_DIR: &str = "data/expected_cil/";

#[test]
fn characterization_tests() {
    let mut count = 0;

    for f in fs::read_dir(POLICIES_DIR).unwrap() {
        count += 1;
        let policy_path = f.unwrap().path();
        let cil_path = match policy_path.extension() {
            Some(e) if e == "cas" => std::path::Path::new(EXPECTED_CIL_DIR).join(
                policy_path
                    .with_extension("cil")
                    .file_name()
                    .expect(&format!(
                        "failed to extract file name from `{}`",
                        policy_path.to_string_lossy()
                    )),
            ),
            _ => continue,
        };

        // TODO: Make compile_machine_policy() take an iterator of AsRef<Path>.
        let (cil_gen, _) = match compile_combined(vec![&policy_path.to_string_lossy()]) {
            Ok(c) => c,
            Err(e) => match fs::read_to_string(&cil_path) {
                Ok(_) => panic!(
                    "Failed to compile '{}', but there is a reference CIL file: {}",
                    policy_path.to_string_lossy(),
                    e
                ),
                Err(_) => continue,
            },
        };
        let cil_ref = fs::read_to_string(&cil_path).unwrap_or_else(|e| {
            panic!(
                "Failed to read file '{}': {}. \
	    You may want to create it with tools/update-expected-cil.sh",
                cil_path.to_string_lossy(),
                e
            )
        });
        if cil_gen != cil_ref {
            panic!(
                "CIL generation doesn't match the recorded one for '{}'. \
	    You may want to update it with tools/update-expected-cil.sh",
                policy_path.to_string_lossy()
            )
        }
    }

    // Make sure we don't check an empty directory.
    assert!(count > 9);
}

fn valid_policy_test(
    filename: &str,
    expected_contents: &[&str],
    disallowed_contents: &[&str],
    expected_warn_count: usize,
) {
    let policy_file = [POLICIES_DIR, filename].concat();
    let (policy_contents, warnings) = match compile_combined(vec![&policy_file]) {
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
    for query in disallowed_contents {
        assert!(
            !policy_contents.contains(query),
            "Output policy contains {}",
            query
        );
    }

    assert_eq!(warnings.count(), expected_warn_count);

    let file_out_path = &[filename, "_test.cil"].concat();
    let cil_out_path = &[filename, "_test_out_policy"].concat();
    let mut out_file = fs::File::create(file_out_path).unwrap();
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

macro_rules! error_policy_test {
($filename:literal, $expected_error_count:literal, $error_pattern:pat_param $(if $guard:expr)?) => {
    let policy_file = [ERROR_POLICIES_DIR, $filename].concat();
    match compile_combined(vec![&policy_file]) {
	Ok(_) => panic!("{} compiled successfully", $filename),
	Err(e) => {
	    assert_eq!(e.error_count(), $expected_error_count);
	    for error in e {
		assert!(matches!(error, $error_pattern $(if $guard)?));
	    }
	}
    }
}
}

#[test]
fn basic_expression_parse_test() {
    let mut errors = Vec::new();
    let res = parser::ExprParser::new().parse(&mut errors, "domain foo {}");
    assert!(res.is_ok(), "Parse Error: {:?}", res);

    let res = parser::ExprParser::new().parse(&mut errors, "virtual resource foo {}");
    assert!(res.is_ok(), "Parse Error: {:?}", res);

    let res = parser::ExprParser::new().parse(&mut errors, "this.read();");
    assert!(res.is_ok(), "Parse Error: {:?}", res);

    assert_eq!(errors.len(), 0);
}

#[test]
fn name_decl_test() {
    let mut errors = Vec::new();
    for name in &["a", "a_a", "a_a_a", "a_aa_a", "a0", "a_0", "a0_00"] {
        let _: ast::CascadeString = parser::NameDeclParser::new()
            .parse(&mut errors, name)
            .expect(&format!("failed to validate `{name}`"));
    }
    for name in &[
        "0", "0a", "_", "_a", "a_", "a_a_", "a__a", "a__a_a", "a_a___a", "-", "a-a",
    ] {
        let _: LalrpopParseError<_, _, _> = parser::NameDeclParser::new()
            .parse(&mut errors, name)
            .expect_err(&format!("successfully validated invalid `{name}`"));
    }
    assert_eq!(errors.len(), 0)
}

#[test]
fn basic_policy_parse_test() {
    let mut errors = Vec::new();
    let policy_file = [POLICIES_DIR, "tmp_file.cas"].concat();
    let policy = fs::read_to_string(policy_file).unwrap();

    let res = parser::PolicyParser::new().parse(&mut errors, &policy);
    assert!(res.is_ok(), "Parse Error: {:?}", res);
    assert_eq!(errors.len(), 0);
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
        &[],
        0,
    );
}

#[test]
fn simple_policy_build_test() {
    valid_policy_test("simple.cas", &[], &[], 0);
}

#[test]
fn function_build_test() {
    valid_policy_test(
    "function.cas",
    &["macro my_file-read", "call my_file-read", "allow source",
    "(macro my_file-call_read ((type this) (type source)) (call my_file-read (my_file source)))",
    "(call my_domain-access (my_domain my_domain-res))",
    ],
    &["my_domain.res"],
    0,
);
}

#[test]
fn auditallow_test() {
    valid_policy_test("auditallow.cas", &["auditallow my_domain foo"], &[], 0);
}

#[test]
fn dontaudit_test() {
    valid_policy_test("dontaudit.cas", &["(dontaudit my_domain foo"], &[], 0);
}

#[test]
fn arguments_test() {
    valid_policy_test(
        "arguments.cas",
        &["(macro foo-some_func ((type this) (name a) (name b) (type c) (type d))"],
        &[],
        0,
    );
}

#[test]
fn filecon_test() {
    valid_policy_test(
        "filecon.cas",
        &[
            "(filecon \"/bin\" file (",
            "(filecon \"/bin\" dir (",
            "(filecon \"/etc\" any (",
        ],
        &["this"],
        0,
    );
}

#[test]
fn domtrans_test() {
    valid_policy_test(
        "domtrans.cas",
        &["typetransition bar foo_exec process foo"],
        &[],
        0,
    );
}

#[test]
fn symbol_binding_test() {
    valid_policy_test(
        "let.cas",
        &["(allow foo bar (file (read open getattr)))"],
        &[],
        0,
    );
}

#[test]
fn virtual_function_test() {
    valid_policy_test(
        "virtual_function.cas",
        &["macro foo-foo"],
        &["macro foo_parent-foo"],
        0,
    );
}

#[test]
fn alias_test() {
    valid_policy_test(
        "alias.cas",
        &[
            "(typealias bar)",
            "(typealiasactual bar baz)",
            "macro baz-read",
            "macro bar-list",
            "macro bar-read",
            "macro foo-list",
            "macro foo-read",
            "macro baz-list",
        ],
        &[],
        0,
    )
}

#[test]
fn named_args_test() {
    valid_policy_test(
        "named_args.cas",
        &[
            "(call some_domain-three_args (some_domain bar baz foo))",
            "(call some_domain-three_args (some_domain foo bar baz))",
        ],
        &[],
        0,
    );
}

// TODO:  This test doesn't do much yet.  With just parser support the
// conditionals just ignore both blocks and generate no policy
// Once conditionals are actually working, we should add a bunch more
// cases and add positive checks for the arms that should be included
// and negative for the ones that shouldn't (and for runtime conditionals
// we'll need to see both since the condition gets passed through to the
// final policy in the form of booleans and cil conditionals
// For now, this confirms that conditionals parse correctly
// The warn count is currently 3 because of warnings that if blocks are unimplemented.  That
// will go to 0 once conditional policy is fully implemented
#[test]
fn conditional_test() {
    valid_policy_test(
        "conditional.cas",
        &[], // TODO
        &[
            "my_tunable", // Tunables don't get passed through to CIL
        ],
        8,
    );
}

#[test]
fn default_arg_test() {
    valid_policy_test(
        "default.cas",
        &["(call foo-read (foo bar))", "(call foo-read (foo baz))"],
        &[],
        0,
    );
}

// TODO: Add expected contents list to tests that contain modules
// after module implementation is complete.
#[test]
fn alias_module_test() {
    valid_policy_test("module_alias.cas", &[], &[], 0)
}

#[test]
fn arguments_module_test() {
    valid_policy_test("module_arguments.cas", &[], &[], 0)
}

#[test]
fn simple_module_test() {
    valid_policy_test("module_simple.cas", &[], &[], 0)
}

#[test]
fn machine_test() {
    valid_policy_test("machines.cas", &["(handleunknown allow)"], &[], 0);
}

#[test]
fn extend_test() {
    valid_policy_test(
        "extend.cas",
        &[
            "(allow bar foo (file (getattr)))",
            "(allow bar foo (file (write)))",
            "(macro foo-my_func ((type this) (type source)) (allow source this (file (read))))",
            "(macro resource-read ((type this) (type source)) (allow source this (file (read))))",
            "(typealias some_alias)",
            "(type bar-baz)",
        ],
        &[],
        0,
    );
}

#[test]
fn networking_rules_test() {
    valid_policy_test(
        "networking_rules.cas",
        &[
            "(portcon tcp 1234 (system_u object_r my_port ((s0) (s0))))",
            "(portcon udp 1235 (system_u object_r my_port ((s0) (s0))))",
            "(portcon tcp 22 (system_u object_r my_port ((s0) (s0))))",
            "(portcon dccp 1337 (system_u object_r my_port ((s0) (s0))))",
            "(portcon sctp 43 (system_u object_r my_port ((s0) (s0))))",
        ],
        &[],
        0,
    );
}

#[test]
fn collection_test() {
    valid_policy_test(
        "collection.cas",
        &[
            "(macro foobar_reader-read_foo_and_bar",
            "(call foobar_reader-read_foo_and_bar",
        ],
        &[],
        0,
    );
}

#[test]
fn makelist_test() {
    valid_policy_test("makelist.cas", &["(call foo-foo_func"], &[], 0);
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

    let mut policies = Vec::new();

    for files in [policy_files, policy_files_reversed] {
        match compile_combined(files) {
            Ok((p, _)) => {
                assert!(p.contains("(call foo-read"));
                assert!(p.contains("(type extend_across_files-res1)"));
                assert!(p.contains("(type extend_across_files-res2)"));
                policies.push(p);
            }
            Err(e) => panic!("Multi file compilation failed with {}", e),
        }
    }

    assert_eq!(policies[0], policies[1]);
}

#[test]
fn compile_machine_policies_test() {
    let policy_files = vec![
        [POLICIES_DIR, "machine_building1.cas"].concat(),
        [POLICIES_DIR, "machine_building2.cas"].concat(),
        [POLICIES_DIR, "machine_building3.cas"].concat(),
    ];
    let policy_files: Vec<&str> = policy_files.iter().map(|s| s as &str).collect();
    let machine_names = vec!["foo".to_string(), "bar".to_string()];

    let res = compile_machine_policies(policy_files, machine_names);
    match res {
        Ok(hashmap) => {
            assert_eq!(hashmap.len(), 2);

            for (machine_name, (machine_cil, warnings)) in hashmap.iter() {
                if machine_name == "foo" {
                    assert!(machine_cil.contains("(handleunknown reject)"));
                    assert!(machine_cil.contains("(allow thud babble (file (read)))"));
                    assert!(machine_cil.contains("(allow thud babble (file (write)))"));
                    assert!(machine_cil.contains("(typeattributeset quux (qux))"));
                    assert!(machine_cil.contains("(macro qux-read ((type this) (type source)) (allow source this (file (read))))"));
                    assert!(machine_cil.contains("(typeattributeset domain (xyzzy))"));
                    assert!(machine_cil.contains("(typeattributeset domain (baz))"));
                    assert!(machine_cil.contains("(typeattributeset domain (quuz))"));

                    assert!(!machine_cil.contains("(type unused)"));
                } else {
                    assert!(machine_cil.contains("(handleunknown deny)"));
                    assert!(machine_cil.contains("(typeattributeset domain (baz))"));
                    assert!(machine_cil.contains("(typeattributeset domain (quuz))"));
                    assert!(machine_cil.contains("(typeattributeset quux (qux))"));
                    assert!(machine_cil.contains("(macro qux-read ((type this) (type source)) (allow source this (file (read))))"));

                    assert!(!machine_cil.contains("(type thud)"));
                    assert!(!machine_cil.contains("(type babble)"));
                    assert!(!machine_cil.contains("(type xyzzy)"));
                    assert!(!machine_cil.contains("(type unused)"));
                }

                assert!(warnings.is_empty());
            }
        }
        Err(e) => panic!("Machine building compilation failed with {}", e),
    }
}

#[test]
fn compile_machine_policies_all_test() {
    let policy_files = vec![
        [POLICIES_DIR, "machine_building1.cas"].concat(),
        [POLICIES_DIR, "machine_building2.cas"].concat(),
        [POLICIES_DIR, "machine_building3.cas"].concat(),
    ];
    let policy_files: Vec<&str> = policy_files.iter().map(|s| s as &str).collect();

    let res = compile_machine_policies_all(policy_files);
    match res {
        Ok(hashmap) => {
            assert_eq!(hashmap.len(), 3);
            for (machine_name, (machine_cil, warnings)) in hashmap.iter() {
                if machine_name == "foo" {
                    assert!(machine_cil.contains("(handleunknown reject)"));
                    assert!(machine_cil.contains("(allow thud babble (file (read)))"));
                    assert!(machine_cil.contains("(allow thud babble (file (write)))"));
                    assert!(machine_cil.contains("(typeattributeset quux (qux))"));
                    assert!(machine_cil.contains("(macro qux-read ((type this) (type source)) (allow source this (file (read))))"));
                    assert!(machine_cil.contains("(typeattributeset domain (xyzzy))"));
                    assert!(machine_cil.contains("(typeattributeset domain (baz))"));
                    assert!(machine_cil.contains("(typeattributeset domain (quuz))"));

                    assert!(!machine_cil.contains("(type unused)"));
                } else if machine_name == "bar" {
                    assert!(machine_cil.contains("(handleunknown deny)"));
                    assert!(machine_cil.contains("(typeattributeset domain (baz))"));
                    assert!(machine_cil.contains("(typeattributeset domain (quuz))"));
                    assert!(machine_cil.contains("(typeattributeset quux (qux))"));
                    assert!(machine_cil.contains("(macro qux-read ((type this) (type source)) (allow source this (file (read))))"));

                    assert!(!machine_cil.contains("(type thud)"));
                    assert!(!machine_cil.contains("(type babble)"));
                    assert!(!machine_cil.contains("(type xyzzy)"));
                    assert!(!machine_cil.contains("(type unused)"));
                } else {
                    assert!(machine_cil.contains("(handleunknown allow)"));
                    assert!(machine_cil.contains("(typeattributeset resource (unused))"));

                    assert!(!machine_cil.contains("(type thud)"));
                    assert!(!machine_cil.contains("(type babble)"));
                    assert!(!machine_cil.contains("(type xyzzy)"));
                    assert!(!machine_cil.contains("(type baz)"));
                    assert!(!machine_cil.contains("(type quuz)"));
                    assert!(!machine_cil.contains("(type qux)"));
                }
                assert!(warnings.is_empty());
            }
        }
        Err(e) => panic!("Machine building compilation failed with {}", e),
    }
}

#[test]
fn trait_test() {
    valid_policy_test(
        "trait.cas",
        &[
            "(macro baz-write ((type this) (type source)) (allow source this (file (write))))",
            "(macro foo-write ((type this) (type source)) (allow source this (dir (write))))",
            "(macro my_trait-write ((type this) (type source)) (allow source this (file (write))))",
        ],
        &["(macro foo-write ((type this) (type source)) (allow source this (file (write))))"],
        0,
    )
}

#[test]
fn this_casting_test() {
    valid_policy_test(
    "this_casting.cas",
    &["(macro daemon-runtime-read ((type this) (type source)) (allow source this (file (read))))",
    "(macro virt_resource-read ((type this) (type source)) (allow source this (file (read))))"],
    &[],
    0,
)
}

#[test]
fn casting_test() {
    valid_policy_test(
        "casting.cas",
        &[
            "(allow foo foo (capability",
            "(allow foo foo (capability2",
            "(macro foo-signal ((type this) (type source)) (allow source this (process (signal))))",
        ],
        &["(allow foo domain (capability"],
        0,
    )
}

#[test]
fn permissions_test() {
    valid_policy_test(
        "permissions.cas",
        &[
            "(allow foo foo (capability (fowner)))",
            "(allow foo foo (capability2 (mac_override)))",
            "(allow foo foo (capability2 (wake_alarm)))",
            "(allow foo bar (file (all)))",
        ],
        &["(capabilty (mac_override", "(capability (wake_alarm"],
        0,
    );
}

#[test]
fn derive_test() {
    valid_policy_test("derive.cas", &["(macro union_all_parents-read ((type this) (type source)) (allow source this (dir (read))) (allow source this (file (read))))",
"(macro derive_from_foo-read ((type this) (type source)) (allow source this (file (read))))",
"(macro custom_define-read ((type this) (type source)) (allow source this (lnk_file (read))))",
"(macro derive_all-read ((type this) (type source)) (allow source this (dir (read))) (allow source this (file (read))))",
"(macro enumerate_parents-read ((type this) (type source)) (allow source this (dir (read))) (allow source this (file (read))))",
"(macro derive_all-write ((type this) (type source)) (allow source this (dir (write))))",
"(macro defaults-write ((type this) (type source)) (allow source this (dir (write))))",
"(call associates-to_associate-some_associated_call",
"(macro some_child-domtrans ((type this) (type source) (type exec)) (typetransition source exec process this))",
"(macro overwrite_one-read ((type this) (type source)) (allow source this (lnk_file (read))))",
"(macro overwrite_one-write ((type this) (type source)) (allow source this (dir (write))))",
"(macro aliased_child-read",
"(macro an_alias-read",
// Bar's version, because foo doesn't define it
"(macro derive_from_foo2-write ((type this) (type source)) (allow source this (dir (write))))",
// Just foo's version, because we specifical parent=foo
"(macro derive_from_foo2-read ((type this) (type source)) (allow source this (file (read))))",
"(macro j-func ((type this) (type source)) (call i-func (this source)))",
"(macro j-func2 ((type this) (type source)) (call i-func2 (this source)))",
"(macro k-func ((type this) (type source)) (allow source this (file (read))) (allow source this (file (write))))",
"(macro k-func2 ((type this) (type source)) (allow source this (file (write))))",
],
&[
"(macro overwrite_one-read ((type this) (type source)) (allow source this (dir (read))))",
],
0);
}

#[test]
fn drop_test() {
    // TODO: This is just a parse test for now
    valid_policy_test("drop.cas", &[], &[], 1);
}

#[test]
fn optional_test() {
    // TODO: This is just a parse test for now
    valid_policy_test("optional.cas", &[], &[], 0);
}

#[test]
fn hint_test() {
    // TODO: This is non functional and should return a warning
    valid_policy_test("hint.cas", &[], &[], 1);
}

#[test]
fn implicit_this_test() {
    valid_policy_test("implicit_this.cas", &["(call foo-read (foo bar))"], &[], 0);
}

#[test]
fn inherit_alias_test() {
    valid_policy_test(
        "inherit_alias.cas",
        &["(typeattributeset an_alias (child))"],
        &[],
        0,
    );
}

#[test]
fn initial_context_test() {
    valid_policy_test(
        "initial_context.cas",
        &[
            "(sidcontext \"kernel\" (system_u object_r kernel_con ((s0) (s0))))",
            "(sidcontext \"security\" (system_u object_r security_con ((s0) (s0))))",
            "(sidcontext \"unlabeled\" (system_u object_r unlabeled_con ((s0) (s0)))",
        ],
        &[
            "(sidcontext kernel (system_u system_r kernel_sid ((s0) (s0))))",
            "(sidcontext security (system_u object_r security_sid ((s0) (s0))))",
            "(sidcontext unlabeled (system_u object_r unlabeled_sid ((s0) (s0))))",
        ],
        0,
    )
}

#[test]
fn arg_call_test() {
    valid_policy_test(
    "arg_call.cas",
    &[
    "(macro dom3-call_in_function ((type this) (type something)) (call bar3-read (bar3 this)) (call baz-call_source_read (baz bar3 this)))",
    "(call bar1-read (bar1 dom1))",
    "(call bar2-read (bar2 dom2))",
    ";Pushed to callers: (source-read source arg)"
    ],
    &[
    "call source-read",
    "dom4.foo",
    ],
    0,
    )
}

#[test]
fn extend_inherit_test() {
    valid_policy_test(
        "extend_inherit.cas",
        &[
            "(typeattributeset bar (dom-foo))",
            "(typeattributeset dom_parent (dom))",
        ],
        &[],
        0,
    )
}

// This is just a quick compile test.  The true purpose of these files is to actually boot in
// enforcing mode on a VM.  That is outside the scope of this test, but compile testing is a
// minimum first step and reasonable to do here.
#[test]
fn full_system_compile_test() {
    let full_system_path = [POLICIES_DIR, "full_system"].concat();
    let mut policy_files = Vec::new();

    for entry in WalkDir::new(full_system_path) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() && entry.path().extension().unwrap_or_default() == "cas" {
            policy_files.push(entry.path().display().to_string());
        }
    }

    let policy_files = policy_files.iter().map(|s| s as &str).collect();

    match compile_combined(policy_files) {
        Ok(_) => (),
        Err(e) => panic!("Full system compilation failed with {}", e),
    }
}

#[test]
fn cycle_error_test() {
    error_policy_test!("cycle.cas", 2, ErrorItem::Compile(_));
}

#[test]
fn bad_type_error_test() {
    error_policy_test!("nonexistent_inheritance.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn bad_allow_rules_test() {
    error_policy_test!("bad_allow.cas", 4, ErrorItem::Compile(_));
}

#[test]
fn non_virtual_inherit_test() {
    valid_policy_test("non_virtual_inherit.cas", &["(macro bar-read ((type this) (type source)) (allow source this (file (read open getattr))))",
"(call bar-read (bar baz))",
"(call bar-read (bar qux))",
"(allow baz foo (file (write)))",
"(allow baz bar (file (write)))",
"(allow qux foo (file (write)))",
"(allow qux bar (file (write)))",
"(allow qux foo (dir (write)))",
"(allow qux bar (dir (write)))",
"(typetransition baz bar process other)",
"(typetransition baz foo process other)",
"(typetransition qux bar process other)",
"(typetransition qux foo process other)",
"(macro baz-reference_foo ((type this) (type other)) (allow other bar (file (setattr))) (allow other foo (file (setattr))))",
],
&["(allow baz foo (dir (write)))"],
0);
}

#[test]
fn bad_alias_test() {
    error_policy_test!("alias.cas", 2, ErrorItem::Compile(_));
}

#[test]
fn bad_typecast_test() {
    error_policy_test!("bad_typecasts.cas", 3, ErrorItem::Compile(_));
}

#[test]
fn unsupplied_arg_test() {
    error_policy_test!("unsupplied_arg.cas", 1, ErrorItem::Compile(
	CompileError {
	    diagnostic: Diag {
		inner: Diagnostic {
		    message: msg,
		    ..
		}
	    },
	    ..
	})
    if msg == *"Function foo.read expected 2 arguments, got 1");
}

#[test]
fn virtual_function_error_test() {
    error_policy_test!("virtual_function_non_define.cas", 1,
    ErrorItem::Compile(CompileError {
	    diagnostic: Diag {
		inner: Diagnostic {
		    message: msg,
		    ..
		}
	    },
	    ..
	}) if msg.contains("foo does not define a function named foo_func"));

    error_policy_test!(
        "virtual_function_illegal_call.cas",
        1,
        ErrorItem::Compile(_)
    );
}

#[test]
fn parsing_unrecognized_token() {
    error_policy_test!("parse_unrecognized_token.cas", 1,
    ErrorItem::Parse(ParseError {
	diagnostic: Diag {
	    inner: Diagnostic {
		message: msg,
		..
	    }
	},
	..
    })
    if msg == *"Unexpected character \".\"");
}

#[test]
fn parsing_unknown_token() {
    error_policy_test!("parse_unknown_token.cas", 1,
    ErrorItem::Parse(ParseError {
	diagnostic: Diag {
	    inner: Diagnostic {
		message: msg,
		..
	    }
	},
	..
    })
    if msg == *"Unknown character");
}

#[test]
fn parsing_unexpected_eof() {
    error_policy_test!("parse_unexpected_eof.cas", 1,
    ErrorItem::Parse(ParseError {
	diagnostic: Diag {
	    inner: Diagnostic {
		message: msg,
		..
	    }
	},
	..
    })
    if msg == *"Unexpected end of file");
}

#[test]
fn domain_filecon_test() {
    error_policy_test!("domain_filecon.cas", 1,
    ErrorItem::Compile(CompileError {
            diagnostic: Diag {
            inner: Diagnostic {
                message: msg,
                ..
            }
            },
            ..
        }) if msg.contains("file_context() calls are only allowed in resources")
    );
}

#[test]
fn virtual_function_associate_error() {
    // TODO: This should be a compile error.  See comment in validate_functions()
    error_policy_test!(
        "virtual_function_association.cas",
        1,
        ErrorItem::Internal(_)
    );
    //error_policy_test!("virtual_function_association.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn invalid_module_error() {
    error_policy_test!("module_invalid.cas", 3, ErrorItem::Compile(_));
}

#[test]
fn module_cycle_error() {
    error_policy_test!("module_cycle.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn invalid_machine_error() {
    error_policy_test!("machine_invalid.cas", 5, ErrorItem::Compile(_));
}

#[test]
fn machine_invalid_module_error() {
    error_policy_test!("machine_invalid_module.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn machine_missing_req_config_error() {
    error_policy_test!("machine_missing_req_config.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn machine_multiple_config_error() {
    error_policy_test!("machine_multiple_config.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn machine_no_modules_error() {
    error_policy_test!("machine_no_modules.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn machine_virtual_error() {
    error_policy_test!(
        "machine_virtual.cas",
        1,
        ErrorItem::Parse(ParseError { .. })
    );
}

#[test]
fn extend_without_declaration_error() {
    error_policy_test!("extend_no_decl.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn extend_double_declaration_error() {
    error_policy_test!("extend_double_decl.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn machine_building_error() {
    let policy_files = vec![
        [POLICIES_DIR, "machine_building1.cas"].concat(),
        [POLICIES_DIR, "machine_building2.cas"].concat(),
        [POLICIES_DIR, "machine_building3.cas"].concat(),
    ];
    let policy_files: Vec<&str> = policy_files.iter().map(|s| s as &str).collect();
    let machine_names = vec!["baz".to_string()];

    let res = compile_machine_policies(policy_files, machine_names);
    match res {
        Ok(_) => panic!("Compiled successfully"),
        Err(e) => {
            assert_eq!(e.error_count(), 1);
            for error in e {
                assert!(matches!(error, ErrorItem::InvalidMachine(_)));
            }
        }
    }
}

#[test]
fn trait_no_impl() {
    error_policy_test!("trait_no_impl.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn derive_mismatched_signatures_error() {
    error_policy_test!("derive_non_matching_parents.cas", 1, ErrorItem::Compile(_));
    error_policy_test!("derive_diff_associated_call.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn derive_dups_error() {
    error_policy_test!("derive_explicit.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn associate_test() {
    valid_policy_test(
    "associate.cas",
    &[
	"call foo-tmp-associated_call_from_tmp (foo-tmp qux)",
	"call bar-tmp-associated_call_from_tmp (bar-tmp qux)",
	"call baz-tmp-associated_call_from_tmp (baz-tmp qux)",
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
	"type qux",
	"roletype system_r qux",
	"typeattributeset domain (qux)",
	"typeattribute tmp",
	"typeattributeset resource (tmp)",
	"typeattribute bin",
	"typeattributeset resource (bin)",
	"typeattribute foo",
	"typeattributeset domain (foo)",
	"typeattribute var",
	"typeattributeset resource (var)",
	"typeattribute bar",
	"typeattributeset foo (bar)",
	"typeattributeset domain (bar)",
	"typeattribute foo-var",
	"typeattributeset var (foo-var)",
	"typeattributeset resource (foo-var)",
	"typeattribute bar-bin",
	"typeattributeset bin (bar-bin)",
	"typeattributeset resource (bar-bin)",
	"typeattribute foo-tmp",
	"typeattributeset tmp (foo-tmp)",
	"typeattributeset resource (foo-tmp)",
	"typeattribute bar-tmp",
	"typeattributeset foo-tmp (bar-tmp)",
	"typeattributeset resource (bar-tmp)",
	"typeattribute bar-var",
	"typeattributeset foo-var (bar-var)",
	"typeattributeset resource (bar-var)",
	"type baz-var",
	// baz-var must inherit bar-var, not foo-var
	"typeattributeset bar-var (baz-var)",
	"typeattributeset resource (baz-var)",
	"type baz-bin",
	// baz-bin must inherit bar-var, not foo-bin
	"typeattributeset bar-bin (baz-bin)",
	"typeattributeset resource (baz-bin)",
	"type baz-tmp",
	// baz-tmp must inherit bar-tmp, not foo-tmp
	"typeattributeset bar-tmp (baz-tmp)",
	"typeattributeset resource (baz-tmp)",
	"type baz",
	"roletype system_r baz",
	"typeattributeset bar (baz)",
	"typeattributeset domain (baz)",
	"(typeattribute nest_parent-nest_resource)",
	"(type nest_child-nest_resource)",
	"(call nest_child-nest_resource-call (nest_child-nest_resource nest_child))",
	"(call nest_parent-nest_resource-call (nest_parent-nest_resource nest_parent))",
	"(allow nest_parent nest_parent-nest_resource (file (write)))",
	"(filecon \"/some/path/to/file\" file (system_u object_r nest_child-nest_resource ((s0) (s0))))",
	"(allow nest_child nest_child-nest_resource (file (ioctl)))",
	"(allow nest_child nest_child-nest_resource (dir (remove_name)))",
	"(type diamond3-tmp)",
	"(typeattributeset diamond1-tmp (diamond3-tmp))",
	"(typeattributeset diamond2-tmp (diamond3-tmp))",
	"call foo-tmp-not_an_associated_call (foo-tmp nest_child))",
	"type foo_userdomain-user_tmp",
	"call foo_userdomain-user_tmp-associated_call_from_user_tmp (foo_userdomain-user_tmp foo_userdomain)",
    ],
    &["(allow nest_parent nest_resource (file (write)))"],
    0,
);
}

#[test]
fn direct_association_reference_test() {
    valid_policy_test(
        "direct_association_reference.cas",
        &["foo-associated"],
        &["this.associated", "foo.associated", "this-associated"],
        0,
    );
}

#[test]
fn automatic_derivation_test() {
    valid_policy_test("automatic_derive.cas",

    &["(macro child-read ((type this) (type source)) (allow source this (dir (read))) (allow source this (file (read))))",
    "(macro child-setattr ((type this) (type source)) (allow source this (lnk_file (write))))",
    "(macro child-write ((type this) (type source)) (call child-setattr (this source)))",
], &[], 0);
}

// Post 0.1, we'll mark these as optional
#[test]
fn nonexistent_optional_test() {
    valid_policy_test(
        "nonexistent_optional.cas",
        &[],
        &["doesnt_exist", "not_here"],
        2,
    );
}

#[test]
fn nested_conflict_test() {
    valid_policy_test(
    "nested_conflict.cas",
    &["(macro name-conflict_func ((type source)) (allow source self (capability (sys_admin))))",
    ],
    &["(type name)"],
    0
    );
}

#[test]
fn invalid_inherit_associated_call() {
    error_policy_test!("bad_inherits_associated_call.cas", 2, ErrorItem::Compile(_));
}

#[test]
fn invalid_inherit_ancestor_associated_call() {
    error_policy_test!(
        "bad_inherits_ancestor_associated_call.cas",
        1,
        ErrorItem::Compile(_)
    );
}

#[test]
fn invalid_duplicate_inherit() {
    error_policy_test!("duplicate_inherit.cas", 2, ErrorItem::Compile(_));
}

#[test]
fn valid_duplicate_inherit() {
    valid_policy_test(
        "duplicate_inherit.cas",
        &[
            "typeattributeset bar (qux)",
            "typeattributeset baz (qux)",
            "typeattributeset foo (bar)",
            "typeattributeset foo (baz)",
        ],
        &[],
        0,
    );
}

#[test]
fn invalid_self_inherit() {
    error_policy_test!("self_inherit.cas", 2, ErrorItem::Compile(_));
}

#[test]
fn invalid_self_subject() {
    error_policy_test!("self_subject.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn invalid_self_function() {
    error_policy_test!("self_function.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn valid_self() {
    valid_policy_test("self.cas", &["allow qux self (file (read))"], &[], 0);
}

#[test]
fn valid_fs_context() {
    valid_policy_test(
        "fs_context.cas",
        &[
            "fsuse xattr ext3 (system_u object_r foo ((s0) (s0)))",
            "fsuse task sockfs (system_u object_r foo ((s0) (s0)))",
            "fsuse trans tmpfs (system_u object_r foo ((s0) (s0)))",
            "genfscon proc \"/\" (system_u object_r foo ((s0) (s0)))",
            // TODO re-add when secilc check is in place
            // "genfscon sysfs \"/zap\" dir (system_u object_r foo ((s0) (s0)))",
            // "genfscon sysfs \"/zap/baa\" file (system_u object_r bar ((s0) (s0)))",
            "genfscon cgroup \"/\" (system_u object_r foo ((s0) (s0)))",
        ],
        &[],
        0,
    );
}

#[test]
fn invalid_fs_context() {
    error_policy_test!("fs_context.cas", 9, ErrorItem::Compile(_));
}

#[test]
fn invalid_fs_context_dup() {
    error_policy_test!("fs_context_dup.cas", 3, ErrorItem::Compile(_));
}

#[test]
fn invalid_resourcetrans() {
    error_policy_test!("resource_trans.cas", 4, ErrorItem::Compile(_));
}

#[test]
fn invalid_named_resourcetrans() {
    error_policy_test!("named_resource_trans.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn invalid_networking_rules() {
    error_policy_test!("networking_rules.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn let_invalid_type() {
    error_policy_test!("let_invalid_type.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn valid_resourcetrans() {
    valid_policy_test(
        "resource_trans.cas",
        &[
            "(typetransition domain bar file foo)",
            "(typetransition domain bar dir foo)",
        ],
        &[],
        0,
    )
}

#[test]
fn valid_named_resourcetrans() {
    valid_policy_test(
        "named_resource_trans.cas",
        &[
            "(typetransition domain bar file \"test.txt\" foo)",
            "(typetransition domain bar dir \"test.txt\" foo)",
            "(call foo-foo_filetrans (foo some_dom bar lnk_file \"test.sh\"))",
        ],
        &[],
        0,
    )
}

#[test]
fn invalid_call_casting() {
    error_policy_test!("call_casting.cas", 6, ErrorItem::Compile(_));
}

#[test]
fn no_arg_function() {
    error_policy_test!("no_arg_function.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn valid_call_casting() {
    valid_policy_test(
        "call_casting.cas",
        &[
            "call bar-read (foo dom)",
            "call bar-foobar (foo dom)",
            "call abc-read (asd asd)",
            "call abc-read (foo asd)",
            "call boo-read_boo_tmp (jkl jkl)",
            "macro xyz-read ((type this) (type source)) (call abc-read (abc source))",
        ],
        &["call foo-read (foo dom)", "call foo-read (bar dom)"],
        0,
    );
}

#[test]
fn invalid_function_recursion_test() {
    error_policy_test!("functions_recursion.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn invalid_function_noterm_test() {
    error_policy_test!("functions_no_term.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn duplicate_association_test() {
    // The nested and non-nested cases happen at different stages of compilation now, so these
    // need to be two separate tests to check both errors
    error_policy_test!("duplicate_association.cas", 1, ErrorItem::Compile(_));
    error_policy_test!("duplicate_association_nested.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn function_arg_count_test() {
    error_policy_test!("functions_arg_count.cas", 3, ErrorItem::Compile(_));
}

#[test]
fn initial_context_error_test() {
    error_policy_test!("initial_context.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn validation_fails_in_list_test() {
    error_policy_test!("class_wrong.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn derive_no_derive_test() {
    error_policy_test!("derive_noderive.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn duplicate_alias_test() {
    error_policy_test!("duplicate_alias.cas", 1, ErrorItem::Compile(_));
}

#[test]
fn valid_nested_alias() {
    valid_policy_test(
        "nested_alias.cas",
        &[
            "(typealias zap)",
            "(typealiasactual zap bar-tmp)",
            "(typealias bob)",
            "(typealiasactual bob abc-xyz)",
            "(allow abc bob (file (read)))",
            "(allow bar bob (file (read)))",
            "(allow abc zap (file (read)))",
        ],
        &[],
        0,
    );
}

#[test]
fn invalid_default_test() {
    let policy_files = vec![
        [ERROR_POLICIES_DIR, "invalid_default1.cas"].concat(),
        [ERROR_POLICIES_DIR, "invalid_default2.cas"].concat(),
    ];
    let policy_files = policy_files.iter().map(|s| s as &str).collect();
    match compile_combined(policy_files) {
        Ok(_) => panic!("Invalid default compiled successfully"),
        Err(mut e) => {
            let error = e.next().unwrap();
            // A bug putting this at the call site instead of the declaration site, could
            // wrongly put this in file 2
            assert!(matches!(error,
            ErrorItem::Compile(CompileError {
                files,
                    diagnostic: Diag {
                    inner: Diagnostic {
                        labels: lbls,
                        ..
                    }
                    },
                    ..
                }) if files.get(lbls[0].file_id).unwrap().name() == "data/error_policies/invalid_default1.cas"
            ));
        }
    }
}

#[test]
fn error_in_associate_test() {
    // It's important that there be only 1 error and that it actually point at a code point
    error_policy_test!("error_in_associate.cas", 1, ErrorItem::Compile(CompileError {
    diagnostic: Diag {
	inner: Diagnostic {
	    message: msg,
	    ..
	}
    },
    ..
}) if msg.contains("file_context"));
}

#[test]
fn alias_name_conflict_test() {
    error_policy_test!("alias_conflict.cas", 1, ErrorItem::Compile(_));
}
