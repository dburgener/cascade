#[macro_use]
extern crate lalrpop_util;

mod ast;
mod compile;
mod functions;

use std::fs::{File};
use std::error::Error;
use std::io::{Error as IOError, Read, Write};
use std::fmt;

lalrpop_mod!(pub parser);

#[derive(Clone, Debug)]
struct HLLCompileError {}

impl fmt::Display for HLLCompileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TODO")
    }
}

impl Error for HLLCompileError {}

// TODO: Should use a more specific error type
pub fn compile_system_policy(input_files: Vec<&mut File>, out_file: &mut File) -> Result<(), Box<dyn Error>> {
    let mut policies: Vec<Box<ast::Policy>> = Vec::new();
    for f in input_files {
        let mut policy_str = String::new();
        f.read_to_string(&mut policy_str)?;
        let p = parse_policy(&policy_str);
        let p = match p {
            Ok(p) => p,
            Err(_) => { println!("TODO: Handle parse errors cleanly");
                return Err(Box::new(HLLCompileError {}));
            }
        };

        policies.push(p);
    }

    // TODO: Combine multiple files
    let cil_tree = compile::compile(&*policies[0])?;

    // TODO: It would be so wonderful if we could guarantee that this can't fail.  Is that
    // possible?
    let out_str = generate_cil(cil_tree);

    write_out_cil(out_file, out_str)?;

    return Ok(());
}

fn parse_policy<'a>(policy: &'a str) -> Result<Box<ast::Policy>, lalrpop_util::ParseError<usize, lalrpop_util::lexer::Token<'a>, &'static str>> {
    // TODO: Probably should only construct once
    // Why though?
    return parser::PolicyParser::new().parse(policy);
}

fn generate_cil(s: sexp::Sexp) -> String{
    return s.to_string();
}

fn write_out_cil(f: &mut File, s: String) -> Result<(), IOError> {
    f.write_all(s.as_bytes())?;
    return Ok(());
}

#[cfg(test)]
mod tests {
    lalrpop_mod!(pub parser);

    use std::fs;

    const POLICIES_DIR: &str = "data/policies/";

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

}
