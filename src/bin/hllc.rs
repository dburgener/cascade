use selinuxhll::compile_system_policy;
use selinuxhll::error::HLLErrorItem;

use std::env;
use std::fs::File;
use std::io::{Error, ErrorKind, Write};

fn usage() {
    println!("hllc policy.hll");
}

fn main() -> std::io::Result<()> {
    // TODO: Move all this to a parse args function
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        usage();
        return Err(Error::new(ErrorKind::InvalidInput, "Missing policy file"));
    }

    let policies: Vec<&str> = vec![&args[1]];
    let mut out_file = File::create("out.cil")?;
    let res = compile_system_policy(policies);
    match res {
        Err(error_list) => {
            for e in error_list {
                if let HLLErrorItem::Parse(p) = e {
                    p.print_diagnostic();
                } else {
                    eprintln!("{}", e);
                }
            }
        }
        Ok(s) => out_file.write_all(s.as_bytes())?,
    }

    Ok(())
}
