use SELinuxhll::compile_system_policy;

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::process::exit;

fn usage() {
    println!("hllc policy.hll");
}

fn main() -> std::io::Result<()> {
    // TODO: Move all this to a parse args function
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        usage();
        exit(1);
    }

    let mut policies: Vec<&mut File> = Vec::new();
    let mut in_file = File::open(&args[1])?;
    policies.push(&mut in_file);

    let mut out_file = File::create("out.cil")?;
    compile_system_policy(policies, &mut out_file);

    return Ok(());
}
