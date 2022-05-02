// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use selinux_cascade::compile_system_policy;
use selinux_cascade::error::ErrorItem;

use clap::Parser;
use std::fs::File;
use std::io::{Error, ErrorKind, Write};

#[derive(Parser, Debug)]
#[clap(author, version, name = "casc")]
struct Args {
    #[clap(required(true))]
    input_file: Vec<String>,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let policies: Vec<&str> = args.input_file.iter().map(|s| s as &str).collect();
    let mut out_file = File::create("out.cil")?;
    let res = compile_system_policy(policies);
    match res {
        Err(error_list) => {
            for e in error_list {
                if let ErrorItem::Parse(p) = e {
                    p.print_diagnostic();
                } else if let ErrorItem::Compile(c) = e {
                    c.print_diagnostic();
                } else {
                    eprintln!("{}", e);
                }
            }
            Err(Error::new(ErrorKind::InvalidData, "Invalid policy"))
        }
        Ok(s) => out_file.write_all(s.as_bytes()),
    }
}
