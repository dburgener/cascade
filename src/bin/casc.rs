// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use selinux_cascade::compile_system_policy;
use selinux_cascade::error::HLLErrorItem;

use clap::{crate_authors, crate_version, App, Arg};
use std::fs::File;
use std::io::{Error, ErrorKind, Write};

fn main() -> std::io::Result<()> {
    let matches = App::new("casc")
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .arg(
            Arg::with_name("INPUT_FILE")
                .help("Cascade policy files to parse")
                .required(true)
                .multiple(true),
        )
        .get_matches();

    let policies: Vec<&str> = matches.values_of("INPUT_FILE").unwrap().collect();
    let mut out_file = File::create("out.cil")?;
    let res = compile_system_policy(policies);
    match res {
        Err(error_list) => {
            for e in error_list {
                if let HLLErrorItem::Parse(p) = e {
                    p.print_diagnostic();
                } else if let HLLErrorItem::Compile(c) = e {
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
