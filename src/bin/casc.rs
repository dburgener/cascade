// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use selinux_cascade::compile_system_policy;
use selinux_cascade::error::ErrorItem;

use clap::Parser;
use std::fs::File;
use std::io::{Error, ErrorKind, Write};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[clap(author, version, name = "casc", about)]
struct Args {
    /// List of input files to process.  Directories are searched recursively.
    #[clap(required(true))]
    input_file: Vec<String>,
    #[clap(default_value = "out.cil", short)]
    out_filename: String,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let policies: Vec<String> = match get_policy_files(args.input_file) {
        Ok(mut s) => {
            // Always treat files in the same order for determinism in compilation
            // sort_unstable() does not preserve equality, which is fine because two
            // different files cannot have the same relative path
            s.sort_unstable();
            s
        }
        Err(e) => {
            eprintln!("{}", e);
            return Err(e);
        }
    };
    if policies.is_empty() {
        // Files supplied on command line, but no .cas files found
        return Err(Error::new(
            ErrorKind::InvalidData,
            "No policy source files found",
        ));
    }
    let mut out_file = File::create(args.out_filename)?;
    let res = compile_system_policy(policies.iter().map(|s| s as &str).collect());
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

// Create a list of policy files
fn get_policy_files(filenames: Vec<String>) -> Result<Vec<String>, Error> {
    let mut policy_files = Vec::new();
    for file in filenames {
        for entry in WalkDir::new(file) {
            let entry = entry?;
            if entry.file_type().is_file() && entry.path().extension().unwrap_or_default() == "cas"
            {
                let filename = entry.path().display().to_string();
                policy_files.push(filename);
            }
        }
    }
    Ok(policy_files)
}
