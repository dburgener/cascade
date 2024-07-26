// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
#![allow(clippy::manual_flatten)]
#![allow(clippy::new_without_default)]
use selinux_cascade::error::{CascadeErrors, ErrorItem};
use selinux_cascade::{compile_combined, compile_machine_policies, compile_machine_policies_all};

mod args;
mod package;
use args::{Args, ColorArg};
use package::build_package;

use clap::Parser;
use is_terminal::IsTerminal;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, ErrorKind, Write};
use termcolor::ColorChoice;
use walkdir::WalkDir;

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
            eprintln!("{e}");
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

    // termcolor doesn't handle automatic terminal detection
    // https://docs.rs/termcolor/latest/termcolor/#detecting-presence-of-a-terminal
    let color = match args.color {
        Some(ColorArg::Always) => ColorChoice::Always,
        Some(ColorArg::Auto) | None => {
            if std::io::stderr().is_terminal() {
                ColorChoice::Auto
            } else {
                ColorChoice::Never
            }
        }
        Some(ColorArg::Never) => ColorChoice::Never,
    };

    // If no machine names are given, output a single CIL file containing all of the policies,
    // with the default out file name (out.cil) if an out file name isn't specified.
    // Else, if the machine name given is "all", build all of the machines.
    // This assumes that "all" is a reserved keyword, so a machine cannot be declared with the name "all".
    // Otherwise, output an individual CIL files for each of the machine names given.
    // In both of the previous two cases, the name of each output CIL file is the name of the machine + .cil.
    let result = if args.machine_names.is_empty() {
        let res = compile_combined(policies.iter().map(|s| s as &str).collect());
        match res {
            Err(e) => Err(e),
            Ok(policy) => {
                let mut hm = HashMap::new();
                let mut out_filename = args.out_filename;
                out_filename.truncate(out_filename.len() - 4);
                hm.insert(out_filename, policy);
                Ok(hm)
            }
        }
    } else if args.machine_names.contains(&"all".to_string()) {
        compile_machine_policies_all(policies.iter().map(|s| s as &str).collect())
    } else {
        compile_machine_policies(
            policies.iter().map(|s| s as &str).collect(),
            args.machine_names,
        )
    };
    match result {
        Err(error_list) => print_error(error_list, color),
        Ok(machine_hashmap) => {
            for (machine_name, (machine_cil, warnings)) in machine_hashmap.iter() {
                let out_filename = machine_name.to_owned() + ".cil";
                let mut out_file = File::create(&out_filename)?;
                out_file.write_all(machine_cil.as_bytes())?;
                if args.package {
                    build_package(machine_name, &out_filename, "32")?;
                }
                warnings.print_warnings(color);
            }
            Ok(())
        }
    }
}

fn print_error(error_list: CascadeErrors, color: ColorChoice) -> std::io::Result<()> {
    for e in error_list {
        if let ErrorItem::Parse(p) = e {
            p.print_diagnostic(color);
        } else if let ErrorItem::Compile(c) = e {
            c.print_diagnostic(color);
        } else {
            eprintln!("{e}");
        }
    }
    Err(Error::new(ErrorKind::InvalidData, "Invalid policy"))
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
