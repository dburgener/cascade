// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
#![allow(clippy::manual_flatten)]
#![allow(clippy::new_without_default)]
#[macro_use]
extern crate lalrpop_util;

extern crate thiserror;

mod alias_map;
mod ast;
mod compile;
mod constants;
mod context;
mod dbus;
pub mod error;
mod functions;
mod internal_rep;
mod machine;
mod obj_class;
mod sexp_internal;
mod util;
pub mod warning;

#[cfg(test)]
mod test;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::ast::{Argument, CascadeString, Declaration, Expression, Policy, PolicyFile};
use crate::context::{BlockType, Context};
use crate::error::{CascadeErrors, InternalError, InvalidMachineError, ParseErrorMsg};
use crate::functions::{FunctionClass, FunctionMap};
use crate::internal_rep::InsertExtendTiming;
use crate::machine::{MachineMap, ModuleMap, ValidatedMachine, ValidatedModule};
use crate::util::append_set_map;
pub use crate::warning::Warnings;

use codespan_reporting::files::SimpleFile;
use lalrpop_util::ParseError as LalrpopParseError;

#[cfg(test)]
use error::ErrorItem;

lalrpop_mod!(#[allow(clippy::all)] pub parser);

/// Compile all machines into a single policy
///
/// The list of input files should contain filenames of files containing policy to be
/// compiled.
/// Returns a Result containing either a string of CIL policy which is the compiled result or a
/// list of errors.
/// In order to convert the compiled CIL policy into a usable policy, you must use secilc.
pub fn compile_combined(
    input_files: Vec<&str>,
) -> Result<(String, Warnings), error::CascadeErrors> {
    let errors = CascadeErrors::new();
    let policies = get_policies(input_files)?;
    let mut res = compile_machine_policies_internal(policies, vec!["out".to_string()], true)?;
    let ret = match res.remove("out") {
        Some(s) => s,
        None => return Err(CascadeErrors::from(InternalError::new())),
    };
    errors.into_result(ret)
}

/// Compile a complete machine policy
///
/// The list of input files should contain filenames of files containing policy to be
/// compiled.
/// The list of machine names are the names of the machines to build.
/// Returns a Result containing either a string of CIL policy which is the compiled result or a
/// list of errors.
/// In order to convert the compiled CIL policy into a usable policy, you must use secilc.
pub fn compile_machine_policies(
    input_files: Vec<&str>,
    machine_names: Vec<String>,
) -> Result<HashMap<String, (String, Warnings)>, error::CascadeErrors> {
    let policies = get_policies(input_files)?;
    compile_machine_policies_internal(policies, machine_names, false)
}

/// Compile all of the machine policies
///
/// The list of input files should contain filenames of files containing policy to be
/// compiled.
/// Returns a Result containing either a string of CIL policy which is the compiled result or a
/// list of errors.
/// In order to convert the compiled CIL policy into a usable policy, you must use secilc.
pub fn compile_machine_policies_all(
    input_files: Vec<&str>,
) -> Result<HashMap<String, (String, Warnings)>, error::CascadeErrors> {
    let mut machine_names = Vec::new();
    let policies = get_policies(input_files)?;
    for p in &policies {
        for e in &p.policy.exprs {
            if let Expression::Decl(Declaration::Machine(s)) = e {
                machine_names.push(s.name.to_string());
            }
        }
    }
    compile_machine_policies_internal(policies, machine_names, false)
}

/// Generate a dbus_contexts file
///
/// In the long term, this needs to take information about the policy to use in the generation
/// For now, all we generate is an xml template
pub fn generate_dbus_contexts() -> Result<String, error::CascadeErrors> {
    Ok(dbus::make_dbus_contexts()?)
}

/// Generate an seusers file
pub fn generate_seusers() -> String {
    "__default__:system_u".to_string()
}

fn compile_machine_policies_internal(
    mut policies: Vec<PolicyFile>,
    machine_names: Vec<String>,
    create_default_machine: bool,
) -> Result<HashMap<String, (String, Warnings)>, error::CascadeErrors> {
    let mut errors = CascadeErrors::new();
    // This will need to be mutable as we add more warnings
    #[allow(unused_mut)]
    let mut warnings = Warnings::new();

    // Generic initialization
    let classlist = obj_class::make_classlist();
    let mut type_map = compile::get_built_in_types_map()?;
    let mut module_map = ModuleMap::new();
    let mut machine_map = MachineMap::new();
    let mut extend_annotations = BTreeMap::new();

    {
        // Collect all type declarations
        for p in &policies {
            match compile::extend_type_map(p, &mut type_map) {
                Ok(anns) => append_set_map(&mut extend_annotations, &mut anns.inner(&mut warnings)),
                Err(e) => {
                    errors.append(e);
                    continue;
                }
            }
        }

        compile::insert_extend_annotations(
            &mut type_map,
            &extend_annotations,
            InsertExtendTiming::Early,
        );

        // Stops if something went wrong for this major step.
        errors = errors.into_result_self()?;
    }

    // Generate type aliases
    let (t_aliases, alias_files) = compile::collect_aliases(type_map.iter())?;
    type_map.validate_aliases(&t_aliases, &alias_files)?;
    type_map.set_aliases(t_aliases);

    for p in &policies {
        match compile::verify_extends(p, &type_map) {
            Ok(()) => (),
            Err(e) => errors.append(e),
        }
    }

    errors = errors.into_result_self()?;

    // Applies annotations
    {
        let mut tmp_func_map = FunctionMap::new();

        // Collect all function declarations
        for p in &policies {
            let mut m = match compile::build_func_map(
                &p.policy.exprs,
                &type_map,
                &classlist,
                FunctionClass::Global,
                &p.file,
            ) {
                Ok(m) => m,
                Err(e) => {
                    errors.append(e);
                    continue;
                }
            };
            tmp_func_map.append(&mut m);
        }

        // TODO: Validate original functions before adding synthetic ones to avoid confusing errors for users.
        match compile::apply_associate_annotations(&type_map, &extend_annotations) {
            Ok(exprs) => {
                let pf = PolicyFile::new(
                    Policy::new(exprs),
                    SimpleFile::new(String::new(), String::new()),
                );
                match compile::extend_type_map(&pf, &mut type_map) {
                    Ok(anns) => {
                        append_set_map(&mut extend_annotations, &mut anns.inner(&mut warnings));
                        policies.push(pf);
                    }
                    Err(e) => errors.append(e),
                }
            }
            Err(e) => errors.append(e),
        }
        compile::insert_extend_annotations(
            &mut type_map,
            &extend_annotations,
            InsertExtendTiming::Late,
        );
    }
    // Stops if something went wrong for this major step.
    errors = errors.into_result_self()?;

    // It would be really nice to do this earlier, but we can't maintain immutable references into
    // the type_map across the mutable reference in extend_type_map().  I *think* it's okay to do
    // it this late, but if we end up needing the global context in build_func_map() or
    // extend_type_map(), we'll need to decouple the type_map references
    let mut contexts = Vec::new();
    for p in &policies {
        match compile::get_global_bindings(p, &type_map, &classlist, &p.file) {
            Ok(c) => contexts.push(c),
            Err(e) => {
                errors.append(e);
                continue;
            }
        }
    }

    let mut global_context = Context::new(BlockType::Global, None, None);
    for mut c in contexts {
        global_context.drain_symbols(&mut c);
    }

    errors = errors.into_result_self()?;

    // Validate modules
    compile::validate_modules(&policies, &type_map, &mut module_map)?;

    // Generate module aliases
    let (m_aliases, alias_files) = compile::collect_aliases(module_map.iter())?;
    module_map.validate_aliases(&m_aliases, &alias_files)?;
    module_map.set_aliases(m_aliases);

    // Validate machines
    compile::validate_machines(&policies, &module_map, &mut machine_map)?;

    // Create a default module and default machine
    // Insert the default module into the default machine and insert the machine into the machine map
    let mut default_module: ValidatedModule;
    let arg;
    if create_default_machine {
        default_module = match ValidatedModule::new(
            CascadeString::from("module"),
            BTreeSet::new(),
            BTreeSet::new(),
            None,
            None,
        ) {
            Ok(m) => m,
            Err(_) => {
                return Err(CascadeErrors::from(InternalError::new()));
            }
        };
        arg = Argument::Var(CascadeString::from("allow"));
        for type_info in type_map.values() {
            default_module.types.insert(type_info);
        }
        let mut configs = BTreeMap::new();
        configs.insert(constants::HANDLE_UNKNOWN_PERMS.to_string(), &arg);
        let mut default_machine = ValidatedMachine::new(
            CascadeString::from(machine_names.first().unwrap().clone()),
            BTreeSet::new(),
            configs,
            None,
        );
        default_machine.modules.insert(&default_module);
        machine_map.insert(default_machine.name.to_string(), default_machine)?;
    }

    let mut machine_hashmap = HashMap::new();
    for machine_name in machine_names {
        let mut machine_warnings = warnings.clone();
        match machine_map.get(&machine_name) {
            Some(machine) => {
                let machine_cil_tree = compile::get_reduced_infos(
                    &policies,
                    &classlist,
                    machine,
                    &type_map,
                    &module_map,
                    &global_context,
                )?
                .inner(&mut machine_warnings);

                let machine_cil = generate_cil(machine_cil_tree);

                machine_hashmap.insert(machine_name, (machine_cil, machine_warnings));
            }
            None => errors.append(CascadeErrors::from(InvalidMachineError::new(&format!(
                "Machine {} does not exist.\nThe valid machines are {}",
                machine_name,
                machine_map
                    .values()
                    .map(|s| s.name.as_ref())
                    .collect::<Vec<&str>>()
                    .join(", ")
            )))),
        }
    }
    errors.into_result(machine_hashmap)
}

fn get_policies(input_files: Vec<&str>) -> Result<Vec<PolicyFile>, CascadeErrors> {
    let mut errors = CascadeErrors::new();
    let mut policies: Vec<PolicyFile> = Vec::new();
    let parser = parser::PolicyParser::new();
    for f in input_files {
        let policy_str = match std::fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) => {
                errors.add_error(e);
                continue;
            }
        };
        let p = match parse_policy(&parser, &policy_str) {
            Ok(p) => p,
            Err(evec) => {
                for e in evec {
                    // TODO: avoid String duplication
                    errors.add_error(error::ParseError::new(e, f.into(), policy_str.clone()));
                }
                continue;
            }
        };
        policies.push(PolicyFile::new(*p, SimpleFile::new(f.into(), policy_str)));
    }
    errors.into_result(policies)
}

fn parse_policy<'a>(
    parser: &parser::PolicyParser,
    policy: &'a str,
) -> Result<Box<Policy>, Vec<LalrpopParseError<usize, lalrpop_util::lexer::Token<'a>, ParseErrorMsg>>>
{
    let mut errors = Vec::new();
    let parse_res = parser.parse(&mut errors, policy);
    // errors is a vec of ErrorRecovery.  ErrorRecovery is a struct wrapping a ParseError
    // and a sequence of discarded characters.  We don't need those characters, so we just
    // remove the wrapping.
    let mut parse_errors: Vec<LalrpopParseError<usize, lalrpop_util::lexer::Token, ParseErrorMsg>> =
        errors.iter().map(|e| e.error.clone()).collect();
    match parse_res {
        Ok(p) => {
            if !errors.is_empty() {
                Err(parse_errors)
            } else {
                Ok(p)
            }
        }
        Err(e) => {
            parse_errors.push(e);
            Err(parse_errors)
        }
    }
}

fn generate_cil(v: Vec<sexp::Sexp>) -> String {
    v.iter()
        .map(sexp_internal::display_cil)
        .collect::<Vec<String>>()
        .join("\n")
}
