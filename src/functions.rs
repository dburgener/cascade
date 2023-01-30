// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use sexp::{atom_s, list, Atom, Sexp};

use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use codespan_reporting::files::SimpleFile;

use crate::alias_map::{AliasMap, Declared};
use crate::ast::{
    get_cil_name, Annotation, Argument, BuiltIns, CascadeString, DeclaredArgument, FuncCall,
    FuncDecl, IpAddr, Port, Statement,
};
use crate::constants;
use crate::context::Context as BlockContext;
use crate::error::{CascadeErrors, CompileError, ErrorItem, InternalError};
use crate::internal_rep::{
    convert_class_name_if_this, type_name_from_string, typeinfo_from_string, Annotated,
    AnnotationInfo, BoundTypeInfo, ClassList, Context, TypeInfo, TypeInstance, TypeMap, TypeValue,
};
use crate::obj_class::perm_list_to_sexp;

pub fn argument_to_typeinfo<'a>(
    a: &ArgForValidation<'_>,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'a>,
    file: Option<&SimpleFile<String, String>>,
) -> Result<&'a TypeInfo, ErrorItem> {
    let t: Option<&TypeInfo> = match a {
        ArgForValidation::Var(s) => match context.symbol_in_context(s.as_ref()) {
            Some(res) => Some(res),
            // In annotations, we want to treat arguments as strings and the annotation is
            // responsible for understanding what they refer to.  This allows annotations to work
            // across namespaces
            None => typeinfo_from_string(
                s.as_ref(),
                context.in_annotation(),
                types,
                class_perms,
                context,
            ),
        },
        ArgForValidation::Quote(s) => types.get(&type_name_from_string(s.as_ref())),
        ArgForValidation::Port(_) => types.get(constants::NUMBER),
        ArgForValidation::IpAddr(_) => types.get(constants::IPADDR),
        ArgForValidation::List(_) => None,
    };

    t.ok_or_else(|| {
        ErrorItem::make_compile_or_internal_error("Not a valid type", file, a.get_range(), "")
    })
}

pub fn argument_to_typeinfo_vec<'a>(
    arg: &[&CascadeString],
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'a>,
    file: Option<&SimpleFile<String, String>>,
) -> Result<Vec<&'a TypeInfo>, ErrorItem> {
    let mut ret = Vec::new();
    for s in arg {
        ret.push(argument_to_typeinfo(
            &ArgForValidation::Var(s),
            types,
            class_perms,
            context,
            file,
        )?);
    }
    Ok(ret)
}

fn rename_cow<'a>(
    cow_str: &CascadeString,
    renames: &BTreeMap<String, String>,
) -> Cow<'a, CascadeString> {
    Cow::Owned(CascadeString::from(
        renames
            .get::<str>(cow_str.as_ref())
            .unwrap_or(&cow_str.to_string())
            .clone(),
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AvRuleFlavor {
    Allow,
    Dontaudit,
    Auditallow,
    Neverallow,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AvRule<'a> {
    pub av_rule_flavor: AvRuleFlavor,
    pub source: Cow<'a, CascadeString>,
    pub target: Cow<'a, CascadeString>,
    pub class: Cow<'a, CascadeString>,
    // Lifetimes get weird once permissions get expanded, so AV rules should just own their permissions
    pub perms: Vec<CascadeString>,
}

impl AvRule<'_> {
    fn get_renamed_statement(&self, renames: &BTreeMap<String, String>) -> Self {
        AvRule {
            av_rule_flavor: self.av_rule_flavor,
            source: rename_cow(&self.source, renames),
            target: rename_cow(&self.target, renames),
            class: rename_cow(&self.class, renames),
            perms: self
                .perms
                .iter()
                .map(|p| {
                    CascadeString::from(
                        renames
                            .get(&p.to_string())
                            .unwrap_or(&p.to_string())
                            .clone(),
                    )
                })
                .collect(),
        }
    }
}

impl From<&AvRule<'_>> for sexp::Sexp {
    fn from(rule: &AvRule) -> sexp::Sexp {
        let mut ret = Vec::new();

        ret.push(match rule.av_rule_flavor {
            AvRuleFlavor::Allow => Sexp::Atom(Atom::S(constants::ALLOW_FUNCTION_NAME.to_string())),
            AvRuleFlavor::Dontaudit => {
                Sexp::Atom(Atom::S(constants::DONTAUDIT_FUNCTION_NAME.to_string()))
            }
            AvRuleFlavor::Auditallow => {
                Sexp::Atom(Atom::S(constants::AUDITALLOW_FUNCTION_NAME.to_string()))
            }
            AvRuleFlavor::Neverallow => {
                Sexp::Atom(Atom::S(constants::NEVERALLOW_FUNCTION_NAME.to_string()))
            }
        });

        ret.push(atom_s(rule.source.get_cil_name().as_ref()));
        ret.push(atom_s(rule.target.get_cil_name().as_ref()));

        let mut classpermset = vec![Sexp::Atom(Atom::S(rule.class.get_cil_name()))];

        let perms = perm_list_to_sexp(&rule.perms);

        classpermset.push(Sexp::List(perms));

        ret.push(Sexp::List(classpermset));

        Sexp::List(ret)
    }
}

// Returns true if the class is collapsed from a normal and 2 variant
fn is_collapsed_class(class: &str) -> bool {
    ["capability", "process", "cap_userns"].contains(&class)
}

// TODO: This can be converted into a TryFrom for more compile time gaurantees
// Returns a set of AV Rules, because one Cascade allow() call could generate multiple CIL level AV
// rules, for example when intermixing capability and capability2 permissions
fn call_to_av_rule<'a>(
    c: &'a FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'a>,
    file: &'a SimpleFile<String, String>,
) -> Result<BTreeSet<AvRule<'a>>, CascadeErrors> {
    let flavor = match c.name.as_ref() {
        constants::ALLOW_FUNCTION_NAME => AvRuleFlavor::Allow,
        constants::DONTAUDIT_FUNCTION_NAME => AvRuleFlavor::Dontaudit,
        constants::AUDITALLOW_FUNCTION_NAME => AvRuleFlavor::Auditallow,
        constants::NEVERALLOW_FUNCTION_NAME => AvRuleFlavor::Neverallow,
        _ => return Err(ErrorItem::Internal(InternalError::new()).into()),
    };

    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::DOMAIN),
                is_list_param: false,
                name: CascadeString::from("source"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::RESOURCE),
                is_list_param: false,
                name: CascadeString::from("target"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("obj_class"),
                is_list_param: false,
                name: CascadeString::from("class"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("perm"),
                is_list_param: true,
                name: CascadeString::from("class"),
                default: None,
            },
            types,
            None,
        )?,
    ];

    let validated_args =
        validate_arguments(c, &target_args, types, class_perms, context, Some(file))?;
    let mut args_iter = validated_args.iter();

    let source = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let target = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let class = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let perms = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_list(context)?;

    if args_iter.next().is_some() {
        return Err(ErrorItem::Internal(InternalError::new()).into());
    }

    for p in &perms {
        class_perms.verify_permission(&class, p, file)?;
    }

    let perms = class_perms.expand_perm_list(perms.iter().collect());

    let av_rules = if is_collapsed_class(class.as_ref()) {
        let mut split_perms = (Vec::new(), Vec::new());
        if let Some(class_struct) = class_perms.classes.get(class.as_ref()) {
            for p in perms {
                if p == "*" {
                    // '*' is the one special case that matches both
                    split_perms.0.push(p.clone());
                    split_perms.1.push(p);
                } else if class_struct.contains_perm(p.as_ref()) {
                    split_perms.0.push(p);
                } else {
                    split_perms.1.push(p);
                }
            }
            let mut av_rules = Vec::new();
            if !split_perms.0.is_empty() {
                av_rules.push(AvRule {
                    av_rule_flavor: flavor,
                    source: Cow::Owned(source.clone()),
                    target: Cow::Owned(target.clone()),
                    class: Cow::Owned(class),
                    perms: split_perms.0,
                });
            }
            if !split_perms.1.is_empty() {
                av_rules.push(AvRule {
                    av_rule_flavor: flavor,
                    source: Cow::Owned(source),
                    target: Cow::Owned(target),
                    class: Cow::Owned(CascadeString::from(class_struct.collapsed_name.unwrap())),
                    perms: split_perms.1,
                });
            }
            av_rules
        } else {
            return Err(ErrorItem::Internal(InternalError::new()).into());
        }
    } else {
        vec![AvRule {
            av_rule_flavor: flavor,
            source: Cow::Owned(source),
            target: Cow::Owned(target),
            class: Cow::Owned(class),
            perms,
        }]
    };

    Ok(av_rules.into_iter().collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileType {
    File,
    Directory,
    SymLink,
    CharDev,
    BlockDev,
    Socket,
    Pipe,
    Any,
}

// These are the CIL strings for the target CIL
// Valid values are listed here:
// https://github.com/SELinuxProject/selinux/blob/master/secilc/docs/cil_file_labeling_statements.md
impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FileType::File => "file",
                FileType::Directory => "dir",
                FileType::SymLink => "symlink",
                FileType::CharDev => "char",
                FileType::BlockDev => "block",
                FileType::Socket => "socket",
                FileType::Pipe => "pipe",
                FileType::Any => "any",
            }
        )
    }
}

// These are the strings inputted in Cascade
// They also need to pass a check as being a valid object class, or the keyword "any", so they must
// match object class names
// If we want to add more human readable options in the future, we should add them to the object
// classes as well.
impl FromStr for FileType {
    type Err = ();
    fn from_str(s: &str) -> Result<FileType, ()> {
        match s {
            "file" => Ok(FileType::File),
            "dir" => Ok(FileType::Directory),
            "lnk_file" => Ok(FileType::SymLink),
            "chr_file" => Ok(FileType::CharDev),
            "blk_file" => Ok(FileType::BlockDev),
            "sock_file" => Ok(FileType::Socket),
            "fifo_file" => Ok(FileType::Pipe),
            "any" => Ok(FileType::Any),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileContextRule<'a> {
    pub regex_string: String,
    pub file_type: FileType,
    pub context: Context<'a>,
}

impl FileContextRule<'_> {
    fn get_renamed_statement(&self, renames: &BTreeMap<String, String>) -> Self {
        FileContextRule {
            regex_string: self.regex_string.clone(),
            file_type: self.file_type,
            context: self.context.get_renamed_context(renames),
        }
    }
}

impl From<&FileContextRule<'_>> for sexp::Sexp {
    fn from(f: &FileContextRule) -> sexp::Sexp {
        list(&[
            atom_s("filecon"),
            atom_s(&f.regex_string),
            Sexp::Atom(Atom::S(f.file_type.to_string())),
            Sexp::from(&f.context),
        ])
    }
}

fn call_to_fc_rules<'a>(
    c: &'a FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'a>,
    file: &'a SimpleFile<String, String>,
) -> Result<Vec<FileContextRule<'a>>, CascadeErrors> {
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("path"),
                is_list_param: false,
                name: CascadeString::from("path_regex"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("obj_class"), //TODO: not really
                is_list_param: true,
                name: CascadeString::from("file_type"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::RESOURCE),
                is_list_param: false,
                name: CascadeString::from("file_context"),
                default: None,
            },
            types,
            None,
        )?,
    ];

    let validated_args =
        validate_arguments(c, &target_args, types, class_perms, context, Some(file))?;
    let mut args_iter = validated_args.iter();
    let mut ret = Vec::new();

    let regex_string = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?
        .to_string();
    let file_types = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_list(context)?;
    let context_str = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let context = match Context::try_from(context_str.to_string()) {
        Ok(c) => c,
        Err(_) => {
            return Err(CascadeErrors::from(
                ErrorItem::make_compile_or_internal_error(
                    "Invalid context",
                    Some(file),
                    context_str.get_range(),
                    "Cannot parse this into a context",
                ),
            ))
        }
    };

    for file_type in file_types {
        let file_type = match file_type.to_string().parse::<FileType>() {
            Ok(f) => f,
            Err(_) => {
                return Err(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        "Not a valid file type",
                        Some(file),
                        file_type.get_range(),
                        "",
                    ),
                ))
            }
        };

        ret.push(FileContextRule {
            regex_string: regex_string.clone(),
            file_type,
            context: context.clone(),
        });
    }

    Ok(ret)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl From<Protocol> for &str {
    fn from(p: Protocol) -> &'static str {
        match p {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct PortconRule<'a> {
    proto: Protocol,
    port: CascadeString, // TODO: lists and ranges
    context: Context<'a>,
}

impl From<&PortconRule<'_>> for sexp::Sexp {
    fn from(p: &PortconRule) -> sexp::Sexp {
        list(&[
            atom_s("portcon"),
            atom_s(p.proto.into()),
            Sexp::Atom(Atom::S(p.port.to_string())),
            Sexp::from(&p.context),
        ])
    }
}

pub fn call_to_portcon_rule<'a>(
    c: &FuncCall,
    types: &TypeMap,
    class_perms: &ClassList,
    context: &BlockContext,
    file: &SimpleFile<String, String>,
    parent_type: &'a TypeInfo,
) -> Result<PortconRule<'a>, CascadeErrors> {
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("string"),
                is_list_param: false,
                name: CascadeString::from("protocol"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("number"),
                is_list_param: false, // TODO: Need to support lists and ranges
                name: CascadeString::from("port"),
                default: None,
            },
            types,
            None,
        )?,
    ];

    let validated_args =
        validate_arguments(c, &target_args, types, class_perms, context, Some(file))?;
    let mut args_iter = validated_args.iter();

    let proto = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let proto = match proto.as_ref() {
        "\"tcp\"" | "\"TCP\"" => Protocol::Tcp,
        "\"udp\"" | "\"UDP\"" => Protocol::Udp,
        _ => {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Not a valid protocol",
                Some(file),
                proto.get_range(),
                "Valid protocols are \"tcp\" and \"udp\"",
            )
            .into());
        }
    };

    let port = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;

    validate_port(&port, Some(file))?;

    let context = match Context::try_from(parent_type.name.as_ref()) {
        Ok(c) => c,
        Err(()) => {
            return Err(ErrorItem::Internal(InternalError::new()).into());
        }
    };

    Ok(PortconRule {
        proto,
        port,
        context,
    })
}

impl PortconRule<'_> {
    fn get_renamed_statement(&self, renames: &BTreeMap<String, String>) -> Self {
        PortconRule {
            proto: self.proto,
            port: self.port.clone(),
            context: self.context.get_renamed_context(renames),
        }
    }
}

// Recursively validate a port
// First, split on commas, then hyphens
// Each comma separated string is validated separatedly
// Each hyphen separated string must be in the valid port range, and the left side must be lower
// than the right.
// The valid port range is 1 through 65535
fn validate_port(
    port: &CascadeString,
    current_file: Option<&SimpleFile<String, String>>,
) -> Result<(), ErrorItem> {
    for substr in port.as_ref().split(',') {
        if validate_port_helper(substr).is_err() {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Not a valid port",
                current_file,
                port.get_range(),
                "This should be a comma separated list of ports or port ranges",
            ));
        }
    }
    Ok(())
}

fn validate_port_helper(port: &str) -> Result<u16, ()> {
    if port.contains('-') {
        let mut split = port.split('-');
        let first = split.next().ok_or(())?.parse::<u16>().map_err(|_| ())?;
        let second = split.next().ok_or(())?.parse::<u16>().map_err(|_| ())?;
        if split.next().is_some() || second <= first {
            Err(())
        } else {
            Ok(0)
        }
    } else {
        port.parse::<u16>().map_err(|_| ())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FSContextType {
    XAttr,
    Task,
    Trans,
    GenFSCon,
}

impl fmt::Display for FSContextType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FSContextType::XAttr => "xattr",
                FSContextType::Task => "task",
                FSContextType::Trans => "trans",
                FSContextType::GenFSCon => "genfscon",
            }
        )
    }
}

impl FromStr for FSContextType {
    type Err = ();
    fn from_str(s: &str) -> Result<FSContextType, ()> {
        match s {
            "xattr" => Ok(FSContextType::XAttr),
            "task" => Ok(FSContextType::Task),
            "trans" => Ok(FSContextType::Trans),
            "genfscon" => Ok(FSContextType::GenFSCon),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FileSystemContextRule<'a> {
    pub fscontext_type: FSContextType,
    pub fs_name: CascadeString,
    pub path: Option<CascadeString>,
    pub file_type: Option<FileType>,
    //Note: if a file type is not given this will be the range of the function name
    pub file_type_range: Range<usize>,
    pub context: Context<'a>,
    pub context_range: Range<usize>,
    pub file: SimpleFile<String, String>,
}
impl Eq for FileSystemContextRule<'_> {}

impl PartialEq for FileSystemContextRule<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.fscontext_type == other.fscontext_type
            && self.fs_name == other.fs_name
            && self.path == other.path
            && self.file_type == other.file_type
            && self.context == other.context
    }
}

impl PartialOrd for FileSystemContextRule<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FileSystemContextRule<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            &self.fscontext_type,
            &self.fs_name,
            &self.path,
            self.file_type,
            &self.context,
        )
            .cmp(&(
                &other.fscontext_type,
                &other.fs_name,
                &other.path,
                other.file_type,
                &other.context,
            ))
    }
}

impl FileSystemContextRule<'_> {
    fn get_renamed_statement(&self, renames: &BTreeMap<String, String>) -> Self {
        FileSystemContextRule {
            fscontext_type: self.fscontext_type.clone(),
            fs_name: self.fs_name.clone(),
            path: self.path.clone(),
            file_type: self.file_type,
            context: self.context.get_renamed_context(renames),
            file: self.file.clone(),
            file_type_range: self.file_type_range.clone(),
            context_range: self.context_range.clone(),
        }
    }
}

impl TryFrom<&FileSystemContextRule<'_>> for sexp::Sexp {
    type Error = ErrorItem;

    fn try_from(f: &FileSystemContextRule) -> Result<sexp::Sexp, ErrorItem> {
        match f.fscontext_type {
            FSContextType::XAttr | FSContextType::Task | FSContextType::Trans => Ok(list(&[
                atom_s("fsuse"),
                Sexp::Atom(Atom::S(f.fscontext_type.to_string())),
                atom_s(f.fs_name.to_string().trim_matches('"')),
                Sexp::from(&f.context),
            ])),
            FSContextType::GenFSCon => {
                if let Some(p) = &f.path {
                    if let Some(file_type) = &f.file_type {
                        // TODO add secilc check here. Right now our github pipeline
                        // supports an older version of secilc.  So to get things moving forward
                        // we are forcing the old behavior.  The new behavior has been tested locally.
                        // REMEMBER TO UPDATE THE TESTS
                        // if secilc/libsepol version is new enough {
                        if false {
                            return Ok(list(&[
                                atom_s("genfscon"),
                                atom_s(f.fs_name.to_string().trim_matches('"')),
                                atom_s(p.as_ref()),
                                Sexp::Atom(Atom::S(file_type.to_string())),
                                Sexp::from(&f.context),
                            ]));
                        }
                    }
                    // We are purposefully falling through without an else to
                    // reduce redundant lines of code
                    Ok(list(&[
                        atom_s("genfscon"),
                        atom_s(f.fs_name.to_string().trim_matches('"')),
                        atom_s(p.as_ref()),
                        Sexp::from(&f.context),
                    ]))
                } else {
                    // We should never get here since we are defaulting to "/"
                    // when we call this normally but if someone calls this in
                    // an unexpected way we will get this call.
                    Err(ErrorItem::Internal(InternalError::new()))
                }
            }
        }
    }
}

fn call_to_fsc_rules<'a>(
    c: &'a FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'a>,
    file: &'a SimpleFile<String, String>,
) -> Result<Vec<FileSystemContextRule<'a>>, CascadeErrors> {
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::RESOURCE),
                is_list_param: false,
                name: CascadeString::from("fs_label"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("string"),
                is_list_param: false,
                name: CascadeString::from("fs_name"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("fs_type"),
                is_list_param: false,
                name: CascadeString::from("fscontext_type"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("path"),
                is_list_param: false,
                name: CascadeString::from("path_regex"),
                default: Some(Argument::Quote(CascadeString::from("\"/\""))),
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("obj_class"), //TODO: not really
                is_list_param: true,
                name: CascadeString::from("file_type"),
                default: Some(Argument::List(vec![])),
            },
            types,
            None,
        )?,
    ];
    let validated_args =
        validate_arguments(c, &target_args, types, class_perms, context, Some(file))?;
    let mut args_iter = validated_args.iter();
    let mut ret = Vec::new();

    let context_str_arg = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?;
    let context_str = context_str_arg.get_name_or_string(context)?;
    let fs_context = match Context::try_from(context_str.to_string()) {
        Ok(c) => c,
        Err(_) => {
            return Err(CascadeErrors::from(
                ErrorItem::make_compile_or_internal_error(
                    "Invalid context",
                    Some(file),
                    context_str.get_range(),
                    "Cannot parse this into a context",
                ),
            ))
        }
    };

    let fs_name = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let fscontext_str = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let fscontext_type = match fscontext_str.to_string().parse::<FSContextType>() {
        Ok(f) => f,
        Err(_) => {
            return Err(CascadeErrors::from(
                ErrorItem::make_compile_or_internal_error(
                    "Not a valid file system type",
                    Some(file),
                    fscontext_str.get_range(),
                    "File system type must be 'xattr', 'task', 'trans', or 'genfscon'",
                ),
            ));
        }
    };
    let regex_string_arg = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?;
    let regex_string = regex_string_arg.get_name_or_string(context)?;

    let file_types_arg = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?;
    let file_types = file_types_arg.get_list(context)?;

    match fscontext_type {
        FSContextType::XAttr | FSContextType::Task | FSContextType::Trans => {
            // The 'regex_string_arg.get_range().is_none()' is a hacky way to
            // to check if arg was actually provided or not.  Since we set the
            // default for regex_string to "/" this is the only way I could find
            // to test if the actual arg was passed or not
            if regex_string_arg.get_range().is_none() && file_types.is_empty() {
                ret.push(FileSystemContextRule {
                    fscontext_type,
                    fs_name,
                    path: None,
                    file_type: None,
                    // file_type_range shouldn't ever be used for xattr, task, or trans but I would rather not
                    // have to deal with Option stuff later
                    file_type_range: c.get_name_range().unwrap_or_default(),
                    context: fs_context.clone(),
                    context_range: context_str_arg
                        .get_range()
                        .ok_or_else(|| CascadeErrors::from(InternalError::new()))?,
                    file: file.clone(),
                });
            }
            let mut errors = CascadeErrors::new();
            if !file_types.is_empty() {
                errors.append(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        "File types can only be provided for 'genfscon'",
                        Some(file),
                        file_types_arg.get_range(),
                        "",
                    ),
                ));
            }
            if regex_string_arg.get_range().is_some() {
                errors.append(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        "File path can only be provided for 'genfscon'",
                        Some(file),
                        regex_string_arg.get_range(),
                        "",
                    ),
                ));
            }
            if !errors.is_empty() {
                return Err(errors);
            }
        }
        FSContextType::GenFSCon => {
            if file_types.is_empty() {
                ret.push(FileSystemContextRule {
                    fscontext_type,
                    fs_name,
                    path: Some(regex_string),
                    file_type: None,
                    // file_type_range shouldn't need to be used here since file_type is None, but I would rather not
                    // have to deal with Option stuff later
                    file_type_range: c.get_name_range().unwrap_or_default(),
                    context: fs_context.clone(),
                    context_range: context_str_arg
                        .get_range()
                        .ok_or_else(|| CascadeErrors::from(InternalError::new()))?,
                    file: file.clone(),
                });
            } else {
                for file_type in file_types {
                    let file_type = match file_type.to_string().parse::<FileType>() {
                        Ok(f) => f,
                        Err(_) => {
                            return Err(CascadeErrors::from(
                                ErrorItem::make_compile_or_internal_error(
                                    "Not a valid file type",
                                    Some(file),
                                    file_type.get_range(),
                                    "",
                                ),
                            ))
                        }
                    };

                    ret.push(FileSystemContextRule {
                        fscontext_type: fscontext_type.clone(),
                        fs_name: fs_name.clone(),
                        path: Some(regex_string.clone()),
                        file_type: Some(file_type),
                        file_type_range: file_types_arg
                            .get_range()
                            .unwrap_or_else(|| c.get_name_range().unwrap_or_default()),
                        context: fs_context.clone(),
                        context_range: context_str_arg
                            .get_range()
                            .ok_or_else(|| CascadeErrors::from(InternalError::new()))?,
                        file: file.clone(),
                    });
                }
            }
        }
    }

    Ok(ret)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomtransRule<'a> {
    pub source: Cow<'a, CascadeString>,
    pub target: Cow<'a, CascadeString>,
    pub executable: Cow<'a, CascadeString>,
}

impl From<&DomtransRule<'_>> for sexp::Sexp {
    fn from(d: &DomtransRule) -> Self {
        list(&[
            atom_s("typetransition"),
            atom_s(&d.source.get_cil_name()),
            atom_s(&d.executable.get_cil_name()),
            atom_s("process"),
            atom_s(&d.target.get_cil_name()),
        ])
    }
}

impl DomtransRule<'_> {
    fn get_renamed_statement(&self, renames: &BTreeMap<String, String>) -> Self {
        DomtransRule {
            source: rename_cow(&self.source, renames),
            target: rename_cow(&self.target, renames),
            executable: rename_cow(&self.executable, renames),
        }
    }
}

fn call_to_domain_transition<'a>(
    c: &'a FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'a>,
    file: &'a SimpleFile<String, String>,
) -> Result<DomtransRule<'a>, CascadeErrors> {
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::DOMAIN),
                is_list_param: false,
                name: CascadeString::from("source"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::RESOURCE),
                is_list_param: false,
                name: CascadeString::from("executable"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::DOMAIN),
                is_list_param: false,
                name: CascadeString::from("target"),
                default: None,
            },
            types,
            None,
        )?,
    ];

    let validated_args =
        validate_arguments(c, &target_args, types, class_perms, context, Some(file))?;
    let mut args_iter = validated_args.into_iter();

    let source = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let executable = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let target = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;

    if args_iter.next().is_some() {
        return Err(ErrorItem::Internal(InternalError::new()).into());
    }

    Ok(DomtransRule {
        source: Cow::Owned(source),
        target: Cow::Owned(target),
        executable: Cow::Owned(executable),
    })
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourcetransRule<'a> {
    pub default: Cow<'a, CascadeString>,
    pub domain: Cow<'a, CascadeString>,
    pub parent: Cow<'a, CascadeString>,
    pub file_type: FileType,
}

impl ResourcetransRule<'_> {
    fn get_renamed_statement(&self, renames: &BTreeMap<String, String>) -> Self {
        ResourcetransRule {
            default: rename_cow(&self.default, renames),
            domain: rename_cow(&self.domain, renames),
            parent: rename_cow(&self.parent, renames),
            file_type: self.file_type,
        }
    }
}

impl From<&ResourcetransRule<'_>> for sexp::Sexp {
    fn from(r: &ResourcetransRule) -> Self {
        list(&[
            atom_s("typetransition"),
            atom_s(&r.domain.get_cil_name()),
            atom_s(&r.parent.get_cil_name()),
            Sexp::Atom(Atom::S(r.file_type.to_string())),
            atom_s(&r.default.get_cil_name()),
        ])
    }
}

fn call_to_resource_transition<'a>(
    c: &'a FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'a>,
    file: &'a SimpleFile<String, String>,
) -> Result<Vec<ResourcetransRule<'a>>, CascadeErrors> {
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::RESOURCE),
                is_list_param: false,
                name: CascadeString::from("default"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::DOMAIN),
                is_list_param: false,
                name: CascadeString::from("domain"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::RESOURCE),
                is_list_param: false,
                name: CascadeString::from("parent"),
                default: None,
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("obj_class"), //TODO: not really
                is_list_param: true,
                name: CascadeString::from("file_type"),
                default: Some(Argument::List(vec![])),
            },
            types,
            None,
        )?,
    ];

    let validated_args =
        validate_arguments(c, &target_args, types, class_perms, context, Some(file))?;
    let mut args_iter = validated_args.into_iter();
    let mut ret = Vec::new();

    let default = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let domain = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let parent = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let file_types = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_list(context)?;

    if args_iter.next().is_some() {
        return Err(ErrorItem::Internal(InternalError::new()).into());
    }

    for file_type in file_types {
        let file_type = match file_type.to_string().parse::<FileType>() {
            Ok(f) => f,
            Err(_) => {
                return Err(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        "Not a valid file type",
                        Some(file),
                        file_type.get_range(),
                        "",
                    ),
                ))
            }
        };

        ret.push(ResourcetransRule {
            default: Cow::Owned(default.clone()),
            domain: Cow::Owned(domain.clone()),
            parent: Cow::Owned(parent.clone()),
            file_type,
        });
    }

    Ok(ret)
}

fn check_associated_call(
    annotation: &Annotation,
    funcdecl: &FuncDecl,
    file: &SimpleFile<String, String>,
) -> Result<bool, ErrorItem> {
    // Checks that annotation arguments match the expected signature.
    let mut annotation_args = annotation.arguments.iter();

    if let Some(a) = annotation_args.next() {
        return Err(ErrorItem::make_compile_or_internal_error(
            "Superfluous argument",
            Some(file),
            a.get_range(),
            "@associated_call doesn't take argument.",
        ));
    }

    // Checks that annotated functions match the expected signature.
    let mut func_args = funcdecl.args.iter();
    match func_args.next() {
        None => {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Invalid method signature for @associated_call annotation: missing first argument",
                Some(file),
                funcdecl.name.get_range(),
                "Add a 'domain' argument.",
            ))
        }
        Some(DeclaredArgument {
            param_type,
            is_list_param,
            name: _,
            default: _,
        }) => {
            if param_type.as_ref() != constants::DOMAIN || *is_list_param {
                return Err(ErrorItem::make_compile_or_internal_error(
                    "Invalid method signature for @associated_call annotation: invalid first argument",
                    Some(file),
                    param_type.get_range(),
                    "The type of the first method argument must be 'domain'.",
                ));
            }
        }
    }
    if let Some(a) = func_args.next() {
        return Err(ErrorItem::make_compile_or_internal_error(
            "Invalid method signature for @associated_call annotation: too many arguments",
            Some(file),
            a.param_type.get_range(),
            "Only one argument of type 'domain' is accepted.",
        ));
    }

    Ok(true)
}

pub type FunctionMap<'a> = AliasMap<FunctionInfo<'a>>;

#[derive(Debug, Clone)]
pub struct FunctionInfo<'a> {
    pub name: String,
    pub class: Option<&'a TypeInfo>,
    pub is_virtual: bool,
    pub args: Vec<FunctionArgument<'a>>,
    pub annotations: BTreeSet<AnnotationInfo>,
    original_body: &'a [Statement],
    pub body: Option<BTreeSet<ValidatedStatement<'a>>>,
    pub declaration_file: &'a SimpleFile<String, String>,
    pub is_associated_call: bool,
    pub is_derived: bool,
    decl: Option<&'a FuncDecl>,
}

impl Declared for FunctionInfo<'_> {
    fn get_file(&self) -> Option<SimpleFile<String, String>> {
        Some(self.declaration_file.clone())
    }

    fn get_name_range(&self) -> Option<Range<usize>> {
        self.decl.and_then(|d| d.name.get_range())
    }

    fn get_generic_name(&self) -> String {
        String::from("function")
    }
}

impl<'a> FunctionInfo<'a> {
    pub fn new(
        funcdecl: &'a FuncDecl,
        types: &'a TypeMap,
        parent_type: Option<&'a TypeInfo>,
        declaration_file: &'a SimpleFile<String, String>,
    ) -> Result<FunctionInfo<'a>, CascadeErrors> {
        let mut args = Vec::new();
        let mut errors = CascadeErrors::new();
        let mut annotations = BTreeSet::new();

        // All member functions automatically have "this" available as a reference to their type
        let parent_type_name = if let Some(parent_type) = parent_type {
            args.push(FunctionArgument::new_this_argument(parent_type));
            Some(&parent_type.name)
        } else {
            None
        };

        let class_aliases = match parent_type {
            Some(ti) => {
                let mut type_aliases = vec![Some(&ti.name)];
                for ann in &ti.annotations {
                    if let AnnotationInfo::Alias(alias_name) = ann {
                        type_aliases.push(Some(alias_name));
                    }
                }
                type_aliases
            }
            None => vec![None],
        };

        let mut func_aliases = vec![&funcdecl.name];

        for a in &funcdecl.args {
            match FunctionArgument::new(a, types, Some(declaration_file)) {
                Ok(a) => args.push(a),
                Err(e) => errors.add_error(e),
            }
        }

        let mut is_associated_call = false;

        // Only allow a set of specific annotation names and strictly check their arguments.
        // TODO: Add tests to verify these checks.
        for annotation in funcdecl.annotations.annotations.iter() {
            match annotation.name.as_ref() {
                "associated_call" => {
                    // For now, there is only one @associated_call allowed.
                    if is_associated_call {
                        return Err(ErrorItem::make_compile_or_internal_error(
                            "Multiple @associated_call annotations",
                            Some(declaration_file),
                            annotation.name.get_range(),
                            "You need to remove superfluous @associated_call annotation.",
                        )
                        .into());
                    }
                    is_associated_call =
                        check_associated_call(annotation, funcdecl, declaration_file)?;
                    // We're done with these, so no need to save them in the annotations
                }
                "alias" => {
                    for arg in &annotation.arguments {
                        match arg {
                            Argument::Var(s) => {
                                func_aliases.push(s);
                            }
                            _ => {
                                return Err(ErrorItem::make_compile_or_internal_error(
                                    "Invalid alias",
                                    Some(declaration_file),
                                    annotation.name.get_range(),
                                    "Alias name must be a symbol",
                                )
                                .into());
                            }
                        }
                    }
                }
                _ => {
                    return Err(ErrorItem::make_compile_or_internal_error(
                        "Unknown annotation",
                        Some(declaration_file),
                        annotation.name.get_range(),
                        "The only valid annotation is '@associated_call'",
                    )
                    .into());
                }
            }
        }

        // For every function, there may be aliases to the class name or the function name.
        // So if we have a function on class 'foo' named 'read', and 'foo' has an alias 'bar'
        // and the 'read' function in 'foo' has an alias 'list', then we need to output functions
        // named: 'foo-list', 'bar-read' and 'bar-list'.  (The real name, 'foo-read' is outputted
        // by FunctionInfo try_from()).  These functions all call into the real function.
        for class_alias in &class_aliases {
            for func_alias in &func_aliases {
                // No alias for real class and func combo
                if *class_alias == parent_type_name && *func_alias == &funcdecl.name {
                    continue;
                }
                annotations.insert(AnnotationInfo::Alias(
                    get_cil_name(*class_alias, func_alias).into(),
                ));
            }
        }

        errors.into_result(FunctionInfo {
            name: funcdecl.name.to_string(),
            class: parent_type,
            is_virtual: funcdecl.is_virtual,
            args,
            annotations,
            original_body: &funcdecl.body,
            body: None,
            declaration_file,
            is_associated_call,
            is_derived: false,
            decl: Some(funcdecl),
        })
    }

    // Create a derived FunctionInfo from the union of derive_classes
    // derive_classes may be a set of classes to be unioned, or a single class to use
    // All provided classes are to be unioned (the decision to union all vs use a single one was
    // made in the parent)
    pub fn new_derived_function(
        name: &CascadeString,
        deriving_type: &'a TypeInfo,
        derive_classes: &BTreeSet<&CascadeString>,
        functions: &FunctionMap<'a>,
        file: &'a SimpleFile<String, String>,
    ) -> Result<FunctionInfo<'a>, CascadeErrors> {
        let mut first_parent = None;
        let mut derived_body = BTreeSet::new();
        let mut derived_is_associated_call = false;
        let mut derived_arg_names: Vec<BTreeSet<String>> = Vec::new();

        for parent in derive_classes {
            // The parent may or may not have such a function implemented.
            // As long as at least one parent has it, that's fine
            let parent_function = match functions.get(&get_cil_name(Some(parent), name)) {
                Some(f) => f,
                None => continue,
            };

            // All parent functions must have the same prototype.  If this is the first function we
            // are looking at, we save that prototype.  Otherwise, we compare to ensure they are
            // identical
            match first_parent {
                None => {
                    first_parent = Some(parent_function);
                    derived_arg_names = parent_function
                        .args
                        .iter()
                        .map(|a| BTreeSet::from([a.name.to_string()]))
                        .collect();
                    derived_is_associated_call = parent_function.is_associated_call;
                }
                Some(first_parent) => {
                    if parent_function.args != first_parent.args {
                        match (
                            first_parent.get_declaration_range(),
                            parent_function.get_declaration_range(),
                        ) {
                            (Some(first_range), Some(second_range)) => {
                                return Err(CompileError::new(
                                        &format!("In attempting to derive {name}, parent functions do not have matching prototypes."),
                                        first_parent.declaration_file,
                                        first_range,
                                        "This parent prototype...",
                                        ).add_additional_message(
                                            parent_function.declaration_file,
                                            second_range,
                                            "...needs to match this parent prototype").into());
                            }
                            (_, _) => {
                                // TODO: One of the mismatched parent signatures is synthetic.
                                // Output an appropriate error message
                                todo!()
                            }
                        }
                    }
                    if derived_is_associated_call != parent_function.is_associated_call {
                        match (
                            first_parent.get_declaration_range(),
                            parent_function.get_declaration_range(),
                        ) {
                            (Some(first_range), Some(second_range)) => {
                                return Err(CompileError::new(
                                        &format!("In attempting to derive {name}, parent functions do not have matching prototypes."),
                                        first_parent.declaration_file,
                                        first_range,
                                        "This parent is annotated with @associated_call...",
                                        ).add_additional_message(
                                            parent_function.declaration_file,
                                            second_range,
                                            "...but this parent is not").into());
                            }
                            (_, _) => {
                                // TODO: One of the mismatched parent signatures is synthetic.
                                // Output an appropriate error message
                                todo!()
                            }
                        }
                    }

                    for (i, a) in parent_function.args.iter().enumerate() {
                        // Guaranteed to not overflow because:
                        // 1. Derived_arg_names length == first_parent length
                        // 2. parent_function.args == first_parent.args
                        derived_arg_names[i].insert(a.name.to_string());
                    }
                }
            }
        }

        for parent in derive_classes {
            let parent_function = match functions.get(&get_cil_name(Some(parent), name)) {
                Some(f) => f,
                None => continue,
            };

            let mut renames = BTreeMap::new();
            for (i, a) in parent_function.args.iter().enumerate() {
                renames.insert(
                    a.name.clone(),
                    derived_arg_names[i]
                        .iter()
                        .cloned()
                        .collect::<Vec<String>>()
                        .join("_"),
                );
            }

            derived_body.append(
                &mut parent_function
                    .body
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .map(|s| s.get_renamed_statement(&renames))
                    .collect(),
            )
        }

        let mut derived_args = match first_parent {
            Some(parent) => parent.args.clone(),
            None => {
                return Err(ErrorItem::make_compile_or_internal_error(
                    &format!("Unable to derive {name}, because it has no parent implementations"),
                    Some(file),
                    name.get_range(),
                    &format!("Attempted to derive an implementation of {name}, but couldn't find any derivable parent implementations")).into());
                // TODO: A hint about the strategy might be useful
            }
        };

        for (mut arg, name) in derived_args.iter_mut().zip(derived_arg_names.iter()) {
            arg.name = name.iter().cloned().collect::<Vec<String>>().join("_");
        }

        Ok(FunctionInfo {
            name: name.to_string(),
            class: Some(deriving_type),
            is_virtual: false, // TODO: Check documentation for correct behavior here
            args: derived_args,
            annotations: BTreeSet::new(),
            original_body: &[], // Unused after validation
            body: Some(derived_body),
            declaration_file: file,
            is_associated_call: derived_is_associated_call,
            is_derived: true,
            decl: None,
        })
    }

    pub fn get_cil_name(&self) -> String {
        match self.decl {
            Some(decl) => decl.get_cil_name(),
            None => get_cil_name(
                self.class.map(|c| &c.name),
                &CascadeString::from(&self.name as &str),
            ),
        }
    }

    pub fn validate_body(
        &mut self,
        functions: &'a FunctionMap<'a>,
        types: &'a TypeMap,
        class_perms: &'a ClassList,
        file: &'a SimpleFile<String, String>,
    ) -> Result<(), CascadeErrors> {
        let mut new_body = BTreeSet::new();
        let mut errors = CascadeErrors::new();
        let mut local_context = BlockContext::new_from_args(&self.args, types, self.class);

        for statement in self.original_body {
            // TODO: This needs to become global in a bit
            match ValidatedStatement::new(
                statement,
                functions,
                types,
                class_perms,
                &mut local_context,
                self.class,
                file,
            ) {
                Ok(mut s) => new_body.append(&mut s),
                Err(e) => errors.append(e),
            }
        }
        self.body = Some(new_body);
        errors.into_result(())
    }

    // Generate the sexp for a synthetic alias function calling the real function
    pub fn generate_synthetic_alias_call(&self, alias_cil_name: &str) -> sexp::Sexp {
        let call = ValidatedCall {
            cil_name: self.get_cil_name(),
            args: self.args.iter().map(|a| a.name.clone()).collect(),
        };

        Sexp::List(vec![
            atom_s("macro"),
            atom_s(alias_cil_name),
            Sexp::List(self.args.iter().map(Sexp::from).collect()),
            Sexp::from(&call),
        ])
    }

    pub fn get_declaration_range(&self) -> Option<Range<usize>> {
        self.decl.and_then(|d| d.name.get_range())
    }
}

impl Annotated for &FunctionInfo<'_> {
    fn get_annotations(&self) -> std::collections::btree_set::Iter<AnnotationInfo> {
        self.annotations.iter()
    }
}

impl TryFrom<&FunctionInfo<'_>> for sexp::Sexp {
    type Error = ErrorItem;

    fn try_from(f: &FunctionInfo) -> Result<sexp::Sexp, ErrorItem> {
        let mut macro_cil = vec![
            atom_s("macro"),
            atom_s(&f.get_cil_name()),
            Sexp::List(f.args.iter().map(Sexp::from).collect()),
        ];
        match &f.body {
            None => return Err(InternalError::new().into()),
            Some(statements) => {
                for statement in statements {
                    match statement {
                        ValidatedStatement::Call(c) => macro_cil.push(Sexp::from(&**c)),
                        ValidatedStatement::AvRule(a) => macro_cil.push(Sexp::from(a)),
                        ValidatedStatement::FcRule(f) => macro_cil.push(Sexp::from(f)),
                        ValidatedStatement::PortconRule(p) => macro_cil.push(Sexp::from(p)),
                        ValidatedStatement::ResourcetransRule(r) => macro_cil.push(Sexp::from(r)),
                        ValidatedStatement::FscRule(fs) => macro_cil.push(Sexp::try_from(fs)?),
                        ValidatedStatement::DomtransRule(d) => macro_cil.push(Sexp::from(d)),
                    }
                }
            }
        }
        Ok(Sexp::List(macro_cil))
    }
}

#[derive(Debug, Clone)]
pub struct FunctionArgument<'a> {
    pub param_type: &'a TypeInfo,
    pub name: String,
    pub is_list_param: bool,
    pub default_value: Option<Argument>,
}

impl<'a> FunctionArgument<'a> {
    pub fn new(
        declared_arg: &DeclaredArgument,
        types: &'a TypeMap,
        file: Option<&SimpleFile<String, String>>,
    ) -> Result<Self, ErrorItem> {
        let param_type = match types.get(declared_arg.param_type.as_ref()) {
            Some(ti) => ti,
            None => {
                return Err(ErrorItem::make_compile_or_internal_error(
                    "No such type",
                    file,
                    declared_arg.param_type.get_range(),
                    "Type does not exist",
                ));
            }
        };

        // TODO list parameters

        Ok(FunctionArgument {
            param_type,
            name: declared_arg.name.to_string(),
            is_list_param: declared_arg.is_list_param,
            default_value: declared_arg.default.clone(),
        })
    }

    pub fn new_this_argument(parent_type: &'a TypeInfo) -> Self {
        FunctionArgument {
            param_type: parent_type,
            name: "this".to_string(),
            is_list_param: false,
            default_value: None,
        }
    }
}

impl From<&FunctionArgument<'_>> for sexp::Sexp {
    fn from(f: &FunctionArgument) -> sexp::Sexp {
        list(&[
            atom_s(f.param_type.get_cil_macro_arg_type()),
            atom_s(&f.name),
        ])
    }
}

// Two arguments are equal if their types are the same (including is_list_param).
// Names and defaults may differ
impl PartialEq for FunctionArgument<'_> {
    fn eq(&self, other: &FunctionArgument) -> bool {
        &self.name == "this" && &other.name == "this"
            || (self.param_type == other.param_type && self.is_list_param == other.is_list_param)
    }
}

impl fmt::Display for FunctionArgument<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.param_type.name)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidatedStatement<'a> {
    Call(Box<ValidatedCall>),
    AvRule(AvRule<'a>),
    FcRule(FileContextRule<'a>),
    PortconRule(PortconRule<'a>),
    ResourcetransRule(ResourcetransRule<'a>),
    FscRule(FileSystemContextRule<'a>),
    DomtransRule(DomtransRule<'a>),
}

impl<'a> ValidatedStatement<'a> {
    pub fn new(
        statement: &'a Statement,
        functions: &FunctionMap<'a>,
        types: &'a TypeMap,
        class_perms: &ClassList<'a>,
        context: &mut BlockContext<'a>,
        parent_type: Option<&'a TypeInfo>,
        file: &'a SimpleFile<String, String>,
    ) -> Result<BTreeSet<ValidatedStatement<'a>>, CascadeErrors> {
        let in_resource = match parent_type {
            Some(t) => t.is_resource(types),
            None => false,
        };

        match statement {
            Statement::Call(c) => match c.check_builtin() {
                Some(BuiltIns::AvRule) => {
                    Ok(call_to_av_rule(c, types, class_perms, context, file)?
                        .into_iter()
                        .map(ValidatedStatement::AvRule)
                        .collect())
                }
                Some(BuiltIns::FileContext) => {
                    if in_resource {
                        Ok(call_to_fc_rules(c, types, class_perms, &*context, file)?
                            .into_iter()
                            .map(ValidatedStatement::FcRule)
                            .collect())
                    } else {
                        Err(CascadeErrors::from(
                            ErrorItem::make_compile_or_internal_error(
                                "file_context() calls are only allowed in resources",
                                Some(file),
                                c.name.get_range(),
                                "Not allowed here",
                            ),
                        ))
                    }
                }
                Some(BuiltIns::ResourceTransition) => {
                    if in_resource {
                        Ok(
                            call_to_resource_transition(c, types, class_perms, &*context, file)?
                                .into_iter()
                                .map(ValidatedStatement::ResourcetransRule)
                                .collect(),
                        )
                    } else {
                        Err(CascadeErrors::from(
                            ErrorItem::make_compile_or_internal_error(
                                "resource_transition() calls are not allowed in domains",
                                Some(file),
                                c.name.get_range(),
                                "Not allowed here",
                            ),
                        ))
                    }
                }
                Some(BuiltIns::FileSystemContext) => {
                    if in_resource {
                        Ok(call_to_fsc_rules(c, types, class_perms, &*context, file)?
                            .into_iter()
                            .map(ValidatedStatement::FscRule)
                            .collect())
                    } else {
                        Err(CascadeErrors::from(
                            ErrorItem::make_compile_or_internal_error(
                                "fs_context() calls are only allowed in resources",
                                Some(file),
                                c.name.get_range(),
                                "Not allowed here",
                            ),
                        ))
                    }
                }
                Some(BuiltIns::PortCon) => {
                    if in_resource {
                        // Unwrap is safe because in_resource can only be true when parent_type
                        // is Some
                        Ok([ValidatedStatement::PortconRule(call_to_portcon_rule(
                            c,
                            types,
                            class_perms,
                            &*context,
                            file,
                            parent_type.unwrap(),
                        )?)]
                        .into())
                    } else {
                        Err(CascadeErrors::from(
                            ErrorItem::make_compile_or_internal_error(
                                "portcon() calls are only allowed in resources",
                                Some(file),
                                c.name.get_range(),
                                "Not allowed here",
                            ),
                        ))
                    }
                }

                Some(BuiltIns::DomainTransition) => {
                    if !in_resource {
                        Ok(
                            Some(ValidatedStatement::DomtransRule(call_to_domain_transition(
                                c,
                                types,
                                class_perms,
                                &*context,
                                file,
                            )?))
                            .into_iter()
                            .collect(),
                        )
                    } else {
                        Err(CascadeErrors::from(
                            ErrorItem::make_compile_or_internal_error(
                                "domain_transition() calls are not allowed in resources",
                                Some(file),
                                c.name.get_range(),
                                "Not allowed here",
                            ),
                        ))
                    }
                }
                None => Ok(Some(ValidatedStatement::Call(Box::new(ValidatedCall::new(
                    c,
                    functions,
                    types,
                    class_perms,
                    parent_type,
                    &*context,
                    file,
                )?)))
                .into_iter()
                .collect()),
            },
            Statement::LetBinding(l) => {
                // Global scope let bindings were handled by get_global_bindings() in a previous
                // pass
                if parent_type.is_some() {
                    context.insert_from_argument(&l.name, &l.value, class_perms, file)?;

                    Ok(BTreeSet::default()) // TODO: This is where local scope let bindings should happen
                } else {
                    // Global scope, nothing to do here
                    Ok(BTreeSet::default())
                }
            }
            Statement::IfBlock => {
                // TODO, but silently skip for now
                // The plan would be to recurse and grab the ifs, store both variants
                // and then resolve the bools later
                Ok(BTreeSet::default())
            }
        }
    }

    fn get_renamed_statement(&self, renames: &BTreeMap<String, String>) -> Self {
        match self {
            ValidatedStatement::Call(c) => {
                ValidatedStatement::Call(Box::new(c.get_renamed_call(renames)))
            }
            ValidatedStatement::AvRule(a) => {
                ValidatedStatement::AvRule(a.get_renamed_statement(renames))
            }
            ValidatedStatement::FcRule(f) => {
                ValidatedStatement::FcRule(f.get_renamed_statement(renames))
            }
            ValidatedStatement::DomtransRule(d) => {
                ValidatedStatement::DomtransRule(d.get_renamed_statement(renames))
            }
            ValidatedStatement::ResourcetransRule(r) => {
                ValidatedStatement::ResourcetransRule(r.get_renamed_statement(renames))
            }
            ValidatedStatement::FscRule(f) => {
                ValidatedStatement::FscRule(f.get_renamed_statement(renames))
            }
            ValidatedStatement::PortconRule(p) => {
                ValidatedStatement::PortconRule(p.get_renamed_statement(renames))
            }
        }
    }
}

impl TryFrom<&ValidatedStatement<'_>> for sexp::Sexp {
    type Error = ErrorItem;
    fn try_from(statement: &ValidatedStatement) -> Result<sexp::Sexp, ErrorItem> {
        match statement {
            ValidatedStatement::Call(c) => Ok(Sexp::from(&**c)),
            ValidatedStatement::AvRule(a) => Ok(Sexp::from(a)),
            ValidatedStatement::FcRule(f) => Ok(Sexp::from(f)),
            ValidatedStatement::PortconRule(p) => Ok(Sexp::from(p)),
            ValidatedStatement::ResourcetransRule(r) => Ok(Sexp::from(r)),
            ValidatedStatement::FscRule(fs) => Sexp::try_from(fs),
            ValidatedStatement::DomtransRule(d) => Ok(Sexp::from(d)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValidatedCall {
    cil_name: String,
    args: Vec<String>,
}

impl ValidatedCall {
    pub fn new(
        call: &FuncCall,
        functions: &FunctionMap<'_>,
        types: &TypeMap,
        class_perms: &ClassList,
        parent_type: Option<&TypeInfo>,
        context: &BlockContext,
        file: &SimpleFile<String, String>,
    ) -> Result<ValidatedCall, CascadeErrors> {
        let cil_name = match &call.class_name {
            Some(class_name) => {
                // Resolve aliases
                match types.get(convert_class_name_if_this(class_name, parent_type)?.as_ref()) {
                    Some(type_name) => get_cil_name(Some(&type_name.name), &call.name),
                    None => call.get_cil_name(), // Expected to error out below
                }
            }
            None => call.get_cil_name(),
        };
        let function_info = match functions.get(&cil_name) {
            Some(function_info) => function_info,
            None => {
                return Err(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        "No such function",
                        Some(file),
                        call.get_name_range(),
                        "",
                    ),
                ));
            }
        };

        if function_info.is_virtual {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Invalid call to virtual function",
                Some(file),
                call.get_name_range(),
                "This function is marked as virtual, so it can't be called.",
            )
            .into());
        }

        // Each argument must match the type the function signature expects
        let mut args = match &call.class_name {
            Some(c) => vec![convert_class_name_if_this(c, parent_type)?.get_cil_name()],
            None => Vec::new(),
        };

        for arg in validate_arguments(
            call,
            &function_info.args,
            types,
            class_perms,
            context,
            Some(file),
        )? {
            args.push(arg.get_name_or_string(context)?.to_string()); // TODO: Handle lists
        }

        Ok(ValidatedCall { cil_name, args })
    }

    fn get_renamed_call(&self, renames: &BTreeMap<String, String>) -> Self {
        let new_args = self
            .args
            .iter()
            .cloned()
            .map(|a| renames.get(&a).unwrap_or(&a).to_string())
            .collect();
        ValidatedCall {
            cil_name: self.cil_name.clone(),
            args: new_args,
        }
    }
}

pub fn validate_arguments<'a>(
    call: &'a FuncCall,
    function_args: &[FunctionArgument],
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'a>,
    file: Option<&'a SimpleFile<String, String>>,
) -> Result<Vec<TypeInstance<'a>>, CascadeErrors> {
    // Some functions start with an implicit "this" argument.  If it does, skip it
    let function_args_iter = function_args.iter().skip_while(|a| a.name == "this");

    if function_args_iter
        .clone()
        .take_while(|a| matches!(a.default_value, None))
        .count()
        > call.args.len()
    {
        let function_args_len = if function_args.iter().take(1).any(|f| f.name == "this") {
            function_args.len() - 1
        } else {
            function_args.len()
        };
        return Err(CascadeErrors::from(
            ErrorItem::make_compile_or_internal_error(
                &format!(
                    "Function {} expected {} arguments, got {}",
                    call.get_display_name(),
                    function_args_len,
                    call.args.len()
                ),
                file,
                call.get_name_range(), // TODO: this may not be the cleanest way to report this error
                "",
            ),
        ));
    }

    let mut args = Vec::new();
    for fa in function_args_iter {
        args.push(ExpectedArgInfo::from(fa));
    }
    for (index, a) in call
        .args
        .iter()
        .take_while(|a| !matches!(a.0, Argument::Named(_, _)))
        .enumerate()
    {
        let validated_arg = validate_argument(
            ArgForValidation::from(&a.0),
            &a.1,
            args[index].function_arg,
            types,
            class_perms,
            context,
            file,
            call.is_avc(),
        )?;
        args[index].provided_arg = Some(validated_arg);
    }

    for a in call
        .args
        .iter()
        .skip_while(|a| !matches!(a.0, Argument::Named(_, _)))
    {
        match &a {
            (Argument::Named(n, a), cast) => {
                let index = match args
                    .iter()
                    .position(|ea| ea.function_arg.name == n.as_ref())
                {
                    Some(i) => i,
                    None => {
                        return Err(ErrorItem::make_compile_or_internal_error(
                            "No such argument",
                            file,
                            n.get_range(),
                            "The function does not have an argument with this name",
                        )
                        .into());
                    }
                };
                let validated_arg = validate_argument(
                    ArgForValidation::from(&**a),
                    cast,
                    args[index].function_arg,
                    types,
                    class_perms,
                    context,
                    file,
                    call.is_avc(),
                )?;
                args[index].provided_arg = Some(validated_arg);
            }
            _ => {
                return Err(
                        ErrorItem::make_compile_or_internal_error(
                        "Cannot specify anonymous argument after named argument",
                        file,
                        a.0.get_range(),
                        "This argument is anonymous, but named arguments occurred previously.  All anonymous arguments must come before any named arguments").into());
            }
        }
    }

    let mut out = Vec::new();
    for a in args {
        let provided_arg = match a.provided_arg {
            Some(arg) => arg,
            None => {
                match &a.function_arg.default_value {
                    // TODO: A compile error here may be confusing.  This should really
                    // be validated earlier and then return an internal error here on failure
                    Some(v) => validate_argument(
                        ArgForValidation::from(v),
                        &None,
                        a.function_arg,
                        types,
                        class_perms,
                        context,
                        file,
                        call.is_avc(),
                    )?,
                    None => {
                        return Err(ErrorItem::make_compile_or_internal_error(
                            &format!("No value supplied for {}", a.function_arg.name),
                            file,
                            call.get_name_range(),
                            &format!(
                                "{} has no default value, and was not supplied by this call",
                                a.function_arg.name
                            ),
                        )
                        .into());
                    }
                }
            }
        };
        out.push(provided_arg);
    }

    Ok(out)
}

// The ast Argument owns the data, this struct is similar, but has references to the owned data in
// the ast, so we can make copies and manipulate
pub enum ArgForValidation<'a> {
    Var(&'a CascadeString),
    List(Vec<&'a CascadeString>),
    Quote(&'a CascadeString),
    Port(&'a Port),
    IpAddr(&'a IpAddr),
}

impl<'a> From<&'a Argument> for ArgForValidation<'a> {
    fn from(a: &'a Argument) -> Self {
        match a {
            Argument::Var(s) => ArgForValidation::Var(s),
            Argument::Named(_, a) => ArgForValidation::from(&**a),
            Argument::List(v) => ArgForValidation::List(v.iter().collect()),
            Argument::Quote(s) => ArgForValidation::Quote(s),
            Argument::Port(p) => ArgForValidation::Port(p),
            Argument::IpAddr(i) => ArgForValidation::IpAddr(i),
        }
    }
}

impl fmt::Display for ArgForValidation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ArgForValidation::Var(a) => write!(f, "'{a}'"),
            ArgForValidation::List(_) => write!(f, "[TODO]",),
            ArgForValidation::Quote(a) => write!(f, "\"{a}\""),
            ArgForValidation::Port(p) => write!(f, "{p}"),
            ArgForValidation::IpAddr(i) => write!(f, "{i}"),
        }
    }
}

impl<'a> ArgForValidation<'a> {
    fn coerce_list(a: ArgForValidation<'a>) -> Self {
        let vec = match a {
            ArgForValidation::Var(s) => vec![s],
            ArgForValidation::List(v) => v,
            ArgForValidation::Quote(s) => vec![s],
            // TODO: The approach here assumes all Arguments are either CascadeStrings or lists of
            // CascadeStrings under the hood.  That seems like basically a bad assumption, but
            // fixing it will be somewhat non-trivial
            ArgForValidation::Port(_p) => todo!(),
            ArgForValidation::IpAddr(_i) => todo!(),
        };
        ArgForValidation::List(vec)
    }

    fn get_range(&self) -> Option<Range<usize>> {
        match self {
            ArgForValidation::Var(s) => s.get_range(),
            ArgForValidation::List(v) => CascadeString::slice_to_range(v),
            ArgForValidation::Quote(s) => s.get_range(),
            ArgForValidation::Port(p) => p.get_range(),
            ArgForValidation::IpAddr(i) => i.get_range(),
        }
    }

    // An arg can be cast to a ti if it is an setype
    // cast_ti is unused for now, but it seems like casting rules may eventually become more
    // complicated, so ensuring we'll have the ability to use it in the future seems worthwhile
    fn verify_cast(
        &self,
        _cast_ti: &TypeInfo,
        types: &TypeMap,
        context: &BlockContext<'a>,
        file: Option<&SimpleFile<String, String>>,
    ) -> Result<(), ErrorItem> {
        let err_ret = |r: Option<Range<usize>>| {
            ErrorItem::make_compile_or_internal_error(
                "Cannot typecast",
                file,
                r,
                "This is not something that can be typecast",
            )
        };

        let check_validity = |s: &CascadeString| {
            if types.get(s.as_ref()).is_none()
                && !context
                    .symbol_in_context(s.as_ref())
                    .map(|ti| ti.is_setype(types))
                    .unwrap_or(false)
            {
                Err(err_ret(s.get_range()))
            } else {
                Ok(())
            }
        };

        match self {
            ArgForValidation::Var(s) => {
                return check_validity(s);
            }
            ArgForValidation::List(v) => {
                for s in v {
                    // TODO: report more than just the first error
                    check_validity(s)?;
                }
            }
            ArgForValidation::Quote(inner) => {
                return Err(err_ret(inner.get_range()));
            }
            ArgForValidation::Port(inner) => {
                return Err(err_ret(inner.get_range()));
            }
            ArgForValidation::IpAddr(inner) => {
                return Err(err_ret(inner.get_range()));
            }
        }

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_argument<'a>(
    arg: ArgForValidation,
    cast_name: &Option<CascadeString>,
    target_argument: &FunctionArgument,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'a>,
    file: Option<&'a SimpleFile<String, String>>,
    is_avc: bool,
) -> Result<TypeInstance<'a>, ErrorItem> {
    // If there is a cast, we first validate that regardless of whether the actual value is a list
    if let Some(cast_name) = cast_name {
        // If the cast doesn't validate, that's an error and we can just return the cast validation
        // error
        let cast_ti = validate_argument(
            ArgForValidation::Var(cast_name),
            &None,
            target_argument,
            types,
            class_perms,
            context,
            file,
            is_avc,
        )?;
        if !matches!(cast_ti.instance_value, TypeValue::SEType(_)) {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Not something we can cast to",
                file,
                cast_name.get_range(),
                "This must be a domain, resource or trait that exists in this policy",
            ));
        }
        arg.verify_cast(cast_ti.type_info.borrow(), types, context, file)?;

        return Ok(TypeInstance::new_cast_instance(
            &arg,
            Cow::Borrowed(argument_to_typeinfo(
                &arg,
                types,
                class_perms,
                context,
                file,
            )?),
            file,
        ));
    }
    match &arg {
        ArgForValidation::List(v) => {
            if !target_argument.is_list_param {
                return Err(ErrorItem::make_compile_or_internal_error(
                    "Unexpected list",
                    file,
                    CascadeString::slice_to_range(v),
                    "This function requires a non-list value here",
                ));
            }
            let target_ti = match types.get(target_argument.param_type.name.as_ref()) {
                Some(t) => t,
                None => return Err(InternalError::new().into()),
            };
            let arg_typeinfo_vec = argument_to_typeinfo_vec(v, types, class_perms, context, file)?;

            for arg in arg_typeinfo_vec {
                if !arg.is_child_or_actual_type(target_argument.param_type, types) {
                    return Err(ErrorItem::make_compile_or_internal_error(
                        &format!("Expected type inheriting {}", target_ti.name),
                        file,
                        arg.name.get_range(),
                        &format!("This type should inherit {}", target_ti.name),
                    ));
                }
            }
            Ok(TypeInstance::new(&arg, target_ti, file, context))
        }
        _ => {
            let arg_typeinfo = argument_to_typeinfo(&arg, types, class_perms, context, file)?;
            if target_argument.is_list_param {
                if arg_typeinfo.list_coercion
                    || matches!(arg_typeinfo.bound_type, BoundTypeInfo::List(_))
                {
                    return validate_argument(
                        ArgForValidation::coerce_list(arg),
                        cast_name,
                        target_argument,
                        types,
                        class_perms,
                        context,
                        file,
                        is_avc,
                    );
                    // TODO: Do we handle bound lists here?
                }
                return Err(ErrorItem::make_compile_or_internal_error(
                    "Expected list",
                    file,
                    arg.get_range(),
                    "This function requires a list value here",
                ));
            }

            if let Some(resource_type) = types.get(constants::RESOURCE) {
                if (target_argument.param_type == resource_type
                    || target_argument
                        .param_type
                        .is_child_or_actual_type(resource_type, types))
                    && arg_typeinfo.name == constants::SELF
                    && !is_avc
                {
                    return Err(ErrorItem::make_compile_or_internal_error(
                        "'self' passed as resource argument",
                        file,
                        arg.get_range(),
                        "'self' cannot be passed into a function as a resource since 'self' \
                        is dependent on local context\n\t(If you intended to refer to the type declared \
                        in the enclosing block, use 'this')",
                    ));
                }
            }

            if arg_typeinfo.is_child_or_actual_type(target_argument.param_type, types) {
                Ok(TypeInstance::new(&arg, arg_typeinfo, file, context))
            } else {
                Err(ErrorItem::make_compile_or_internal_error(
                    &format!(
                        "Expected type inheriting {}",
                        target_argument.param_type.name
                    ),
                    file,
                    arg.get_range(),
                    &format!(
                        "This type should inherit {}",
                        target_argument.param_type.name
                    ),
                ))
            }
        }
    }
}

impl From<&ValidatedCall> for sexp::Sexp {
    fn from(call: &ValidatedCall) -> sexp::Sexp {
        let args = call.args.iter().map(|a| atom_s(a)).collect::<Vec<Sexp>>();

        Sexp::List(vec![
            atom_s("call"),
            atom_s(&call.cil_name),
            Sexp::List(args),
        ])
    }
}

struct ExpectedArgInfo<'a, 'b> {
    function_arg: &'a FunctionArgument<'a>,
    provided_arg: Option<TypeInstance<'b>>,
}

impl<'a> From<&'a FunctionArgument<'a>> for ExpectedArgInfo<'a, '_> {
    fn from(f: &'a FunctionArgument) -> Self {
        ExpectedArgInfo {
            function_arg: f,
            provided_arg: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Annotations, TypeDecl};
    use crate::sexp_internal;

    #[test]
    fn is_collapsed_class_test() {
        assert!(!is_collapsed_class("foo"));
        assert!(!is_collapsed_class("capability2"));
        assert!(is_collapsed_class("capability"));
        assert!(is_collapsed_class("process"));
        assert!(is_collapsed_class("cap_userns"));
    }

    #[test]
    fn generate_cil_for_av_rule_test() {
        let cil_sexp = Sexp::from(&AvRule {
            av_rule_flavor: AvRuleFlavor::Allow,
            source: Cow::Owned("foo".into()),
            target: Cow::Owned("bar".into()),
            class: Cow::Owned("file".into()),
            perms: vec!["read".into(), "getattr".into()],
        });

        let cil_expected = "(allow foo bar (file (read getattr)))";

        assert_eq!(cil_sexp.to_string(), cil_expected.to_string());
    }

    #[test]
    fn function_info_get_cil_name_test() {
        let some_file = SimpleFile::new("bar".to_string(), "bar".to_string());
        let mut fi = FunctionInfo {
            name: "foo".to_string(),
            class: None,
            is_virtual: false,
            args: Vec::new(),
            annotations: BTreeSet::new(),
            original_body: &[],
            body: None,
            declaration_file: &some_file,
            is_associated_call: false,
            is_derived: false,
            decl: None,
        };

        assert_eq!(&fi.get_cil_name(), "foo");

        let ti = TypeInfo::new(
            TypeDecl {
                name: CascadeString::from("bar"),
                inherits: Vec::new(),
                is_virtual: false,
                is_trait: false,
                is_extension: false,
                expressions: Vec::new(),
                annotations: Annotations::new(),
            },
            &some_file,
        )
        .unwrap();

        fi.class = Some(&ti);

        assert_eq!(&fi.get_cil_name(), "bar-foo");
    }

    #[test]
    fn filecon_to_sexp_test() {
        let fc = FileContextRule {
            regex_string: "\"/bin\"".to_string(),
            file_type: FileType::File,
            context: Context::new(
                false,
                Some(Cow::Borrowed("u")),
                Some(Cow::Borrowed("r")),
                Cow::Borrowed("bin_t"),
                None,
                None,
            ),
        };
        assert_eq!(
            "(filecon \"/bin\" file (u r bin_t ((s0) (s0))))".to_string(),
            sexp_internal::display_cil(&Sexp::from(&fc))
        );
    }

    #[test]
    fn file_type_from_string_test() {
        let file_type = "file".parse::<FileType>().unwrap();
        assert!(matches!(file_type, FileType::File));
        let file_type = "any".parse::<FileType>().unwrap();
        assert!(matches!(file_type, FileType::Any));

        assert!("bad_type".parse::<FileType>().is_err());
    }

    #[test]
    fn get_renamed_statement_test() {
        let statement1 = ValidatedStatement::Call(Box::new(ValidatedCall {
            cil_name: "foo".to_string(),
            args: vec!["old_name".to_string(), "b".to_string()],
        }));

        let statement2 = ValidatedStatement::AvRule(AvRule {
            av_rule_flavor: AvRuleFlavor::Allow,
            source: Cow::Owned(CascadeString::from("foo")),
            target: Cow::Owned(CascadeString::from("bar")),
            class: Cow::Owned(CascadeString::from("old_name")),
            perms: vec![CascadeString::from("read")],
        });

        let statement3 = ValidatedStatement::FcRule(FileContextRule {
            regex_string: "/bin".to_string(),
            file_type: FileType::SymLink,
            context: Context::new(false, None, None, Cow::Borrowed("old_name"), None, None),
        });

        let statement4 = ValidatedStatement::DomtransRule(DomtransRule {
            source: Cow::Owned(CascadeString::from("old_name")),
            target: Cow::Owned(CascadeString::from("old_name")),
            executable: Cow::Owned(CascadeString::from("old_name")),
        });

        let statement5 = ValidatedStatement::PortconRule(PortconRule {
            proto: Protocol::Tcp,
            port: CascadeString::from("1234"),
            context: Context::new(false, None, None, Cow::Borrowed("old_name"), None, None),
        });

        for statement in [statement1, statement2, statement3, statement4, statement5] {
            let mut renames = BTreeMap::new();
            renames.insert("old_name".to_string(), "new_name".to_string());
            let renamed_statement = statement.get_renamed_statement(&renames);
            let sexp = Sexp::try_from(&renamed_statement).unwrap();
            assert!(sexp.to_string().contains("new_name"));
            assert!(!sexp.to_string().contains("old_name"));
        }
    }

    #[test]
    fn validate_port_test() {
        validate_port(&CascadeString::from("1"), None).unwrap();
        assert!(validate_port(&CascadeString::from("foo"), None).is_err());
        validate_port(&CascadeString::from("1-2"), None).unwrap();
        validate_port(&CascadeString::from("1,2"), None).unwrap();
        validate_port(&CascadeString::from("1,1234-2000"), None).unwrap();
        validate_port(&CascadeString::from("1,1234-2000,65535"), None).unwrap();
        assert!(validate_port(&CascadeString::from("1-2-3"), None).is_err());
        assert!(validate_port(&CascadeString::from("65536"), None).is_err());
        assert!(validate_port(&CascadeString::from("-1"), None).is_err());
        assert!(validate_port(&CascadeString::from("2-1"), None).is_err());
    }
}
