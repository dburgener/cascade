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
    get_all_func_calls, get_cil_name, Annotation, Argument, BuiltIns, CascadeString,
    DeclaredArgument, FuncCall, FuncDecl, IpAddr, Port, Statement,
};
use crate::constants;
use crate::context::{BlockType, Context as BlockContext};
use crate::error::{
    add_or_create_compile_error, CascadeErrors, CompileError, ErrorItem, InternalError,
};
use crate::internal_rep::{
    type_name_from_string, typeinfo_from_string, Annotated, AnnotationInfo, ClassList, Context,
    Sid, TypeInfo, TypeInstance, TypeMap,
};
use crate::obj_class::perm_list_to_sexp;
use crate::warning::{Warning, Warnings, WithWarnings};

macro_rules! nv_on_field {
    ($self: ident, $field:ident, $rules:ident, $types:ident) => {
        let nv_children = $types
            .get($self.$field.as_ref().as_ref())
            .map(|ti| ti.non_virtual_children.clone())
            .unwrap_or_default();
        let mut new_rules = BTreeSet::new();
        for child in &nv_children {
            let mut new_rule = $self.clone();
            new_rule.$field = Cow::Owned(child.clone());
            new_rules.insert(new_rule);
            for rule in &$rules {
                let mut new_rule = rule.clone();
                new_rule.$field = Cow::Owned(child.clone());
                new_rules.insert(new_rule);
            }
        }
        $rules.append(&mut new_rules);
    };
}

pub fn argument_to_typeinfo<'a>(
    a: &ArgForValidation<'_>,
    types: &'a TypeMap,
    class_perms: &ClassList,
    expected_type: Option<&TypeInfo>,
    context: &BlockContext<'a>,
    file: Option<&'a SimpleFile<String, String>>,
) -> Result<&'a TypeInfo, ErrorItem> {
    let t: Option<&TypeInfo> = match a {
        ArgForValidation::Var(s) => match context.symbol_in_context(s.as_ref(), types) {
            Some(res) => Some(res),
            // In annotations, we want to treat arguments as strings and the annotation is
            // responsible for understanding what they refer to.  This allows annotations to work
            // across namespaces
            None => typeinfo_from_string(
                s.as_ref(),
                context.in_annotation(),
                types,
                class_perms,
                expected_type,
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
    expected_type: Option<&TypeInfo>,
    context: &BlockContext<'a>,
    file: Option<&'a SimpleFile<String, String>>,
) -> Result<Vec<&'a TypeInfo>, ErrorItem> {
    let mut ret = Vec::new();
    for s in arg {
        ret.push(argument_to_typeinfo(
            &ArgForValidation::Var(s),
            types,
            class_perms,
            expected_type,
            context,
            file,
        )?);
    }
    Ok(ret)
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

impl<'a> AvRule<'a> {
    pub fn create_non_virtual_child_rules(
        &self,
        types: &TypeMap,
    ) -> BTreeSet<ValidatedStatement<'a>> {
        let mut rules: BTreeSet<AvRule> = BTreeSet::new();
        nv_on_field!(self, source, rules, types);
        nv_on_field!(self, target, rules, types);

        rules.into_iter().map(ValidatedStatement::AvRule).collect()
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
    c: &FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'_>,
    file: Option<&'a SimpleFile<String, String>>,
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
            class_perms,
            context,
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
            class_perms,
            context,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::CLASS),
                is_list_param: true,
                name: CascadeString::from("class"),
                default: None,
            },
            types,
            class_perms,
            context,
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
            class_perms,
            context,
            None,
        )?,
    ];

    let validated_args = validate_arguments(
        c,
        &target_args,
        types,
        class_perms,
        context,
        file,
        None,
        None,
    )?;
    let mut args_iter = validated_args.iter();

    let source = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let target = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let classes = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_list(context)?;
    let perms = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_list(context)?;

    if args_iter.next().is_some() {
        return Err(ErrorItem::Internal(InternalError::new()).into());
    }

    for class in &classes {
        for p in &perms {
            class_perms.verify_permission(class, p, context, file)?;
        }
    }

    let perms = ClassList::expand_perm_list(perms.iter().collect(), context);

    let mut av_rules = Vec::new();

    for class in classes {
        if is_collapsed_class(class.as_ref()) {
            let mut split_perms = (Vec::new(), Vec::new());
            if let Some(class_struct) = class_perms.classes.get(class.as_ref()) {
                for p in perms.clone() {
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
                        source: Cow::Owned(source.clone()),
                        target: Cow::Owned(target.clone()),
                        class: Cow::Owned(CascadeString::from(
                            class_struct.collapsed_name.unwrap(),
                        )),
                        perms: split_perms.1,
                    });
                }
            } else {
                return Err(ErrorItem::Internal(InternalError::new()).into());
            }
        } else {
            av_rules.push(AvRule {
                av_rule_flavor: flavor,
                source: Cow::Owned(source.clone()),
                target: Cow::Owned(target.clone()),
                class: Cow::Owned(class.clone()),
                perms: perms.clone(),
            })
        };
    }

    Ok(av_rules.into_iter().collect())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileType {
    File,
    Directory,
    SymLink,
    CharDev,
    BlockDev,
    Socket,
    Pipe,
    Any,
    // A symbol bound at the CIL level to a file type string
    Symbol(String),
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
                FileType::Symbol(s) => s,
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

impl FileType {
    fn validate(
        file_type: CascadeString,
        file: Option<&SimpleFile<String, String>>,
    ) -> Result<Self, CascadeErrors> {
        match file_type.to_string().parse::<FileType>() {
            Ok(ft) => Ok(ft),
            Err(_) => Err(CascadeErrors::from(
                ErrorItem::make_compile_or_internal_error(
                    "Not a valid file type",
                    file,
                    file_type.get_range(),
                    "",
                ),
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileContextRule<'a> {
    pub regex_string: String,
    pub file_type: FileType,
    pub context: Context<'a>,
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
    c: &FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'_>,
    file: Option<&'a SimpleFile<String, String>>,
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
            class_perms,
            context,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::CLASS), //TODO: not really
                is_list_param: true,
                name: CascadeString::from("file_type"),
                default: None,
            },
            types,
            class_perms,
            context,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("context"),
                is_list_param: false,
                name: CascadeString::from("file_context"),
                default: None,
            },
            types,
            class_perms,
            context,
            None,
        )?,
    ];

    let validated_args = validate_arguments(
        c,
        &target_args,
        types,
        class_perms,
        context,
        file,
        None,
        None,
    )?;
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
                    file,
                    context_str.get_range(),
                    "Cannot parse this into a context",
                ),
            ))
        }
    };

    for file_type in file_types {
        let ft = FileType::validate(file_type, file)?;

        ret.push(FileContextRule {
            regex_string: regex_string.clone(),
            file_type: ft,
            context: context.clone(),
        });
    }

    Ok(ret)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
    Dccp,
    Sctp,
}

impl From<Protocol> for &str {
    fn from(p: Protocol) -> &'static str {
        match p {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Dccp => "dccp",
            Protocol::Sctp => "sctp",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct PortconRule<'a> {
    proto: Protocol,
    port_num: Port,
    context: Context<'a>,
}

impl From<&PortconRule<'_>> for sexp::Sexp {
    fn from(p: &PortconRule) -> sexp::Sexp {
        list(&[
            atom_s("portcon"),
            atom_s(p.proto.into()),
            Sexp::from(&p.port_num),
            Sexp::from(&p.context),
        ])
    }
}

pub fn call_to_portcon_rules<'a>(
    c: &FuncCall,
    types: &TypeMap,
    class_perms: &ClassList,
    context: &BlockContext,
    file: Option<&SimpleFile<String, String>>,
) -> Result<BTreeSet<PortconRule<'a>>, CascadeErrors> {
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("string"),
                is_list_param: false,
                name: CascadeString::from("protocol"),
                default: None,
            },
            types,
            class_perms,
            context,
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
            class_perms,
            context,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("context"),
                is_list_param: false,
                name: CascadeString::from("port_context"),
                default: None,
            },
            types,
            class_perms,
            context,
            None,
        )?,
    ];

    let validated_args = validate_arguments(
        c,
        &target_args,
        types,
        class_perms,
        context,
        file,
        None,
        None,
    )?;
    let mut args_iter = validated_args.iter();

    let proto = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let proto = match proto.as_ref() {
        "\"tcp\"" | "\"TCP\"" => Protocol::Tcp,
        "\"udp\"" | "\"UDP\"" => Protocol::Udp,
        "\"dccp\"" | "\"DCCP\"" => Protocol::Dccp,
        "\"sctp\"" | "\"SCTP\"" => Protocol::Sctp,
        _ => {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Not a valid protocol",
                file,
                proto.get_range(),
                "Valid protocols are \"tcp\", \"udp\", \"dccp\", and \"sctp\"",
            )
            .into());
        }
    };

    let port = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;

    let ports = validate_port(&port, file)?;

    let context_str = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;

    let context = match Context::try_from(context_str.to_string()) {
        Ok(c) => c,
        Err(()) => {
            return Err(ErrorItem::Internal(InternalError::new()).into());
        }
    };

    let mut ret = BTreeSet::new();
    for p in ports {
        ret.insert(PortconRule {
            proto,
            port_num: p,
            context: context.clone(),
        });
    }
    Ok(ret)
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
) -> Result<Vec<Port>, ErrorItem> {
    let mut ret = Vec::new();
    for substr in port.as_ref().split(',') {
        match validate_port_helper(substr) {
            Ok(p) => ret.push(p),
            Err(_) => {
                return Err(ErrorItem::make_compile_or_internal_error(
                    "Not a valid port",
                    current_file,
                    port.get_range(),
                    "This should be a comma separated list of ports or port ranges",
                ));
            }
        }
    }
    Ok(ret)
}

fn validate_port_helper(port: &str) -> Result<Port, ()> {
    if port.contains('-') {
        let mut split = port.split('-');
        let first = split.next().ok_or(())?.parse::<u16>().map_err(|_| ())?;
        let second = split.next().ok_or(())?.parse::<u16>().map_err(|_| ())?;
        if split.next().is_some() || second <= first {
            Err(())
        } else {
            Ok(Port::new_port_range(first, second, None))
        }
    } else {
        Ok(Port::new(port.parse::<u16>().map_err(|_| ())?, None))
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
    pub file: Option<SimpleFile<String, String>>,
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
            &self.file_type,
            &self.context,
        )
            .cmp(&(
                &other.fscontext_type,
                &other.fs_name,
                &other.path,
                &other.file_type,
                &other.context,
            ))
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
    c: &FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'_>,
    file: Option<&'a SimpleFile<String, String>>,
) -> Result<Vec<FileSystemContextRule<'a>>, CascadeErrors> {
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("string"),
                is_list_param: false,
                name: CascadeString::from("fs_name"),
                default: None,
            },
            types,
            class_perms,
            context,
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
            class_perms,
            context,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("context"),
                is_list_param: false,
                name: CascadeString::from("fs_label"),
                default: None,
            },
            types,
            class_perms,
            context,
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
            class_perms,
            context,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::CLASS), //TODO: not really
                is_list_param: true,
                name: CascadeString::from("file_type"),
                default: Some(Argument::List(vec![])),
            },
            types,
            class_perms,
            context,
            None,
        )?,
    ];
    let validated_args = validate_arguments(
        c,
        &target_args,
        types,
        class_perms,
        context,
        file,
        None,
        None,
    )?;
    let mut args_iter = validated_args.iter();
    let mut ret = Vec::new();

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
                    file,
                    fscontext_str.get_range(),
                    "File system type must be 'xattr', 'task', 'trans', or 'genfscon'",
                ),
            ));
        }
    };
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
                    file,
                    context_str.get_range(),
                    "Cannot parse this into a context",
                ),
            ))
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
                    file: file.cloned(),
                });
            }
            let mut errors = CascadeErrors::new();
            if !file_types.is_empty() {
                errors.append(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        "File types can only be provided for 'genfscon'",
                        file,
                        file_types_arg.get_range(),
                        "",
                    ),
                ));
            }
            if regex_string_arg.get_range().is_some() {
                errors.append(CascadeErrors::from(
                    ErrorItem::make_compile_or_internal_error(
                        "File path can only be provided for 'genfscon'",
                        file,
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
                    file: file.cloned(),
                });
            } else {
                for file_type in file_types {
                    let file_type = FileType::validate(file_type, file)?;

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
                        file: file.cloned(),
                    });
                }
            }
        }
    }

    Ok(ret)
}

fn call_to_sids<'a>(
    c: &FuncCall,
    types: &TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'_>,
    file: Option<&SimpleFile<String, String>>,
) -> Result<Vec<Sid<'a>>, CascadeErrors> {
    if context.in_function_block() {
        return Err(CascadeErrors::from(
            ErrorItem::make_compile_or_internal_error(
                "initial_context() calls are not valid in functions",
                file,
                c.name.get_range(),
                "You may want to place this call directly inside a type definition",
            ),
        ));
    }

    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("string"),
                is_list_param: false,
                name: CascadeString::from("sid_name"),
                default: None,
            },
            types,
            class_perms,
            context,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("context"),
                is_list_param: false,
                name: CascadeString::from("fs_label"),
                default: None,
            },
            types,
            class_perms,
            context,
            None,
        )?,
    ];
    let validated_args = validate_arguments(
        c,
        &target_args,
        types,
        class_perms,
        context,
        file,
        None,
        None,
    )?;
    let mut args_iter = validated_args.iter();

    let sid_name = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let context_str = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let sid_context = match Context::try_from(context_str.to_string()) {
        Ok(c) => c,
        Err(_) => {
            return Err(CascadeErrors::from(
                ErrorItem::make_compile_or_internal_error(
                    "Invalid context",
                    file,
                    context_str.get_range(),
                    "Cannot parse this into a context",
                ),
            ))
        }
    };

    Ok(vec![Sid::new(sid_name.to_string(), sid_context)])
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomtransRule<'a> {
    pub source: Cow<'a, CascadeString>,
    pub target: Cow<'a, CascadeString>,
    pub executable: Cow<'a, CascadeString>,
}

impl<'a> DomtransRule<'a> {
    pub fn create_non_virtual_child_rules(
        &self,
        types: &TypeMap,
    ) -> BTreeSet<ValidatedStatement<'a>> {
        let mut rules: BTreeSet<DomtransRule> = BTreeSet::new();
        nv_on_field!(self, source, rules, types);
        nv_on_field!(self, target, rules, types);
        nv_on_field!(self, executable, rules, types);

        rules
            .into_iter()
            .map(ValidatedStatement::DomtransRule)
            .collect()
    }
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

fn call_to_domain_transition<'a>(
    c: &FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'_>,
    file: Option<&'a SimpleFile<String, String>>,
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
            class_perms,
            context,
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
            class_perms,
            context,
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
            class_perms,
            context,
            None,
        )?,
    ];

    let validated_args = validate_arguments(
        c,
        &target_args,
        types,
        class_perms,
        context,
        file,
        None,
        None,
    )?;
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
    pub file_type: Cow<'a, CascadeString>,
    pub obj_name: Option<CascadeString>,
}

impl<'a> ResourcetransRule<'a> {
    pub fn create_non_virtual_child_rules(
        &self,
        types: &TypeMap,
    ) -> BTreeSet<ValidatedStatement<'a>> {
        let mut rules: BTreeSet<ResourcetransRule> = BTreeSet::new();
        nv_on_field!(self, default, rules, types);
        nv_on_field!(self, domain, rules, types);
        nv_on_field!(self, parent, rules, types);

        rules
            .into_iter()
            .map(ValidatedStatement::ResourcetransRule)
            .collect()
    }
}

impl From<&ResourcetransRule<'_>> for sexp::Sexp {
    fn from(r: &ResourcetransRule) -> Self {
        if let Some(obj_name) = &r.obj_name {
            list(&[
                atom_s("typetransition"),
                atom_s(&r.domain.get_cil_name()),
                atom_s(&r.parent.get_cil_name()),
                Sexp::Atom(Atom::S(r.file_type.to_string())),
                atom_s(obj_name.as_ref()),
                atom_s(&r.default.get_cil_name()),
            ])
        } else {
            list(&[
                atom_s("typetransition"),
                atom_s(&r.domain.get_cil_name()),
                atom_s(&r.parent.get_cil_name()),
                Sexp::Atom(Atom::S(r.file_type.to_string())),
                atom_s(&r.default.get_cil_name()),
            ])
        }
    }
}

fn call_to_resource_transition<'a>(
    c: &FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'_>,
    file: Option<&'a SimpleFile<String, String>>,
) -> Result<Vec<ResourcetransRule<'a>>, CascadeErrors> {
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::DOMAIN),
                is_list_param: false,
                name: CascadeString::from("domain"),
                default: None,
            },
            types,
            class_perms,
            context,
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
            class_perms,
            context,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::CLASS),
                is_list_param: true,
                name: CascadeString::from("classes"),
                default: None,
            },
            types,
            class_perms,
            context,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from(constants::RESOURCE),
                is_list_param: false,
                name: CascadeString::from("default"),
                default: None,
            },
            types,
            class_perms,
            context,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("string"),
                is_list_param: false,
                name: CascadeString::from("obj_name"),
                default: Some(Argument::Quote(CascadeString::from(""))),
            },
            types,
            class_perms,
            context,
            None,
        )?,
    ];

    let validated_args = validate_arguments(
        c,
        &target_args,
        types,
        class_perms,
        context,
        file,
        None,
        None,
    )?;
    let mut args_iter = validated_args.into_iter();
    let mut ret = Vec::new();

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
    let default = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;

    let obj_name = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;

    if args_iter.next().is_some() {
        return Err(ErrorItem::Internal(InternalError::new()).into());
    }

    let obj_name = if obj_name.to_string().is_empty() {
        None
    } else {
        Some(obj_name)
    };

    for file_type in file_types {
        ret.push(ResourcetransRule {
            default: Cow::Owned(default.clone()),
            domain: Cow::Owned(domain.clone()),
            parent: Cow::Owned(parent.clone()),
            file_type: Cow::Owned(file_type.clone()),
            obj_name: obj_name.clone(),
        });
    }

    Ok(ret)
}

fn check_associated_call(
    annotation: &Annotation,
    funcdecl: &FuncDecl,
    file: &SimpleFile<String, String>,
    types: &TypeMap,
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
            if let Some(type_info) = types.get(param_type.as_ref()) {
                if !type_info.is_domain(types) || *is_list_param {
                    return Err(ErrorItem::make_compile_or_internal_error(
                        "Invalid method signature for @associated_call annotation: invalid first argument",
                        Some(file),
                        param_type.get_range(),
                        "The type of the first method argument must be a domain.",
                    ));
                }
            } else {
                return Err(ErrorItem::make_compile_or_internal_error(
                    "Invalid method signature for @associated_call annotation: could not resolve first argument type",
                    Some(file),
                    param_type.get_range(),
                    "Is the first argument type properly defined?",
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

// Information about a caller of a given function
// Note that deriving PartialEq and Eq means that all elements must be equal (including
// passed_args) for CallerInfo to be equal.  This is important, because we need exactly one copy of
// each set of args a given parent calls a function with
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallerInfo {
    caller_name: CascadeString,
    pub passed_args: Vec<CilArg>,
}

impl CallerInfo {
    pub fn new(caller_name: CascadeString, passed_args: Vec<CilArg>) -> CallerInfo {
        CallerInfo {
            caller_name,
            passed_args,
        }
    }
}

pub type FunctionMap<'a> = AliasMap<FunctionInfo<'a>>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FunctionClass<'a> {
    Type(&'a TypeInfo),
    Collection(&'a CascadeString),
    Global,
}

// If we're in a type block, get the type, else None
impl<'a> From<FunctionClass<'a>> for Option<&'a TypeInfo> {
    fn from(class: FunctionClass<'a>) -> Option<&'a TypeInfo> {
        if let FunctionClass::Type(t) = class {
            Some(t)
        } else {
            None
        }
    }
}

impl<'a> FunctionClass<'a> {
    fn get_name(&self) -> Option<&'a CascadeString> {
        match self {
            FunctionClass::Type(t) => Some(&t.name),
            FunctionClass::Collection(a) => Some(a),
            FunctionClass::Global => None,
        }
    }

    pub fn is_type(&self) -> bool {
        matches!(self, FunctionClass::Type(_))
    }
}

#[derive(Debug, Clone)]
pub struct FunctionInfo<'a> {
    pub name: String,
    pub name_aliases: BTreeSet<String>,
    pub class: FunctionClass<'a>,
    pub is_virtual: bool,
    pub args: Vec<FunctionArgument<'a>>,
    pub annotations: BTreeSet<AnnotationInfo>,
    pub original_body: Vec<Statement>,
    pub body: Option<BTreeSet<ValidatedStatement<'a>>>,
    pub declaration_file: Option<&'a SimpleFile<String, String>>,
    pub is_associated_call: bool,
    pub is_derived: bool,
    // This will be initialized to true and prevalidate_functions will set this
    // to false if needed.
    pub is_castable: bool,
    pub callers: BTreeSet<CallerInfo>,
    decl: Option<&'a FuncDecl>,
}

impl Declared for FunctionInfo<'_> {
    fn get_file(&self) -> Option<SimpleFile<String, String>> {
        self.declaration_file.cloned()
    }

    fn get_name_range(&self) -> Option<Range<usize>> {
        self.decl.and_then(|d| d.name.get_range())
    }

    fn get_generic_name(&self) -> String {
        String::from("function")
    }

    fn get_secondary_indices(&self) -> Vec<String> {
        match self.class.get_name() {
            Some(name) => vec![name.to_string()],
            None => Vec::new(),
        }
    }
}

impl<'a> FunctionInfo<'a> {
    pub fn new(
        funcdecl: &'a FuncDecl,
        types: &'a TypeMap,
        classlist: &ClassList,
        parent_type: FunctionClass<'a>,
        declaration_file: &'a SimpleFile<String, String>,
    ) -> Result<FunctionInfo<'a>, CascadeErrors> {
        let mut args = Vec::new();
        let mut errors = CascadeErrors::new();
        let mut annotations = BTreeSet::new();

        // All member functions automatically have "this" available as a reference to their type
        if let FunctionClass::Type(parent_type) = parent_type {
            args.push(FunctionArgument::new_this_argument(parent_type));
        }

        let class_aliases = match parent_type {
            FunctionClass::Type(ti) => {
                let mut type_aliases = vec![Some(&ti.name)];
                for ann in &ti.annotations {
                    if let AnnotationInfo::Alias(alias_name) = ann {
                        type_aliases.push(Some(alias_name));
                    }
                }
                type_aliases
            }
            FunctionClass::Collection(c) => vec![Some(c)], // TODO: aliases on the collection itself
            FunctionClass::Global => vec![None],
        };

        let mut func_aliases = vec![&funcdecl.name];

        if funcdecl.args.is_empty() {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Function has no arguments",
                Some(declaration_file),
                funcdecl.name.get_range(),
                "This function has no arguments, which is illegal in Cascade",
            )
            .into());
        }

        // We don't currently track a context through the function mapping
        let fake_context = BlockContext::new(BlockType::Global, None, None);

        for a in &funcdecl.args {
            match FunctionArgument::new(a, types, classlist, &fake_context, Some(declaration_file))
            {
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
                        check_associated_call(annotation, funcdecl, declaration_file, types)?;
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
                if *class_alias == parent_type.get_name() && *func_alias == &funcdecl.name {
                    continue;
                }
                annotations.insert(AnnotationInfo::Alias(
                    get_cil_name(*class_alias, func_alias).into(),
                ));
            }
        }

        errors.into_result(FunctionInfo {
            name: funcdecl.name.to_string(),
            name_aliases: func_aliases.iter().map(|alias| alias.to_string()).collect(),
            class: parent_type,
            is_virtual: funcdecl.is_virtual,
            args,
            annotations,
            original_body: funcdecl.body.clone(),
            body: None,
            declaration_file: Some(declaration_file),
            is_associated_call,
            is_derived: false,
            is_castable: true,
            callers: BTreeSet::new(),
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
        file: Option<&'a SimpleFile<String, String>>,
    ) -> Result<FunctionInfo<'a>, CascadeErrors> {
        let mut first_parent = None;
        let mut derived_body = Vec::new();
        let mut derived_is_associated_call = false;
        let mut derived_arg_names: Vec<BTreeSet<String>> = Vec::new();
        let mut derived_name_aliases = BTreeSet::new();

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
                            first_parent.declaration_file,
                            first_parent.get_declaration_range(),
                            parent_function.declaration_file,
                            parent_function.get_declaration_range(),
                        ) {
                            (
                                Some(first_file),
                                Some(first_range),
                                Some(second_file),
                                Some(second_range),
                            ) => {
                                return Err(CompileError::new(
                                        &format!("In attempting to derive {name}, parent functions do not have matching prototypes."),
                                        first_file,
                                        first_range,
                                        "This parent prototype...",
                                        ).add_additional_message(
                                            second_file,
                                            second_range,
                                            "...needs to match this parent prototype").into());
                            }
                            (_, _, _, _) => {
                                // TODO: One of the mismatched parent signatures is synthetic.
                                // Output an appropriate error message
                                todo!()
                            }
                        }
                    }
                    if derived_is_associated_call != parent_function.is_associated_call {
                        match (
                            first_parent.declaration_file,
                            first_parent.get_declaration_range(),
                            parent_function.declaration_file,
                            parent_function.get_declaration_range(),
                        ) {
                            (
                                Some(first_file),
                                Some(first_range),
                                Some(second_file),
                                Some(second_range),
                            ) => {
                                return Err(CompileError::new(
                                        &format!("In attempting to derive {name}, parent functions do not have matching prototypes."),
                                        first_file,
                                        first_range,
                                        "This parent is annotated with @associated_call...",
                                        ).add_additional_message(
                                            second_file,
                                            second_range,
                                            "...but this parent is not").into());
                            }
                            (_, _, _, _) => {
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
                    .original_body
                    .iter()
                    .map(|s| s.get_renamed_statement(&renames))
                    .collect(),
            );

            derived_name_aliases.append(&mut parent_function.name_aliases.clone());
        }

        let mut derived_args = match first_parent {
            Some(parent) => parent.args.clone(),
            None => {
                return Err(ErrorItem::make_compile_or_internal_error(
                    &format!("Unable to derive {name}, because it has no parent implementations"),
                    file,
                    name.get_range(),
                    &format!("Attempted to derive an implementation of {name}, but couldn't find any derivable parent implementations")).into());
                // TODO: A hint about the strategy might be useful
            }
        };

        for (arg, name) in derived_args.iter_mut().zip(derived_arg_names.iter()) {
            arg.name = name.iter().cloned().collect::<Vec<String>>().join("_");
        }

        Ok(FunctionInfo {
            name: name.to_string(),
            name_aliases: derived_name_aliases,
            class: FunctionClass::Type(deriving_type),
            is_virtual: false, // TODO: Check documentation for correct behavior here
            args: derived_args,
            annotations: BTreeSet::new(),
            original_body: derived_body,
            body: None,
            declaration_file: file,
            is_associated_call: derived_is_associated_call,
            is_derived: true,
            is_castable: true,
            callers: BTreeSet::new(),
            decl: None,
        })
    }

    pub fn get_cil_name(&self) -> String {
        match self.decl {
            Some(decl) => decl.get_cil_name(),
            None => get_cil_name(
                self.class.get_name(),
                &CascadeString::from(&self.name as &str),
            ),
        }
    }

    pub fn validate_body(
        &self,
        functions: &FunctionMap<'a>,
        types: &'a TypeMap,
        class_perms: &'a ClassList,
        context: &BlockContext<'_>,
    ) -> Result<WithWarnings<BTreeSet<ValidatedStatement<'a>>>, CascadeErrors> {
        let mut new_body = BTreeSet::new();
        let mut errors = CascadeErrors::new();
        let mut warnings = Warnings::new();
        let local_context = BlockContext::new_from_args(&self.args, self.class.into(), context);

        for statement in &self.original_body {
            // TODO: This needs to become global in a bit
            match ValidatedStatement::new(
                statement,
                functions,
                types,
                class_perms,
                &local_context,
                self.class,
                self.declaration_file,
            ) {
                Ok(s) => new_body.append(&mut s.inner(&mut warnings)),
                Err(e) => errors.append(e),
            }
        }
        let mut nv_rules = create_non_virtual_child_rules(&new_body, types);
        new_body.append(&mut nv_rules);
        errors.into_result(WithWarnings::new(new_body, warnings))
    }

    // Generate the sexp for a synthetic alias function calling the real function
    pub fn generate_synthetic_alias_call(&self, alias_cil_name: &str) -> sexp::Sexp {
        let call = ValidatedCall {
            cil_name: self.get_cil_name(),
            args: self
                .args
                .iter()
                .map(|a| CilArg::Name(a.name.clone()))
                .collect(),
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

    // Get the name of a call to this function for displaying to the user
    pub fn get_full_display_name(&self) -> String {
        match self.class.get_name() {
            Some(name) => format!("{}.{}", name, self.name),
            None => self.name.clone(),
        }
    }

    // Convert a symbol defined by the arguments of this function into the symbol a given caller
    // passed into it.  If the symbol is not the name of a function argument, return None
    pub fn symbol_to_caller_symbol(
        &self,
        symbol: &str,
        caller_args: &Vec<CilArg>,
    ) -> Option<String> {
        for (func_arg, caller_arg) in self.args.iter().zip(caller_args) {
            if func_arg.name == symbol {
                // We ignore perm lists, for no good reason.  This should probably return a CilArg
                // and let the parent unpack it
                if let CilArg::Name(caller_symbol) = caller_arg {
                    return Some(caller_symbol.clone());
                }
            }
        }
        None
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
                        ValidatedStatement::Deferred(d) => macro_cil.push(Sexp::from(d)),
                        ValidatedStatement::Sid(_) => {
                            return Err(InternalError::new().into());
                        }
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
        class_perms: &ClassList,
        context: &BlockContext<'a>,
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

        // Build a partial argument first, use it to validate the default, then complete it
        let mut ret = FunctionArgument {
            param_type,
            name: declared_arg.name.to_string(),
            is_list_param: declared_arg.is_list_param,
            default_value: None,
        };

        if let Some(default_arg) = &declared_arg.default {
            validate_argument(
                ArgForValidation::from(default_arg),
                &None,
                &ret,
                types,
                class_perms,
                context,
                file,
                false,
                None,
                None,
            )?;

            ret.default_value = declared_arg.default.clone();
        }
        Ok(ret)
    }

    pub fn new_this_argument(parent_type: &'a TypeInfo) -> Self {
        FunctionArgument {
            param_type: parent_type,
            name: "this".to_string(),
            is_list_param: false,
            default_value: None,
        }
    }

    pub fn has_default_value(&self) -> bool {
        self.default_value.is_some()
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

fn validate_cast(
    // Initial type we are casting from
    start_type: &CascadeString,
    // Type Info for what we are casting to
    // If cast_ti is Some() func_call and func_info
    // must also be Some()
    cast_ti: Option<&TypeInfo>,
    // Function call we are trying to use
    // the cast version of a function.
    func_call: Option<&FuncCall>,
    // Function info we are trying to use
    // the cast version of a function.
    func_info: Option<&FunctionInfo>,
    // Full type map
    types: &TypeMap,
    // Context block for the call
    context: &BlockContext,
    // File used for error output
    file: Option<&SimpleFile<String, String>>,
) -> Result<(), ErrorItem> {
    let err_ret = |msg: &str, r: Option<Range<usize>>| {
        ErrorItem::make_compile_or_internal_error(
            "Cannot typecast",
            file,
            r,
            format!("This is not something that can be typecast. {}", msg).as_ref(),
        )
    };

    if let Some(cast_ti_unwrap) = cast_ti {
        if !cast_ti_unwrap.is_setype(types) {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Not something we can cast to",
                file,
                cast_ti_unwrap.name.get_range(),
                "This must be a domain, resource or trait that exists in this policy",
            ));
        }
    }

    // If we are validating a function cast and it is a this.* function call
    // we need to get the real name first than look in the type map.
    let true_start_type = if func_call.is_some() && start_type.as_ref().starts_with("this.") {
        context.convert_arg_this(start_type.as_ref())
    } else {
        start_type.to_string()
    };

    let type_info = types
        .get(&true_start_type)
        .or_else(|| context.symbol_in_context(&true_start_type, types));
    if type_info.is_none() || !type_info.map(|ti| ti.is_setype(types)).unwrap_or(false) {
        return Err(err_ret("Could not resolve type", start_type.get_range()));
    }
    match (cast_ti, func_call, func_info) {
        (Some(cast_ti), Some(func_call), Some(func_info)) => {
            // If we can validate the inheritance then things are castable.  If we cannot
            // we need to check if the function itself is castable.
            if !validate_inheritance(func_call, type_info, &cast_ti.name, file)? {
                if func_info.is_castable {
                    Ok(())
                } else {
                    Err(ErrorItem::make_compile_or_internal_error(
                        "Not something we can cast to",
                        file,
                        func_call.get_name_range(),
                        "The function is not castable or inherited by caller",
                    ))
                }
            } else {
                Ok(())
            }
        }
        (Some(_), Some(_), None) => Err(ErrorItem::Internal(InternalError::new())),
        (Some(_), None, Some(_)) => Err(ErrorItem::Internal(InternalError::new())),
        (None, _, _) => Err(err_ret(
            "Could not resolve cast type",
            start_type.get_range(),
        )),
        (_, _, _) => Ok(()),
    }
}

// Validate that the parent provided both exists and is actually a parent of the current resource.
// This function will return:
//   true if classes exist and class_info does in fact inherit from the parent_name
//   false if the classes exist but class_info does not inherit from parent_name
//   Error if the classes do not exist.
fn validate_inheritance(
    call: &FuncCall,
    class_info: Option<&TypeInfo>,
    parent_name: &CascadeString,
    file: Option<&SimpleFile<String, String>>,
) -> Result<bool, ErrorItem> {
    match class_info {
        Some(class_info) => {
            if !class_info.inherits.contains(parent_name) && class_info.name != parent_name.as_ref()
            {
                return Ok(false);
            }
        }
        None => {
            return Err(ErrorItem::make_compile_or_internal_error(
                "No such type",
                file,
                call.get_name_range(),
                "",
            ));
        }
    };
    Ok(true)
}

// Take a list of VSs.  If any of them reference non-virtual children, make new VSs copied from
// the original, subbing in the names of the validated children
pub fn create_non_virtual_child_rules<'a>(
    statements: &BTreeSet<ValidatedStatement<'a>>,
    types: &'a TypeMap,
) -> BTreeSet<ValidatedStatement<'a>> {
    let mut ret = BTreeSet::new();
    for statement in statements {
        let mut rules = match statement {
            // The context built ins don't get copied
            // TODO: Consider if warning in that situation is too loud?
            // TODO: Calls calling context functions is a bigger issue than just this, but
            // could cause issues perhaps
            ValidatedStatement::Call(c) => c.create_non_virtual_child_rules(types),
            ValidatedStatement::AvRule(a) => a.create_non_virtual_child_rules(types),
            ValidatedStatement::ResourcetransRule(r) => r.create_non_virtual_child_rules(types),
            ValidatedStatement::DomtransRule(d) => d.create_non_virtual_child_rules(types),
            ValidatedStatement::FcRule(_)
            | ValidatedStatement::PortconRule(_)
            | ValidatedStatement::FscRule(_)
            | ValidatedStatement::Deferred(_)
            | ValidatedStatement::Sid(_) => BTreeSet::new(),
        };
        ret.append(&mut rules);
    }
    ret
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
    Deferred(DeferredStatement),
    Sid(Sid<'a>),
}

impl<'a> ValidatedStatement<'a> {
    pub fn new(
        statement: &Statement,
        functions: &FunctionMap<'a>,
        types: &'a TypeMap,
        class_perms: &ClassList<'a>,
        context: &BlockContext<'_>,
        parent_type: FunctionClass<'a>,
        file: Option<&'a SimpleFile<String, String>>,
    ) -> Result<WithWarnings<BTreeSet<ValidatedStatement<'a>>>, CascadeErrors> {
        let in_resource = match parent_type {
            FunctionClass::Type(t) => t.is_resource(types),
            FunctionClass::Collection(_) => false,
            FunctionClass::Global => false,
        };

        // check drop
        if let Statement::Call(c) = statement {
            if c.drop {
                // TODO: actually handle drop
                let range = match c.name.get_range() {
                    Some(r) => r,
                    None => return Err(InternalError::new().into()),
                };
                let mut ret = WithWarnings::from(BTreeSet::new());
                if let Some(file) = file {
                    // No need to warn if this is synthetic
                    ret.add_warning(Warning::new(
                        "Drop is not yet implemented",
                        file,
                        range,
                        "These permissions will be allowed",
                    ));
                }
                return Ok(ret);
            }
        }

        match statement {
            Statement::Call(c) => match c.check_builtin() {
                Some(BuiltIns::AvRule) => Ok(WithWarnings::from(
                    call_to_av_rule(c, types, class_perms, context, file)?
                        .into_iter()
                        .map(ValidatedStatement::AvRule)
                        .collect::<BTreeSet<ValidatedStatement>>(),
                )),
                Some(BuiltIns::FileContext) => {
                    if in_resource {
                        Ok(WithWarnings::from(
                            call_to_fc_rules(c, types, class_perms, context, file)?
                                .into_iter()
                                .map(ValidatedStatement::FcRule)
                                .collect::<BTreeSet<ValidatedStatement>>(),
                        ))
                    } else {
                        Err(CascadeErrors::from(
                            ErrorItem::make_compile_or_internal_error(
                                "file_context() calls are only allowed in resources",
                                file,
                                c.name.get_range(),
                                "Not allowed here",
                            ),
                        ))
                    }
                }
                Some(BuiltIns::ResourceTransition) => Ok(WithWarnings::from(
                    call_to_resource_transition(c, types, class_perms, context, file)?
                        .into_iter()
                        .map(ValidatedStatement::ResourcetransRule)
                        .collect::<BTreeSet<ValidatedStatement>>(),
                )),
                Some(BuiltIns::FileSystemContext) => {
                    if in_resource {
                        Ok(WithWarnings::from(
                            call_to_fsc_rules(c, types, class_perms, context, file)?
                                .into_iter()
                                .map(ValidatedStatement::FscRule)
                                .collect::<BTreeSet<ValidatedStatement>>(),
                        ))
                    } else {
                        Err(CascadeErrors::from(
                            ErrorItem::make_compile_or_internal_error(
                                "fs_context() calls are only allowed in resources",
                                file,
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
                        Ok(WithWarnings::from(
                            call_to_portcon_rules(c, types, class_perms, context, file)?
                                .into_iter()
                                .map(ValidatedStatement::PortconRule)
                                .collect::<BTreeSet<ValidatedStatement>>(),
                        ))
                    } else {
                        Err(CascadeErrors::from(
                            ErrorItem::make_compile_or_internal_error(
                                "portcon() calls are only allowed in resources",
                                file,
                                c.name.get_range(),
                                "Not allowed here",
                            ),
                        ))
                    }
                }
                Some(BuiltIns::InitialContext) => Ok(WithWarnings::from(
                    call_to_sids(c, types, class_perms, context, file)?
                        .into_iter()
                        .map(ValidatedStatement::Sid)
                        .collect::<BTreeSet<ValidatedStatement>>(),
                )),
                Some(BuiltIns::DomainTransition) => {
                    if !in_resource {
                        Ok(WithWarnings::from(
                            Some(ValidatedStatement::DomtransRule(call_to_domain_transition(
                                c,
                                types,
                                class_perms,
                                context,
                                file,
                            )?))
                            .into_iter()
                            .collect::<BTreeSet<ValidatedStatement>>(),
                        ))
                    } else {
                        Err(CascadeErrors::from(
                            ErrorItem::make_compile_or_internal_error(
                                "domain_transition() calls are not allowed in resources",
                                file,
                                c.name.get_range(),
                                "Not allowed here",
                            ),
                        ))
                    }
                }
                None => Ok(WithWarnings::from(
                    ValidatedCall::new(c, functions, types, class_perms, context, file)?
                        .into_iter()
                        .collect::<BTreeSet<ValidatedStatement>>(),
                )),
            },
            Statement::LetBinding(_) => {
                // Handled in parent
                Ok(WithWarnings::from(BTreeSet::default()))
            }
            Statement::IfBlock(i) => {
                // TODO, but silently skip for now
                // The plan would be to recurse and grab the ifs, store both variants
                // and then resolve the bools later
                let mut ret = WithWarnings::from(BTreeSet::<ValidatedStatement>::default());
                if let Some(file) = file {
                    // No need to warn if this is synthetic
                    ret.add_warning(Warning::new(
                        "If blocks are not yet implemented",
                        file,
                        i.keyword_range.clone(),
                        "All rules in this if block will be omitted",
                    ));
                }
                Ok(ret)
            }
            Statement::OptionalBlock(o) => {
                // For now, just include all statements (ie ignore the presence of optional)
                // Optional policy isn't fully designed yet, so the exact details of what needs to
                // happen here in the "real" case is TBD
                let mut out = BTreeSet::new();
                let mut warnings = Warnings::new();
                for s in &o.contents {
                    let vs = ValidatedStatement::new(
                        s,
                        functions,
                        types,
                        class_perms,
                        &BlockContext::new(BlockType::Optional, parent_type.into(), Some(context)),
                        parent_type,
                        file,
                    )?;
                    out.append(&mut vs.inner(&mut warnings));
                }
                Ok(WithWarnings::new(out, warnings))
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
            ValidatedStatement::Deferred(d) => Ok(Sexp::from(d)),
            // Sids in functions should error during validation.  Global SIDs are filtered out
            // before sexp generation
            ValidatedStatement::Sid(_) => Err(InternalError::new().into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeferredStatement {
    Call(DeferredCall),
    Validation, // TODO
}

impl DeferredStatement {
    // Copy into the parent context, converting argument names
    fn parent_copy(&self, caller_args: &Vec<CilArg>, orig_function: &FunctionInfo) -> Self {
        match self {
            DeferredStatement::Call(dc) => {
                DeferredStatement::Call(dc.parent_copy(caller_args, orig_function))
            }
            DeferredStatement::Validation => self.clone(),
        }
    }
}

impl From<&DeferredStatement> for sexp::Sexp {
    fn from(d: &DeferredStatement) -> sexp::Sexp {
        // These push their contents up the call tree to have effects elsewhere.  Here, we put a
        // note in the output for human reference and debugging
        match d {
            DeferredStatement::Call(c) => atom_s(&format!(
                ";Pushed to callers: ({}-{} {})",
                c.call_class_name,
                c.call_func_name,
                c.args
                    .iter()
                    .map(Sexp::from)
                    .map(|s| crate::sexp_internal::display_cil(&s))
                    .collect::<Vec<_>>()
                    .join(" ")
            )),
            DeferredStatement::Validation => todo!(),
        }
    }
}

// A call that can't be resolved inside a function, because it depends on knowledge about the
// callers.
// These are statements, but generate no sexp.
// Instead, they push a call up the call stack to all callers to the point where it is
// unambiguously resolvable
//
// A DeferredCall inside a function, generates a DeferredCall in the parent, which may propagate up
// until the symbol we are deferring on is unambigously resolvable.
// Functions calls are resolvable if we can unambiguously assign one function name to them.  A
// function call using an argument (eg "source.read()", where "source" is an argument name) can't
// be unambiguously resolved (even if the function has only one caller, there may be
// cross-compiling callers).  Once we propagate up to the actual symbol, we insert the call at that
// level.
//
// In the below struct, the fields correspond to a call of arg_name.call_func_name()
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeferredCall {
    call_func_name: CascadeString,
    call_class_name: CascadeString,
    // We know the parent function signature, so argument validation can be done before deferring
    args: Vec<CilArg>,
    // If this is true, this is the function that originally created this call.  If false, it's
    // propagated up from a child.  This is important because if it is false, then we already
    // propagated to our parents when working on the child
    original: bool,
}

impl DeferredCall {
    pub fn new(
        call_func_name: CascadeString,
        call_class_name: CascadeString,
        args: Vec<CilArg>,
    ) -> DeferredCall {
        DeferredCall {
            call_func_name,
            call_class_name,
            args,
            original: true,
        }
    }

    pub fn parent_copy(&self, caller_args: &Vec<CilArg>, orig_function: &FunctionInfo) -> Self {
        DeferredCall {
            call_func_name: self.call_func_name.clone(),
            call_class_name: orig_function
                .symbol_to_caller_symbol(self.call_class_name.as_ref(), caller_args)
                .unwrap_or(self.call_class_name.to_string())
                .into(),
            args: self
                .args
                .iter()
                .cloned()
                .map(|a| {
                    if let CilArg::Name(n) = a {
                        CilArg::Name(
                            orig_function
                                .symbol_to_caller_symbol(&n, caller_args)
                                .unwrap_or(n),
                        )
                    } else {
                        a
                    }
                })
                .collect(),
            original: false,
        }
    }

    pub fn call_class_name(&self) -> &CascadeString {
        &self.call_class_name
    }

    pub fn args(&self) -> &Vec<CilArg> {
        &self.args
    }

    // Make either a real or deferred call for the parent level
    pub fn make_parent_statement<'a>(
        &self,
        types: &TypeMap,
        current_function: &FunctionInfo,
        caller_info: &CallerInfo,
    ) -> ValidatedStatement<'a> {
        if types.get(self.call_class_name().as_ref()).is_some() {
            // We can resolve correctly at this level
            ValidatedStatement::Call(Box::new(ValidatedCall::from(self)))
        } else {
            ValidatedStatement::Deferred(DeferredStatement::Call(
                self.parent_copy(&caller_info.passed_args, current_function),
            ))
        }
    }
}

// Make a validated call from the DeferredCall.  In order for this to be valid, all the symbols
// must be valid where it applies.  Importantly, cil_name must refer to a real function.
impl From<&DeferredCall> for ValidatedCall {
    fn from(dc: &DeferredCall) -> Self {
        ValidatedCall {
            cil_name: get_cil_name(Some(&dc.call_class_name), &dc.call_func_name),
            args: dc.args.clone(),
        }
    }
}

pub fn propagate(
    func_name: String,
    deferral: DeferredStatement,
    functions: &mut FunctionMap,
    types: &TypeMap,
) -> Result<(), CascadeErrors> {
    let this_fi = functions
        .get(&func_name)
        .ok_or_else(|| CascadeErrors::from(ErrorItem::Internal(InternalError::new())))?;
    // Clone so that we can keep the callers without keeping a reference to functions
    let callers = this_fi.callers.clone();

    for c in callers {
        // We have to shadow this in the loop so that we won't hold the immutable borrow over the
        // mutation below
        let this_fi = functions
            .get(&func_name)
            .ok_or_else(|| CascadeErrors::from(ErrorItem::Internal(InternalError::new())))?;
        let caller_dc_copy = deferral.parent_copy(
            &c.passed_args,
            functions
                .get(&func_name)
                .ok_or_else(|| CascadeErrors::from(ErrorItem::Internal(InternalError::new())))?,
        );
        match &caller_dc_copy {
            DeferredStatement::Call(dc) => {
                let mut done = false;
                let to_insert = dc.make_parent_statement(types, this_fi, &c);
                if matches!(to_insert, ValidatedStatement::Call(_)) {
                    done = true;
                }
                {
                    let caller_fi = functions.get_mut(c.caller_name.as_ref()).ok_or_else(|| {
                        CascadeErrors::from(ErrorItem::Internal(InternalError::new()))
                    })?;
                    caller_fi
                        .body
                        .as_mut()
                        .ok_or_else(|| {
                            CascadeErrors::from(ErrorItem::Internal(InternalError::new()))
                        })?
                        .insert(to_insert);
                    if done {
                        continue;
                    }
                }
            }
            DeferredStatement::Validation => {
                // For future use
            }
        }
        propagate(
            c.caller_name.to_string(),
            deferral.parent_copy(
                &c.passed_args,
                functions.get(&func_name).ok_or_else(|| {
                    CascadeErrors::from(ErrorItem::Internal(InternalError::new()))
                })?,
            ),
            functions,
            types,
        )?;
    }
    Ok(())
}

// There are two cases we pass through to CIL:
// 1. A single identifier (type, class or name)
// 3. A classpermissionset
// Note that at the CIL level, classes and permissions go together, whereas in Cascade, they can be
// handled separately.  The implication here is that to pass a list of permissions, we need to pass
// a class along with them.  There are three cases:
// 1. In the function, the permissions are used with exactly one class
// 2. In the function, the permissions are used with several classes but are valid for all
// 3. The permissions are not valid for some of the listed classes
// In case 1, the function definition should assume the class will be passed in, and the call(s)
// should pass the set of class with permissions
// In case 2, the caller should generate a classmapping for the combined set of classes and perms
// In case 3, validate_argument() is responsible to detect this and return a compile error
//
// A list of classes should be expanded to multiple calls on a single class
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CilArg {
    Name(String),
    // class, permissions
    PermList(String, Vec<String>),
}

impl From<&CilArg> for sexp::Sexp {
    fn from(arg: &CilArg) -> Self {
        match arg {
            CilArg::Name(s) => atom_s(s),
            CilArg::PermList(c, p) => {
                let p: Vec<CascadeString> =
                    p.iter().map(|s| CascadeString::from(s as &str)).collect();
                list(&[atom_s(c), Sexp::List(perm_list_to_sexp(&p))])
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValidatedCall {
    pub cil_name: String,
    pub args: Vec<CilArg>,
}

impl ValidatedCall {
    // Might return a DeferredCall instead
    // Probably the "correct" thing to do here is make ValidatedCall an enum, with a deferred
    // variant, but that can be future work
    #[allow(clippy::new_ret_no_self)]
    pub fn new<'nothing>(
        call: &FuncCall,
        functions: &FunctionMap<'_>,
        types: &TypeMap,
        class_perms: &ClassList,
        context: &BlockContext,
        file: Option<&SimpleFile<String, String>>,
    ) -> Result<BTreeSet<ValidatedStatement<'nothing>>, CascadeErrors> {
        // If we have gotten into the state where the class name is none
        // but the cast_name is some, something has gone wrong.
        if call.class_name.is_none() && call.cast_name.is_some() {
            return Err(ErrorItem::Internal(InternalError::new()).into());
        }

        let cil_name = resolve_true_cil_name(call, context, types, file, functions)?;

        let function_info = match functions.get(&cil_name) {
            Some(function_info) => function_info,
            None => {
                return Err(make_no_such_function_error(file, call, types, context));
            }
        };

        if function_info.is_virtual {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Invalid call to virtual function",
                file,
                call.get_name_range(),
                "This function is marked as virtual, so it can't be called.",
            )
            .into());
        }

        if let Some(cast_name) = &call.cast_name {
            if let Some(class_name) = &call.class_name {
                validate_cast(
                    class_name,
                    types.get(cast_name.as_ref()),
                    Some(call),
                    Some(function_info),
                    types,
                    context,
                    file,
                )?;
            }
        }

        let mut defer = None;

        // If the resolved name is an argument, we should defer instead of trying to find a
        // function
        // Note that we need to have validated the function exists first.  The above lookup is
        // being done against the argument type, which may be a parent function.
        if let Some(orig_name) = call.cast_name.as_ref().or(call.class_name.as_ref()) {
            // 'this' is technically an argument, but it locally resolvable
            if orig_name.as_ref() != "this" && context.symbol_is_arg(orig_name.as_ref()) {
                defer = Some((&call.name, orig_name));
            }
        }

        let args = match (&call.class_name, function_info.class) {
            (Some(class_name), FunctionClass::Type(_)) => {
                vec![CilArg::Name(
                    context
                        .symbol_in_context(class_name.as_ref(), types)
                        .map(|ti| &ti.name)
                        .unwrap_or(&CascadeString::from(
                            context.convert_arg_this(class_name.as_ref()),
                        ))
                        .get_cil_name(),
                )]
            }
            _ => Vec::new(),
        };

        let mut arg_lists = Vec::new();
        arg_lists.push(args);

        for arg in validate_arguments(
            call,
            &function_info.args,
            types,
            class_perms,
            context,
            file,
            Some(function_info),
            Some(functions),
        )? {
            // We don't know if these are symbols or lists.
            // If they are symbols, we save them as CilArg::Name
            // If they are lists, then we either need to explode our calls to the list count, or in
            // specifically the list of perms case, we need to construct a classpermissionset
            if let Ok(arg) = arg.get_name_or_string(context) {
                for args in &mut arg_lists {
                    args.push(CilArg::Name(arg.to_string()));
                }
            } else if let Ok(list) = arg.get_list(context) {
                // Below is the not perm-set case
                arg_lists = expand_arg_lists(arg_lists, list);
                // TODO: Add support for the perm-set case
            } else {
                // Should not be possible, since get_name_or_string() and get_list() collectively
                // should be comprehensive returning Ok() on TypeValue
                return Err(InternalError::new().into());
            }
        }

        let mut ret = BTreeSet::new();
        for args in arg_lists {
            ret.insert(match defer {
                None => ValidatedStatement::Call(Box::new(ValidatedCall {
                    cil_name: cil_name.clone(),
                    args,
                })),
                Some((call_name, arg_name)) => {
                    ValidatedStatement::Deferred(DeferredStatement::Call(DeferredCall::new(
                        call_name.clone(),
                        arg_name.clone(),
                        args,
                    )))
                }
            });
        }

        Ok(ret)
    }

    pub fn create_non_virtual_child_rules<'a>(
        &self,
        types: &TypeMap,
    ) -> BTreeSet<ValidatedStatement<'a>> {
        let mut ret: BTreeSet<ValidatedStatement> = BTreeSet::new();
        for (index, arg) in self.args.iter().enumerate() {
            if let CilArg::Name(arg) = arg {
                let nv_children = types
                    .get(arg)
                    .map(|ti| ti.non_virtual_children.clone())
                    .unwrap_or_default();
                for nv_child in nv_children {
                    let mut new_call: ValidatedCall = self.clone();
                    // This feels weird on two levels, but I believe it to be safe.
                    // 1. Explicit indexing - This is guaranteed not to panic because new_call.args is
                    //    a clone of self.args, so they are definitely the same length
                    // 2. We validated the call already.  Does this child validate?  Should be "yes",
                    //    because if the parent can validate the child can
                    new_call.args[index] = CilArg::Name(nv_child.to_string());
                    // There may be more children to resolve, so we call recursively
                    // This is guaranteed to terminate, because the typemap has been checked for
                    // inheritance loops already
                    let mut recursive_rules = new_call.create_non_virtual_child_rules(types);
                    if recursive_rules.is_empty() {
                        // new_call didn't need anymore resolution
                        ret.insert(ValidatedStatement::Call(Box::new(new_call)));
                    } else {
                        // We generated new rules from new_call, so we can discard it and use those
                        // instead
                        ret.append(&mut recursive_rules);
                    }
                }
            }
        }
        ret
    }
}

fn make_no_such_function_error(
    file: Option<&SimpleFile<String, String>>,
    call: &FuncCall,
    types: &TypeMap,
    context: &BlockContext,
) -> CascadeErrors {
    let true_name = match call.get_true_class_name(context, types, file) {
        Ok(n) => n,
        Err(_) => {
            // We just called this from resolve_true_cil_name() and should have already errored
            // out
            return ErrorItem::Internal(InternalError::new()).into();
        }
    };
    // The below only works if it's a member function of a type
    if types.get(&true_name).is_none() {
        let range = match &call.cast_name {
            Some(cast_name) => cast_name.get_range(),
            None => call.get_name_range(),
        };
        return CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
            "No such type",
            file,
            range,
            "",
        ));
    }
    if let Some(class_name) = &call.class_name {
        let func_definer = if let Some(cast_name) = &call.cast_name {
            cast_name
        } else {
            class_name
        };
        CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
            "No such member function",
            file,
            call.name.get_range(),
            &format!(
                "{} does not define a function named {}",
                &func_definer, &call.name
            ),
        ))
    } else {
        CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
            "No such function",
            file,
            call.get_name_range(),
            "",
        ))
    }
}

// Turns an arg list like: (arg1, [arg2 arg3]) into:
// (arg1, arg2) and (arg1, arg3)
fn expand_arg_lists(
    existing_lists: Vec<Vec<CilArg>>,
    next_arg_list: Vec<CascadeString>,
) -> Vec<Vec<CilArg>> {
    let mut new_arg_lists = Vec::new();
    for existing_args in existing_lists {
        for next_arg in &next_arg_list {
            let mut new_arg_list = existing_args.clone();
            new_arg_list.push(CilArg::Name(next_arg.to_string()));
            new_arg_lists.push(new_arg_list);
        }
    }
    new_arg_lists
}

#[allow(clippy::too_many_arguments)]
pub fn validate_arguments<'a>(
    call: &'a FuncCall,
    function_args: &[FunctionArgument],
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'a>,
    // The file we're validating in
    // *NOT* the function definition file
    file: Option<&'a SimpleFile<String, String>>,
    // target_func_info and func_map will be None for built-ins
    target_func_info: Option<&'a FunctionInfo>,
    func_map: Option<&FunctionMap>,
) -> Result<Vec<TypeInstance<'a>>, CascadeErrors> {
    // Member functions start with an invisible"this" argument.  If it does, skip it
    let function_args_iter = function_args.iter().skip_while(|a| a.name == "this");

    let function_args_len = if function_args.iter().take(1).any(|f| f.name == "this") {
        function_args.len() - 1
    } else {
        function_args.len()
    };

    // Implicit this: If the function has exactly one argument which is not optional, and the function is called with
    // 0 arguments, pass this as the single argument
    let implicit_this_args = if let Some(parent_type) = context.get_parent_type_name() {
        vec![(Argument::Var(parent_type), None)]
    } else {
        Vec::new()
    };

    // Allow len() == 0 instead of is_empty().  It's clearer when compared to another len check
    // here
    #[allow(clippy::len_zero)]
    let call_args = if function_args_len == 1
        && call.args.len() == 0
        && !function_args.iter().any(|a| a.has_default_value())
    {
        &implicit_this_args
    } else {
        &call.args
    };

    // Validate the number of arguments.  A function with default values may have calls with
    // various numbers of arguments.  There are three cases here:
    // 1. If the call has < arguments than the non-default declared arguments, that's an error
    // 2. If the call has >= arguments than non-default declared arguments and <= arguments to
    //    total declared arguments, then length is okay and we continue with validation to
    //    determine whether those arguments match the expected types
    // 3. If the call has > arguments vs the total number of declared arguments, regardless of
    //    default values, that's an error

    if function_args_iter
        .clone()
        .take_while(|a| matches!(a.default_value, None))
        .count()
        > call_args.len()
        || function_args_len < call_args.len()
    {
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
    for (call_arg, decl_arg) in call_args
        .iter()
        .take_while(|a| !matches!(a.0, Argument::Named(_, _)))
        .zip(args.iter_mut())
    {
        let validated_arg = validate_argument(
            ArgForValidation::from(&call_arg.0),
            &call_arg.1,
            decl_arg.function_arg,
            types,
            class_perms,
            context,
            file,
            call.is_avc(),
            target_func_info,
            func_map,
        )?;
        decl_arg.provided_arg = Some(validated_arg);
    }

    for a in call_args
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
                    target_func_info,
                    func_map,
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
                    // We validated the default argument at function signature creation time.
                    // That's helpful, because the function may be derived, so it's hard to know
                    // its file now.  If it fails here, that's an internal error
                    Some(v) => validate_argument(
                        ArgForValidation::from(v),
                        &None,
                        a.function_arg,
                        types,
                        class_perms,
                        context,
                        target_func_info.and_then(|f| f.declaration_file),
                        call.is_avc(),
                        target_func_info,
                        func_map,
                    )
                    .map_err(|_| InternalError::new())?,
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
#[derive(Debug)]
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

    pub fn get_range(&self) -> Option<Range<usize>> {
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
    fn validate_argcast(
        &self,
        cast_ti: &TypeInstance,
        types: &TypeMap,
        context: &BlockContext<'a>,
        file: Option<&SimpleFile<String, String>>,
    ) -> Result<(), ErrorItem> {
        let err_ret = |msg: &str, r: Option<Range<usize>>| {
            ErrorItem::make_compile_or_internal_error(
                format!("Cannot typecast {}", msg).as_ref(),
                file,
                r,
                "This is not something that can be typecast",
            )
        };

        match self {
            ArgForValidation::Var(s) => {
                return validate_cast(
                    s,
                    Some(cast_ti.type_info.borrow()),
                    None,
                    None,
                    types,
                    context,
                    file,
                );
            }
            ArgForValidation::List(v) => {
                for s in v {
                    // TODO: report more than just the first error
                    validate_cast(
                        s,
                        Some(cast_ti.type_info.borrow()),
                        None,
                        None,
                        types,
                        context,
                        file,
                    )?;
                }
            }
            ArgForValidation::Quote(inner) => {
                return Err(err_ret("Quote", inner.get_range()));
            }
            ArgForValidation::Port(inner) => {
                return Err(err_ret("Port", inner.get_range()));
            }
            ArgForValidation::IpAddr(inner) => {
                return Err(err_ret("Ip Address", inner.get_range()));
            }
        }

        Ok(())
    }

    // Return true if this is a symbol which binds to a list, else false
    pub fn is_list_symbol(&self, context: &BlockContext) -> bool {
        if let ArgForValidation::Var(s) = self {
            context.symbol_is_list(s.as_ref())
        } else {
            false
        }
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
    func_info: Option<&FunctionInfo>,
    func_map: Option<&FunctionMap>,
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
            func_info,
            func_map,
        )?;
        arg.validate_argcast(&cast_ti, types, context, file)?;

        return Ok(TypeInstance::new_cast_instance(
            &arg,
            argument_to_typeinfo(
                &arg,
                types,
                class_perms,
                Some(target_argument.param_type),
                context,
                file,
            )?,
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
            let arg_typeinfo_vec = argument_to_typeinfo_vec(
                v,
                types,
                class_perms,
                Some(target_argument.param_type),
                context,
                file,
            )?;

            for (arg_ti, arg) in arg_typeinfo_vec.iter().zip(v.iter()) {
                if !arg_ti.is_child_or_actual_type(target_argument.param_type, types) {
                    return Err(ErrorItem::make_compile_or_internal_error(
                        &format!("Expected type inheriting {}", target_ti.name),
                        file,
                        arg.get_range(),
                        &format!("This type should inherit {}", target_ti.name),
                    ));
                }
            }
            Ok(TypeInstance::new(&arg, target_ti, file, context))
        }
        _ => {
            let arg_typeinfo = argument_to_typeinfo(
                &arg,
                types,
                class_perms,
                Some(target_argument.param_type),
                context,
                file,
            )?;
            if target_argument.is_list_param {
                if arg_typeinfo.list_coercion
                    || arg.is_list_symbol(context)
                    // Automatically coerce everything in annotations
                    || context.in_annotation()
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
                        func_info,
                        func_map,
                    );
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
                Err(validate_argument_error_handler(
                    arg,
                    arg_typeinfo,
                    target_argument,
                    types,
                    file,
                    func_info,
                    func_map,
                ))
            }
        }
    }
}

// Helper function for handling the error case for validate_argument.
fn validate_argument_error_handler(
    arg: ArgForValidation,
    arg_typeinfo: &TypeInfo,
    target_argument: &FunctionArgument,
    types: &TypeMap,
    file: Option<&SimpleFile<String, String>>,
    func_info: Option<&FunctionInfo>,
    func_map: Option<&FunctionMap>,
) -> ErrorItem {
    // If func_info is none, which means we are validating a built in and cannot be an associated call,
    // or the call is not an asociated one fall through and return the "standard" error.
    // If this is the associated call we need to do some more digging to give the user a better
    // error message.
    // Unwraps of func_info are safe in this block because of the false return on map_or
    if func_info.map_or(false, |f| f.is_associated_call) {
        let mut error = ErrorItem::make_compile_or_internal_error(
            &format!(
                "Expected type inheriting {} for associated call",
                target_argument.param_type.name
            ),
            arg_typeinfo.get_file().as_ref(),
            arg_typeinfo.name.get_range(),
            &format!(
                "An associated call: '{}' was made for this domain.  That call requires this domain inherit {}",
                func_info.unwrap().name, target_argument.param_type.name
            ),
        );
        if let (Some(file), Some(range)) = (
            func_info.unwrap().declaration_file,
            func_info.unwrap().get_name_range(),
        ) {
            // We have a valid file name so we can put the associated function directly into the error
            if !file.name().is_empty() {
                if let ErrorItem::Compile(e) = error {
                    error = ErrorItem::Compile(e.add_additional_message(
                        file,
                        range,
                        "Associated function found here",
                    ));
                }
                return error;
            }
        }

        // The file name is not valid so we have to go looking through our parents to find out where
        // we are called from.
        if let Some(class) = types.get(
            func_info
                .unwrap()
                .class
                .get_name()
                .unwrap_or(&CascadeString::from(""))
                .as_ref(),
        ) {
            for parent in &class.inherits {
                if let (Some(parent), Some(func_map)) = (types.get(parent.as_ref()), func_map) {
                    if let Some(f) =
                        find_func_in_ancestor(parent, types, &func_info.unwrap().name, func_map)
                    {
                        if let (Some(file), Some(range)) =
                            (f.declaration_file, f.get_declaration_range())
                        {
                            if let ErrorItem::Compile(e) = error {
                                error = ErrorItem::Compile(e.add_additional_message(
                                    file,
                                    range,
                                    "Associated function found here",
                                ));
                            }
                            return error;
                        }
                    }
                }
            }
        }
        // We should never hit this but just in case
        return error;
    }

    ErrorItem::make_compile_or_internal_error(
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
    )
}

fn find_func_in_ancestor<'a>(
    type_info: &'a TypeInfo,
    types: &'a TypeMap,
    func_name: &String,
    func_map: &'a FunctionMap<'a>,
) -> Option<&'a FunctionInfo<'a>> {
    // First look at the type passed in
    for f in func_map.values_by_index(type_info.name.to_string()) {
        // If our range is None that means we are looking at the synthetic function not the "real" one
        if f.name == func_name.as_ref() && f.get_declaration_range().is_some() {
            return Some(f);
        }
    }

    // If we dont find it there start looking at our parents
    for parent in &type_info.inherits {
        if let Some(parent) = types.get(parent.as_ref()) {
            return find_func_in_ancestor(parent, types, func_name, func_map);
        }
    }

    // If we have fallen through return None
    None
}

impl From<&ValidatedCall> for sexp::Sexp {
    fn from(call: &ValidatedCall) -> sexp::Sexp {
        let args = call.args.iter().map(Sexp::from).collect::<Vec<Sexp>>();

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

// Go through all functions and check if they are castable
// based only on their args
pub fn initialize_castable(functions: &mut FunctionMap, types: &TypeMap) {
    for func in functions.values_mut() {
        for arg in &func.args {
            if arg.param_type.is_associated_resource(types) {
                func.is_castable = false;

                // If we have found one associated resource
                // we can continue
                continue;
            }
        }
    }
}

// Go through all of the functions and check if they are castable
// base on functions they call.
pub fn determine_castable(functions: &mut FunctionMap, types: &TypeMap) -> u64 {
    let mut num_changed: u64 = 0;
    // We need tmp_functions to avoid a immutable borrow after a mutable one.
    let tmp_functions = functions.clone();
    'outer: for func in functions.values_mut() {
        // If we are already false there is no reason to check our called functions.
        if !func.is_castable {
            continue;
        }
        for call in &func.original_body {
            if let Statement::Call(call) = call {
                if let Some(inner_func) = tmp_functions.get(&call.get_cil_name()) {
                    if !inner_func.is_castable {
                        num_changed += 1;
                        func.is_castable = false;
                        continue 'outer;
                    }
                }
                for arg in &call.args {
                    if let Argument::Var(arg) = &arg.0 {
                        // Need to special case this.*
                        if arg.to_string().contains("this.") {
                            num_changed += 1;
                            func.is_castable = false;
                            continue 'outer;
                        }
                        if let Some(ti) = types.get(arg.as_ref()) {
                            if ti.is_associated_resource(types) {
                                num_changed += 1;
                                func.is_castable = false;
                                continue 'outer;
                            }
                        }
                    }
                }
            }
        }
    }
    num_changed
}

pub fn initialize_terminated<'a>(
    functions: &'a FunctionMap<'a>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut term_ret_vec: BTreeSet<String> = BTreeSet::new();
    let mut nonterm_ret_vec: BTreeSet<String> = BTreeSet::new();

    for func in functions.values() {
        let mut is_term = true;

        let func_calls = get_all_func_calls(&func.original_body);

        for call in func_calls {
            if call.check_builtin().is_none() {
                is_term = false;
                break;
            }
        }
        if is_term {
            term_ret_vec.insert(func.get_cil_name().clone());
        } else {
            nonterm_ret_vec.insert(func.get_cil_name().clone());
        }
    }

    (term_ret_vec, nonterm_ret_vec)
}

// Helper function to ressolve the "true" name of a function
// given the FuncCall (the Function we are looking to get the true cil name),
// Context it is called in and FunctionMap (all FunctionInfos).
// If the function call needs to be cast this will handle that.  This function will not
// validate the cast that is done else where.
// If the function call has a "this" class or no class, it will substitue the class of
// the caller
// Lastely if the function is type aliased this function will resolve the alias.
fn resolve_true_cil_name(
    call: &FuncCall,
    context: &BlockContext,
    types: &TypeMap,
    file: Option<&SimpleFile<String, String>>,
    function_map: &FunctionMap,
) -> Result<String, CascadeErrors> {
    let true_call_class = call.get_true_class_name(context, types, file)?;
    let original_cil_name = get_cil_name(Some(&CascadeString::from(true_call_class)), &call.name);

    // Deal with aliases
    if let Some(call_func_info) = function_map.get(&original_cil_name) {
        return Ok(call_func_info.get_cil_name());
    }

    Ok(original_cil_name)
}

// Search through the non terminating functions to find loops
fn find_recursion_loop(
    func: &str,
    function_map: &FunctionMap,
    terminated_list: &BTreeSet<String>,
    visited: &mut BTreeSet<String>,
    types: &TypeMap,
) -> Result<BTreeSet<String>, CascadeErrors> {
    visited.insert(func.to_string());
    if let Some(function_info) = function_map.get(func) {
        let func_context = BlockContext::new(BlockType::Function, function_info.class.into(), None);
        let func_calls = get_all_func_calls(&function_info.original_body);
        for call in func_calls {
            if call.check_builtin().is_some() {
                continue;
            }
            let call_cil_name = resolve_true_cil_name(
                call,
                &func_context,
                types,
                function_info.declaration_file,
                function_map,
            )?;

            if terminated_list.contains(&call_cil_name) {
                continue;
            } else if visited.contains(&call_cil_name) {
                break;
            // If we cannot resolve the function continue.  It is not our job here
            // to confirm if a function exists or not, that will be caught later.
            } else if function_map.get(&call_cil_name).is_none() {
                continue;
            } else {
                return find_recursion_loop(
                    &call_cil_name,
                    function_map,
                    terminated_list,
                    visited,
                    types,
                );
            }
        }
    }
    Ok(visited.clone())
}

pub fn search_for_recursion(
    terminated_list: &mut BTreeSet<String>,
    functions: &mut BTreeSet<String>,
    types: &TypeMap,
    function_map: &FunctionMap,
) -> Result<(), CascadeErrors> {
    let mut removed: u64 = 1;
    while removed > 0 {
        removed = 0;
        for func in functions.clone().iter() {
            let mut is_term = true;
            if let Some(function_info) = function_map.get(func) {
                let func_context =
                    BlockContext::new(BlockType::Function, function_info.class.into(), None);
                let func_calls = get_all_func_calls(&function_info.original_body);
                for call in func_calls {
                    if call.check_builtin().is_some() {
                        continue;
                    }
                    let call_cil_name = resolve_true_cil_name(
                        call,
                        &func_context,
                        types,
                        function_info.declaration_file,
                        function_map,
                    )?;
                    if !terminated_list.contains(&call_cil_name)
                        && function_map.get(&call_cil_name).is_some()
                    {
                        is_term = false;
                        break;
                    }
                }
                if is_term {
                    terminated_list.insert(function_info.get_cil_name());
                    removed += 1;
                    functions.remove(&function_info.get_cil_name());
                }
            }
        }
    }

    if !functions.is_empty() {
        let mut loops: Vec<BTreeSet<String>> = Vec::new();

        for func in functions.iter() {
            loops.push(find_recursion_loop(
                func,
                function_map,
                terminated_list,
                &mut BTreeSet::new(),
                types,
            )?);
        }

        // Unwrap is safe, if we are here functions must have at least one element, which means loops must
        // have at least one element
        let smallest_loop = loops.iter().min_by(|x, y| x.len().cmp(&y.len())).unwrap();

        let mut previous_function: String = String::new();
        let mut error: Option<CompileError> = None;
        for func in smallest_loop {
            if let Some(function_info) = function_map.get(func) {
                if let (Some(file), Some(range)) = (
                    function_info.declaration_file,
                    function_info.get_declaration_range(),
                ) {
                    // This is the start of the loop, so we want a slightly different message
                    if error.is_none() {
                        error = Some(add_or_create_compile_error(
                            error,
                            "Recursive Function call found",
                            file,
                            range,
                            "This function is the start of the loop.  There may be additional loops once this is resolved.",
                        ));
                        previous_function = function_info.get_full_display_name();
                    } else {
                        error = Some(add_or_create_compile_error(
                            error,
                            "Recursive Function call found",
                            file,
                            range,
                            &format!(
                                "This function calls the next function: {}.",
                                previous_function
                            ),
                        ));
                        previous_function = function_info.get_full_display_name();
                    }
                } else {
                    return Err(InternalError::new().into());
                }
            }
        }

        // Unwrap is safe since we need to go through the loop above at least once
        return Err(CascadeErrors::from(error.unwrap()));
    }

    Ok(())
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
        let mut warnings = Warnings::new();
        let some_file = SimpleFile::new("bar".to_string(), "bar".to_string());
        let mut fi = FunctionInfo {
            name: "foo".to_string(),
            name_aliases: BTreeSet::new(),
            class: FunctionClass::Global,
            is_virtual: false,
            args: Vec::new(),
            annotations: BTreeSet::new(),
            original_body: Vec::new(),
            body: None,
            declaration_file: Some(&some_file),
            is_associated_call: false,
            is_derived: false,
            is_castable: true,
            callers: BTreeSet::new(),
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
        .unwrap()
        .inner(&mut warnings);

        fi.class = FunctionClass::Type(&ti);

        assert_eq!(&fi.get_cil_name(), "bar-foo");
        assert!(warnings.is_empty());
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

    #[test]
    fn expand_arg_list_test() {
        let existing_lists = vec![Vec::new()];
        let next_arg_list = vec![
            CascadeString::from("foo".to_string()),
            CascadeString::from("bar".to_string()),
        ];

        let mut expanded_list = expand_arg_lists(existing_lists, next_arg_list);

        assert_eq!(
            expanded_list,
            vec![
                vec![CilArg::Name("foo".to_string())],
                vec![CilArg::Name("bar".to_string())]
            ]
        );

        let second_arg_list = vec![
            CascadeString::from("baz".to_string()),
            CascadeString::from("qux".to_string()),
        ];
        expanded_list = expand_arg_lists(expanded_list, second_arg_list);

        assert_eq!(
            expanded_list,
            vec![
                vec![
                    CilArg::Name("foo".to_string()),
                    CilArg::Name("baz".to_string())
                ],
                vec![
                    CilArg::Name("foo".to_string()),
                    CilArg::Name("qux".to_string())
                ],
                vec![
                    CilArg::Name("bar".to_string()),
                    CilArg::Name("baz".to_string())
                ],
                vec![
                    CilArg::Name("bar".to_string()),
                    CilArg::Name("qux".to_string())
                ],
            ]
        )
    }

    #[test]
    fn symbol_to_caller_symbol_test() {
        let ti = TypeInfo::make_built_in("foo".to_string(), false);
        let fi = FunctionInfo {
            name: "foo".to_string(),
            name_aliases: BTreeSet::new(),
            class: FunctionClass::Global,
            is_virtual: false,
            args: vec![
                FunctionArgument {
                    param_type: &ti,
                    name: "a".to_string(),
                    is_list_param: false,
                    default_value: None,
                },
                FunctionArgument {
                    param_type: &ti,
                    name: "b".to_string(),
                    is_list_param: false,
                    default_value: None,
                },
                FunctionArgument {
                    param_type: &ti,
                    name: "c".to_string(),
                    is_list_param: false,
                    default_value: None,
                },
            ],
            annotations: BTreeSet::new(),
            // doesn't matter here
            original_body: Vec::new(),
            body: None,
            declaration_file: None,
            is_associated_call: false,
            is_derived: false,
            is_castable: false,
            callers: BTreeSet::new(),
            decl: None,
        };

        let caller_args = vec![
            CilArg::Name("c1".to_string()),
            CilArg::Name("c2".to_string()),
            CilArg::Name("c3".to_string()),
        ];

        assert_eq!(
            fi.symbol_to_caller_symbol("a", &caller_args),
            Some("c1".to_string())
        );
        assert_eq!(
            fi.symbol_to_caller_symbol("b", &caller_args),
            Some("c2".to_string())
        );
        assert_eq!(
            fi.symbol_to_caller_symbol("c", &caller_args),
            Some("c3".to_string())
        );
        assert_eq!(fi.symbol_to_caller_symbol("d", &caller_args), None);
    }
}
