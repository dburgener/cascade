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

use crate::ast::{
    get_cil_name, Annotation, Annotations, Argument, BuiltIns, CascadeString, DeclaredArgument,
    FuncCall, FuncDecl, Module, Statement, TypeDecl,
};
use crate::constants;
use crate::context::{BlockType, Context as BlockContext};
use crate::error::{CascadeErrors, CompileError, ErrorItem, InternalError, InvalidFileSystemError};
use crate::obj_class::perm_list_to_sexp;

const DEFAULT_USER: &str = "system_u";
const DEFAULT_OBJECT_ROLE: &str = "object_r";
const DEFAULT_DOMAIN_ROLE: &str = "system_r";
const DEFAULT_MLS: &str = "s0";

#[derive(Clone, Debug)]
pub struct AliasMap<T> {
    declarations: BTreeMap<String, T>,
    #[allow(dead_code)]
    aliases: BTreeMap<String, String>,
}

pub type TypeMap = AliasMap<TypeInfo>;
pub type AliasMapIter<'a, T> = std::collections::btree_map::Iter<'a, String, T>;
pub type AliasMapValues<'a, T> = std::collections::btree_map::Values<'a, String, T>;
pub type AliasMapValuesMut<'a, T> = std::collections::btree_map::ValuesMut<'a, String, T>;
pub type AliasMapIntoIter<T> = std::collections::btree_map::IntoIter<String, T>;

impl<T: Declared> AliasMap<T> {
    fn get_type_name<'a>(aliases: &'a BTreeMap<String, String>, key: &'a str) -> &'a str {
        if aliases.contains_key(key) {
            &aliases[key]
        } else {
            key
        }
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        let type_name = Self::get_type_name(&self.aliases, key);
        self.declarations.get(type_name)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut T> {
        let type_name = Self::get_type_name(&self.aliases, key);
        self.declarations.get_mut(type_name)
    }

    pub fn new() -> Self {
        AliasMap {
            declarations: BTreeMap::new(),
            aliases: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: String, value: T) -> Result<(), CascadeErrors> {
        // try_insert() is nightly only.  Convert once stable.
        if let Some(orig_decl) = self.get(&key) {
            // If the file is None, this is a synthetic type, and we should have handled
            // the error earlier.
            let mut error = ErrorItem::make_compile_or_internal_error(
                "Duplicate declaration",
                value.get_file().as_ref(),
                value.get_name_range(),
                &format!(
                    "A {} named {} already exists",
                    value.get_generic_name(),
                    key
                ),
            );
            if let ErrorItem::Compile(e) = error {
                let (file, range) = match (orig_decl.get_file(), orig_decl.get_name_range()) {
                    (Some(file), Some(range)) => (file, range),
                    _ => {
                        // The previous one was a synthetic type.  We should have already errored
                        // out
                        return Err(ErrorItem::Internal(InternalError::new()).into());
                    }
                };
                error = ErrorItem::Compile(e.add_additional_message(
                    &file,
                    range,
                    "Already defined here",
                ));
            }
            return Err(error.into());
        }

        self.declarations.insert(key, value);
        Ok(())
    }

    pub fn values(&self) -> AliasMapValues<'_, T> {
        self.declarations.values()
    }

    pub fn values_mut(&mut self) -> AliasMapValuesMut<'_, T> {
        self.declarations.values_mut()
    }

    pub fn iter(&self) -> AliasMapIter<'_, T> {
        self.declarations.iter()
    }

    pub fn append(&mut self, other: &mut AliasMap<T>) {
        self.declarations.append(&mut other.declarations);
        self.aliases.append(&mut other.aliases);
    }

    pub fn set_aliases(&mut self, aliases: BTreeMap<String, String>) {
        self.aliases = aliases
    }

    // fallible extend, reject duplicates
    pub fn try_extend<I: IntoIterator<Item = (String, T)>>(
        &mut self,
        iter: I,
    ) -> Result<(), CascadeErrors> {
        for item in iter {
            self.insert(item.0, item.1)?;
        }
        Ok(())
    }
}

impl<T> Extend<(String, T)> for AliasMap<T> {
    fn extend<I: IntoIterator<Item = (String, T)>>(&mut self, iter: I) {
        self.declarations.extend(iter)
    }
}

impl<T> IntoIterator for AliasMap<T> {
    type Item = (String, T);
    type IntoIter = AliasMapIntoIter<T>;

    fn into_iter(self) -> AliasMapIntoIter<T> {
        self.declarations.into_iter()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Associated {
    pub resources: BTreeSet<CascadeString>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnnotationInfo {
    MakeList,
    Associate(Associated),
    Alias(CascadeString),
    Derive(Vec<Argument>),
}

#[derive(Clone, Debug)]
pub enum BoundTypeInfo {
    Single(String),
    List(Vec<String>),
    Unbound,
}

impl BoundTypeInfo {
    pub fn get_contents_as_vec(&self) -> Vec<String> {
        match self {
            BoundTypeInfo::Single(s) => vec![s.clone()],
            BoundTypeInfo::List(v) => v.clone(),
            BoundTypeInfo::Unbound => Vec::new(),
        }
    }
}

pub trait Annotated {
    fn get_annotations(&self) -> std::collections::btree_set::Iter<AnnotationInfo>;
}

pub trait Declared {
    fn get_file(&self) -> Option<SimpleFile<String, String>>;
    fn get_name_range(&self) -> Option<Range<usize>>;
    fn get_generic_name(&self) -> String;
}

#[derive(Clone, Debug)]
pub struct TypeInfo {
    pub name: CascadeString,
    pub inherits: Vec<CascadeString>,
    pub is_virtual: bool,
    pub is_trait: bool,
    pub list_coercion: bool, // Automatically transform single instances of this type to a single element list
    pub declaration_file: Option<SimpleFile<String, String>>, // Built in types have no file
    pub annotations: BTreeSet<AnnotationInfo>,
    // TODO: replace with Option<&TypeDecl>
    pub decl: Option<TypeDecl>,
    pub bound_type: BoundTypeInfo,
}

impl PartialEq for TypeInfo {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for TypeInfo {}

// This implementation is for deterministic CIL generation.
impl PartialOrd for TypeInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TypeInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

impl Annotated for &TypeInfo {
    fn get_annotations(&self) -> std::collections::btree_set::Iter<AnnotationInfo> {
        self.annotations.iter()
    }
}

impl Declared for TypeInfo {
    fn get_file(&self) -> Option<SimpleFile<String, String>> {
        self.declaration_file.clone()
    }

    fn get_name_range(&self) -> Option<Range<usize>> {
        self.decl.as_ref().and_then(|d| d.name.get_range())
    }

    fn get_generic_name(&self) -> String {
        String::from("type")
    }
}

impl TypeInfo {
    pub fn new(td: TypeDecl, file: &SimpleFile<String, String>) -> Result<TypeInfo, CascadeErrors> {
        let mut temp_vec = td.inherits.clone();
        temp_vec.sort();
        let mut iter = temp_vec.iter().peekable();
        while let Some(cur_val) = iter.next() {
            if let Some(next_val) = iter.peek() {
                if cur_val == *next_val {
                    return Err(CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
                        "Duplicate Inherit",
                        Some(file),
                        (*next_val).get_range(),
                        "This type to inherit is identical to another type in the same inheritance list. Perhaps you meant to inherit some other type?",
                    )));
                }
            }
        }
        Ok(TypeInfo {
            name: td.name.clone(),
            inherits: td.inherits.clone(),
            is_virtual: td.is_virtual,
            is_trait: td.is_trait,
            // TODO: Use AnnotationInfo::MakeList instead
            list_coercion: td.annotations.has_annotation("makelist"),
            declaration_file: Some(file.clone()), // TODO: Turn into reference
            annotations: get_type_annotations(file, &td.annotations)?,
            decl: Some(td),
            bound_type: BoundTypeInfo::Unbound,
        })
    }

    pub fn new_bound_type(
        name: CascadeString,
        variant: &str,
        file: &SimpleFile<String, String>,
        bound_type: BoundTypeInfo,
        annotations: &Annotations,
    ) -> Result<TypeInfo, CascadeErrors> {
        Ok(TypeInfo {
            name,
            inherits: vec![variant.into()], // Does this need to somehow grab the bound parents? Does this work for the single case?
            is_virtual: true,               // Maybe?
            is_trait: false,                // TODO: Allow bound traits?
            list_coercion: annotations.has_annotation("makelist"),
            declaration_file: Some(file.clone()),
            annotations: get_type_annotations(file, annotations)?,
            decl: None, // TODO: Where is this used?
            bound_type,
        })
    }

    pub fn make_built_in(name: String, makelist: bool) -> TypeInfo {
        TypeInfo {
            name: CascadeString::from(name),
            inherits: Vec::new(),
            is_virtual: true,
            is_trait: false,
            list_coercion: makelist,
            declaration_file: None,
            annotations: BTreeSet::new(),
            decl: None,
            bound_type: BoundTypeInfo::Unbound,
        }
    }

    pub fn is_child_or_actual_type(&self, target: &TypeInfo, types: &TypeMap) -> bool {
        if self.name == target.name {
            return true;
        }

        for parent in &self.inherits {
            let parent_typeinfo = match types.get(parent.as_ref()) {
                Some(t) => t,
                None => continue,
            };
            if parent_typeinfo.is_child_or_actual_type(target, types) {
                return true;
            }
        }
        false
    }

    // Get the type that cil is aware of that this ti falls into
    pub fn get_cil_macro_arg_type(&self) -> &str {
        for name_type in &["path", "string"] {
            if self.name == *name_type {
                return "name";
            }
        }
        "type" // Includes attributes in macro args
    }

    fn get_cil_declaration_type(&self) -> Option<&str> {
        for built_in_type in constants::BUILT_IN_TYPES {
            if *built_in_type == constants::DOMAIN || *built_in_type == constants::RESOURCE {
                continue;
            }
            if self.name == *built_in_type {
                return None;
            }
        }
        if self.is_virtual {
            Some("typeattribute")
        } else {
            Some("type")
        }
    }

    pub fn is_type_by_name(&self, types: &TypeMap, name: &str) -> bool {
        let ti = match types.get(name.as_ref()) {
            Some(ti) => ti,
            None => return false,
        };
        self.is_child_or_actual_type(ti, types)
    }

    pub fn is_resource(&self, types: &TypeMap) -> bool {
        self.is_type_by_name(types, constants::RESOURCE)
    }

    pub fn is_perm(&self, types: &TypeMap) -> bool {
        self.is_type_by_name(types, constants::PERM)
    }

    pub fn is_class(&self, types: &TypeMap) -> bool {
        self.is_type_by_name(types, constants::CLASS)
    }

    pub fn is_domain(&self, types: &TypeMap) -> bool {
        self.is_type_by_name(types, constants::DOMAIN)
    }

    pub fn is_setype(&self, types: &TypeMap) -> bool {
        self.is_domain(types) || self.is_resource(types)
    }

    pub fn is_trait(&self) -> bool {
        self.is_trait
    }

    // All types must inherit from some built in.  Get one for this type.
    // It's possible to inherit from multiple built-ins, so order matters here.  We return the
    // first type in order of preference.
    pub fn get_built_in_variant(&self, types: &TypeMap) -> Option<&str> {
        constants::BUILT_IN_TYPES
            .iter()
            .find(|t| self.is_type_by_name(types, t))
            .copied()
    }

    pub fn defines_function(&self, virtual_function_name: &str, functions: &FunctionMap) -> bool {
        for f in functions.values() {
            if f.class == Some(self) && f.name == virtual_function_name {
                return true;
            }
        }
        false
    }

    pub fn get_all_parent_names<'a>(&'a self, types: &'a TypeMap) -> BTreeSet<&'a CascadeString> {
        let mut ret = BTreeSet::new();
        for parent in &self.inherits {
            if ret.insert(parent) {
                if let Some(parent_ti) = types.get(parent.as_ref()) {
                    for name in &parent_ti.get_all_parent_names(types) {
                        ret.insert(name);
                    }
                }
            }
        }
        ret
    }
}

// This is the sexp for *declaring* the type
impl From<&TypeInfo> for Option<sexp::Sexp> {
    fn from(typeinfo: &TypeInfo) -> Option<sexp::Sexp> {
        let flavor = match typeinfo.get_cil_declaration_type() {
            Some(f) => f,
            None => return None,
        };
        Some(list(&[
            atom_s(flavor),
            atom_s(typeinfo.name.get_cil_name().as_ref()),
        ]))
    }
}

// Determine what sort of types are in a slice.
// Returns a &TypeInfo representing the inferred type which is a shared parent of all types.
// For now, we infer a "top level" built in type.
// It may be possible in some situations to infer the type more specifically, and we may also want
// to allow the user to specify a type for the bound type in the declaration.
// Returns an error if no common parent exists.
pub fn type_slice_to_variant<'a>(
    type_slice: &[&TypeInfo],
    types: &'a TypeMap,
) -> Result<&'a TypeInfo, CascadeErrors> {
    let first_type_variant = match type_slice.first() {
        Some(t) => match t.get_built_in_variant(types) {
            Some(v) => v,
            None => return Err(ErrorItem::Internal(InternalError::new()).into()),
        },
        None => todo!(), // TODO: Return error
    };

    for ti in type_slice {
        let ti_variant = match ti.get_built_in_variant(types) {
            Some(v) => v,
            None => return Err(ErrorItem::Internal(InternalError::new()).into()),
        };
        if ti_variant != first_type_variant {
            todo!() // TODO: Return error
        }
    }
    match types.get(first_type_variant) {
        Some(t) => Ok(t),
        None => Err(ErrorItem::Internal(InternalError::new()).into()),
    }
}

fn get_associate(
    file: &SimpleFile<String, String>,
    annotation_name_range: Option<Range<usize>>,
    annotation: &Annotation,
) -> Result<AnnotationInfo, ErrorItem> {
    let mut args = annotation.arguments.iter();

    let res_list = match args.next() {
        None => {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Missing resource list as first argument",
                Some(file),
                annotation_name_range,
                "You must use a set of resource names, enclosed by square brackets, as first argument.",
            ));
        }
        Some(Argument::List(l)) => l,
        Some(a) => {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Invalid argument type",
                Some(file),
                a.get_range(),
                "You must use a set of resource names, enclosed by square brackets, as first argument.",
            ));
        }
    };

    if let Some(a) = args.next() {
        return Err(ErrorItem::make_compile_or_internal_error(
            "Superfluous argument",
            Some(file),
            a.get_range(),
            "There must be only one argument.",
        ));
    }

    Ok(AnnotationInfo::Associate(Associated {
        // Checks for duplicate resources.
        resources: res_list.iter().try_fold(BTreeSet::new(), |mut s, e| {
            if !s.insert(e.clone()) {
                Err(ErrorItem::make_compile_or_internal_error(
                    "Duplicate resource",
                    Some(file),
                    e.get_range(),
                    "Only unique resource names are valid.",
                ))
            } else {
                Ok(s)
            }
        })?,
    }))
}

fn get_type_annotations(
    file: &SimpleFile<String, String>,
    annotations: &Annotations,
) -> Result<BTreeSet<AnnotationInfo>, ErrorItem> {
    let mut infos = BTreeSet::new();

    // Only allow a set of specific annotation names and strictly check their arguments.
    // TODO: Add tests to verify these checks.
    for annotation in annotations.annotations.iter() {
        match annotation.name.as_ref() {
            "makelist" => {
                // TODO: Check arguments
                // Multiple @makelist annotations doesn't make sense.
                if !infos.insert(AnnotationInfo::MakeList) {
                    return Err(ErrorItem::make_compile_or_internal_error(
                        "Multiple @makelist annotations",
                        Some(file),
                        annotation.name.get_range(),
                        "You need to remove duplicated @makelist annotations.",
                    ));
                }
            }
            "associate" => {
                // Multiple @associate annotations doesn't make sense.
                if !infos.insert(get_associate(
                    file,
                    annotation.name.get_range(),
                    annotation,
                )?) {
                    return Err(ErrorItem::make_compile_or_internal_error(
                        "Multiple @associate annotations",
                        Some(file),
                        annotation.name.get_range(),
                        "You need to remove duplicated @associate annotations.",
                    ));
                }
            }
            "alias" => {
                for a in &annotation.arguments {
                    match a {
                        Argument::Var(a) => {
                            infos.insert(AnnotationInfo::Alias(a.clone()));
                        }
                        _ => {
                            return Err(ErrorItem::make_compile_or_internal_error(
                                "Invalid alias",
                                Some(file),
                                a.get_range(),
                                "This must be a symbol",
                            ));
                        }
                    }
                }
            }
            "derive" => {
                // Arguments are validated at function creation time
                infos.insert(AnnotationInfo::Derive(annotation.arguments.clone()));
            }
            _ => {
                return Err(ErrorItem::make_compile_or_internal_error(
                    "Unknown annotation",
                    Some(file),
                    annotation.name.get_range(),
                    "This is not a valid annotation name.",
                ));
            }
        }
    }
    Ok(infos)
}

// On success, returns a tuple of parents to derive from and the names of the functions to derive
pub fn validate_derive_args<'a>(
    target_type: &'a TypeInfo,
    arguments: &[Argument],
    types: &'a TypeMap,
    class_perms: &ClassList,
) -> Result<(BTreeSet<&'a CascadeString>, Vec<CascadeString>), CascadeErrors> {
    // TODO: We might actually be in a context here, once nested type declarations are supported
    let local_context = BlockContext::new(BlockType::Annotation, types, None);
    let file = target_type.declaration_file.as_ref();
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("string"),
                is_list_param: true,
                name: CascadeString::from("functions"),
                default: Some(Argument::Var("all".into())),
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("string"),
                is_list_param: true,
                name: CascadeString::from("parents"),
                default: Some(Argument::Var("*".into())),
            },
            types,
            None,
        )?,
    ];

    let fake_call = FuncCall::new(None, CascadeString::from("derive"), arguments.to_vec());

    let valid_args = validate_arguments(
        &fake_call,
        &target_args,
        types,
        class_perms,
        &local_context,
        file,
    )?;

    let mut args_iter = valid_args.iter();

    let functions = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_list(&local_context)?
        .iter()
        .map(|s| (*s).clone())
        .collect();

    let parents = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_list(&local_context)?;

    if args_iter.next().is_some() {
        return Err(ErrorItem::Internal(InternalError::new()).into());
    }

    let derive_parents = if parents.first() == Some(&CascadeString::from("*")) {
        target_type.get_all_parent_names(types)
    } else {
        let mut ret = BTreeSet::new();
        for name in &parents {
            let parent_ti = types.get(name.as_ref()).ok_or_else(|| {
                ErrorItem::make_compile_or_internal_error(
                    "No such type",
                    file,
                    name.get_range(),
                    "This type does not exist.",
                )
            })?;
            if &target_type.name == name {
                return Err(ErrorItem::make_compile_or_internal_error(
                    "Cannot derive from self",
                    file,
                    name.get_range(),
                    "This needs to be a parent type",
                )
                .into());
            }
            if !target_type.is_child_or_actual_type(parent_ti, types) {
                return Err(ErrorItem::make_compile_or_internal_error(
                    &format!("{} is not a parent of {}", name, target_type.name),
                    file,
                    name.get_range(),
                    &format!("This needs to be a parent of {}", target_type.name),
                )
                .into());
            }
            ret.insert(&parent_ti.name);
        }
        ret
    };

    Ok((derive_parents, functions))
}

// strings may be paths or strings
pub fn type_name_from_string(string: &str) -> String {
    if string.contains('/') {
        "path".to_string()
    } else {
        "string".to_string()
    }
}

fn typeinfo_from_string<'a>(
    s: &str,
    coerce_strings: bool,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: &BlockContext<'a>,
) -> Option<&'a TypeInfo> {
    if s == "*" {
        // Don't coerce to string
        types.get("*")
    } else if coerce_strings {
        types.get("string")
    } else if class_perms.is_class(s) {
        types.get("obj_class")
    } else if class_perms.is_perm(s) {
        types.get("perm")
    } else {
        types.get(&context.convert_arg_this(s))
    }
}

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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Context<'a> {
    user: Cow<'a, str>,
    role: Cow<'a, str>,
    setype: Cow<'a, str>,
    mls_low: Cow<'a, str>,
    mls_high: Cow<'a, str>,
}

impl<'a> Context<'a> {
    // All fields except setype is optional.  User and role are replaced with defaults if set to None
    pub fn new(
        is_domain: bool,
        u: Option<Cow<'a, str>>,
        r: Option<Cow<'a, str>>,
        t: Cow<'a, str>,
        ml: Option<Cow<'a, str>>,
        mh: Option<Cow<'a, str>>,
    ) -> Self {
        Context {
            user: u.unwrap_or(Cow::Borrowed(DEFAULT_USER)),
            role: r.unwrap_or(if is_domain {
                Cow::Borrowed(DEFAULT_DOMAIN_ROLE)
            } else {
                Cow::Borrowed(DEFAULT_OBJECT_ROLE)
            }),
            setype: t,
            mls_low: ml.unwrap_or(Cow::Borrowed(DEFAULT_MLS)),
            mls_high: mh.unwrap_or(Cow::Borrowed(DEFAULT_MLS)),
        }
    }

    fn get_renamed_context(&self, renames: &BTreeMap<String, String>) -> Self {
        // The global rename_cow works on CascadeStrings.  In this local case we work on &strs
        // instead
        fn rename_cow<'a>(cow_str: &str, renames: &BTreeMap<String, String>) -> Cow<'a, str> {
            let new_str: &str = cow_str.borrow();
            Cow::Owned(renames.get(new_str).unwrap_or(&new_str.to_string()).clone())
        }
        Context {
            user: rename_cow(&self.user, renames),
            role: rename_cow(&self.role, renames),
            setype: rename_cow(&self.setype, renames),
            mls_low: rename_cow(&self.mls_low, renames),
            mls_high: rename_cow(&self.mls_high, renames),
        }
    }
}

impl From<&Context<'_>> for sexp::Sexp {
    fn from(c: &Context) -> sexp::Sexp {
        let mls_range = Sexp::List(vec![
            Sexp::List(vec![atom_s(&c.mls_low)]),
            Sexp::List(vec![atom_s(&c.mls_high)]),
        ]);
        Sexp::List(vec![
            atom_s(&c.user),
            atom_s(&c.role),
            atom_s(&c.setype),
            mls_range,
        ])
    }
}

// A context can be generated from any of the following patterns:
// type
// user:role:type
// user:role:type:sensitivity
// user:role:type:sensitivity:category
// That means that splitting on : yields 1, 3, 4 or 5 fields.  Any other number of fields is an
// error
// These contexts are always resources
// Errors will be handled by level above
// TODO: Somewhere along the line the mls low vs high distinction got confused with the sensitivity
// vs category distinction.  Since MLS isn't implemented yet, this is all placeholders, but this
// will need to be fixed before we implement MLS
impl<'a> TryFrom<&'a str> for Context<'a> {
    type Error = ();
    fn try_from(s: &'a str) -> Result<Context<'a>, ()> {
        let mut split_string = s.split(':');
        let first_field = split_string.next().ok_or(())?;
        let second_field = split_string.next();

        let role = match second_field {
            None => {
                return Ok(Context::new(
                    false,
                    None,
                    None,
                    Cow::Borrowed(first_field),
                    None,
                    None,
                ))
            }
            Some(role) => role,
        };

        let user = first_field; // The one field case was already handled.  In all other cases, the first field is user

        let context_type = split_string.next().ok_or(())?;

        let sensitivity = split_string.next(); // Sensitivity and category are optional

        // Iterators may start returning Some again after None
        let category = match &sensitivity {
            Some(_) => split_string.next(),
            None => None,
        };

        Ok(Context::new(
            false,
            Some(Cow::Borrowed(user)),
            Some(Cow::Borrowed(role)),
            Cow::Borrowed(context_type),
            sensitivity.map(Cow::Borrowed),
            category.map(Cow::Borrowed),
        ))
    }
}

// Result in owned types in CoW
impl<'a> TryFrom<String> for Context<'a> {
    type Error = ();
    // https://github.com/rust-lang/rust/issues/52188
    fn try_from(s: String) -> Result<Context<'a>, ()> {
        let context = Context::try_from(s.as_ref())?;

        Ok(Context::new(
            false,
            Some(Cow::Owned(context.user.into_owned())),
            Some(Cow::Owned(context.role.into_owned())),
            Cow::Owned(context.setype.into_owned()),
            None, // TODO
            None,
        ))
    }
}

impl<'a> fmt::Display for Context<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{} - {}",
            self.user, self.role, self.setype, self.mls_low, self.mls_high,
        )
    }
}

pub struct Sid<'a> {
    name: &'a str,
    context: Context<'a>,
}

impl<'a> Sid<'a> {
    pub fn new(name: &'a str, context: Context<'a>) -> Self {
        Sid { name, context }
    }

    fn get_sid_statement(&self) -> Sexp {
        Sexp::List(vec![atom_s("sid"), atom_s(self.name)])
    }

    fn get_sidcontext_statement(&self) -> Sexp {
        Sexp::List(vec![
            atom_s("sidcontext"),
            atom_s(self.name),
            Sexp::from(&self.context),
        ])
    }

    fn get_name_as_sexp_atom(&self) -> Sexp {
        atom_s(self.name)
    }
}

pub fn generate_sid_rules(sids: Vec<Sid>) -> Vec<Sexp> {
    let mut ret = Vec::new();
    let mut order = Vec::new();
    for s in sids {
        ret.push(s.get_sid_statement());
        ret.push(s.get_sidcontext_statement());
        order.push(s.get_name_as_sexp_atom());
    }
    ret.push(Sexp::List(vec![atom_s("sidorder"), Sexp::List(order)]));
    ret
}

pub struct Class<'a> {
    pub name: &'a str,
    // Another class that is treated like this class in Cascade
    pub collapsed_name: Option<&'a str>,
    pub perms: Vec<&'a str>,
}

impl From<&Class<'_>> for sexp::Sexp {
    fn from(c: &Class) -> sexp::Sexp {
        list(&[
            atom_s("class"),
            atom_s(c.name),
            Sexp::List(c.perms.iter().map(|p| atom_s(p)).collect()),
        ])
    }
}

impl<'a> Class<'a> {
    pub fn new(name: &'a str, perms: Vec<&'a str>) -> Self {
        Class {
            name,
            collapsed_name: None,
            perms,
        }
    }

    pub fn contains_perm(&self, perm: &str) -> bool {
        for p in &self.perms {
            if *p == perm {
                return true;
            }
        }
        false
    }
}

pub struct ClassList<'a> {
    pub classes: BTreeMap<&'a str, Class<'a>>,
    // It might be nice to just reference the strings in the policy, but the lifetimes get *really* messy, so it should simplify everything just to own these types
    pub perm_sets: BTreeMap<String, Vec<String>>,
}

impl<'a> ClassList<'a> {
    pub fn new() -> Self {
        ClassList {
            classes: BTreeMap::new(),
            perm_sets: BTreeMap::new(),
        }
    }

    pub fn add_class(&mut self, name: &'a str, perms: Vec<&'a str>) {
        self.classes.insert(name, Class::new(name, perms));
    }

    // If main_class exists, set collapsed class.  If it doesn't, noop
    pub fn set_collapsed(&mut self, main_class: &str, collapsed_class: &'a str) {
        if let Some(mut c) = self.classes.get_mut(main_class) {
            c.collapsed_name = Some(collapsed_class);
        }
    }

    pub fn generate_class_perm_cil(&self) -> Vec<Sexp> {
        let mut ret: Vec<Sexp> = self.classes.values().map(Sexp::from).collect();

        let classorder = list(&[
            atom_s("classorder"),
            Sexp::List(self.classes.values().map(|c| atom_s(c.name)).collect()),
        ]);

        ret.push(classorder);

        ret
    }

    // In base SELinux, object classes with more than 31 permissions, have a second object class
    // for overflow permissions.  In Cascade, we treat all of those the same.  This function needs to
    // handle that conversion in lookups.  If a permission wasn't found for capability, we check
    // capability2
    pub fn verify_permission(
        &self,
        class: &CascadeString,
        permission: &CascadeString,
        file: &SimpleFile<String, String>,
    ) -> Result<(), ErrorItem> {
        let class_struct = match self.classes.get(class.as_ref()) {
            Some(c) => c,
            None => {
                return Err(ErrorItem::make_compile_or_internal_error(
                    "No such object class",
                    Some(file),
                    class.get_range(),
                    "Invalid class",
                ));
            }
        };

        if permission.as_ref() == "*" {
            // * matches all valid object classes
            return Ok(());
        }

        if let Some(perm_vec) = self.perm_sets.get(&permission.to_string()) {
            for p in perm_vec {
                self.verify_permission(class, &p.as_str().into(), file)?;
            }
            return Ok(());
        }

        if class_struct.perms.contains(&permission.as_ref()) {
            Ok(())
        } else {
            let other_str = match class.as_ref() {
                "capability" => Some("capability2"),
                "process" => Some("process2"),
                "cap_userns" => Some("cap_userns2"),
                _ => None,
            };

            if let Some(s) = other_str {
                let hll_string = match class.get_range() {
                    Some(range) => CascadeString::new(s.to_string(), range),
                    None => CascadeString::from(s.to_string()),
                };
                return self.verify_permission(&hll_string, permission, file);
            }

            Err(ErrorItem::make_compile_or_internal_error(
                &format!(
                    "Permission {} is not defined for object class {}",
                    permission.as_ref(),
                    class.as_ref()
                ),
                Some(file),
                permission.get_range(),
                "Invalid permission",
            ))
        }
    }

    pub fn is_class(&self, class: &str) -> bool {
        // "any" is a special keyword to represent any class
        if class == "any" {
            return true;
        }
        self.classes.get(class).is_some()
    }

    pub fn is_perm(&self, perm: &str) -> bool {
        if perm == "*" {
            return true;
        }
        if self.perm_sets.get(perm).is_some() {
            return true;
        }
        for class in self.classes.values() {
            if class.contains_perm(perm) {
                return true;
            }
        }
        false
    }

    pub fn insert_perm_set(&mut self, set_name: &str, perms: Vec<String>) {
        self.perm_sets.insert(set_name.to_string(), perms);
    }

    pub fn expand_perm_list(&self, perms: Vec<&CascadeString>) -> Vec<CascadeString> {
        let mut ret = Vec::new();
        for p in perms {
            if let Some(pset) = self.perm_sets.get(&p.to_string()) {
                let pset_strings: Vec<CascadeString> = pset
                    .iter()
                    .map(|s| CascadeString::from(s.as_str()))
                    .collect();
                ret.append(&mut self.expand_perm_list(pset_strings.iter().collect()));
            } else {
                ret.push(p.clone());
            }
        }
        ret
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileSystemContextRule<'a> {
    pub fscontext_type: FSContextType,
    pub fs_name: String,
    pub path: Option<String>,
    pub file_type: Option<FileType>,
    pub context: Context<'a>,
}

impl FileSystemContextRule<'_> {
    fn get_renamed_statement(&self, renames: &BTreeMap<String, String>) -> Self {
        FileSystemContextRule {
            fscontext_type: self.fscontext_type.clone(),
            fs_name: self.fs_name.clone(),
            path: self.path.clone(),
            file_type: self.file_type,
            context: self.context.get_renamed_context(renames),
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
                atom_s(f.fs_name.trim_matches('"')),
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
                                atom_s(f.fs_name.trim_matches('"')),
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
                        atom_s(f.fs_name.trim_matches('"')),
                        atom_s(p.as_ref()),
                        Sexp::from(&f.context),
                    ]))
                } else {
                    Err(ErrorItem::InvalidFileSystem(InvalidFileSystemError::new(
                        &format!(
                            "Genfscon missing path.\n No path given for genfscon rule:\
                        \n\tFilesystem name: {}\n\tContext: {}",
                            f.fs_name, f.context,
                        ),
                    )))
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

    let context_str = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let fs_context = match Context::try_from(context_str.to_string()) {
        Ok(c) => c,
        Err(_) => {
            return Err(CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
                "Invalid context",
                Some(file),
                context_str.get_range(),
                "Cannot parse this into a context",
            )))
        }
    };
    let fs_name = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?
        .to_string();
    let fscontext_str = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?
        .get_name_or_string(context)?;
    let fscontext_type = match fscontext_str.to_string().parse::<FSContextType>() {
        Ok(f) => f,
        Err(_) => {
            return Err(CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
                "Not a valid file system type",
                Some(file),
                fscontext_str.get_range(),
                "File system type must be 'xattr', 'task', 'trans', or 'genfscon'",
            )));
        }
    };
    let regex_string_arg = args_iter
        .next()
        .ok_or_else(|| ErrorItem::Internal(InternalError::new()))?;
    let regex_string = regex_string_arg.get_name_or_string(context)?.to_string();
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
                    context: fs_context.clone(),
                });
            }
            let mut errors = CascadeErrors::new();
            if !file_types.is_empty() {
                errors.append(CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
                    "File types can only be provided for 'genfscon'",
                    Some(file),
                    file_types_arg.get_range(),
                    "",
                )));
            }
            if regex_string_arg.get_range().is_some() {
                errors.append(CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
                    "File path can only be provided for 'genfscon'",
                    Some(file),
                    regex_string_arg.get_range(),
                    "",
                )));
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
                    context: fs_context.clone(),
                });
            } else {
                for file_type in file_types {
                    let file_type = match file_type.to_string().parse::<FileType>() {
                        Ok(f) => f,
                        Err(_) => {
                            return Err(CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
                                "Not a valid file type",
                                Some(file),
                                file_type.get_range(),
                                "",
                            )))
                        }
                    };

                    ret.push(FileSystemContextRule {
                        fscontext_type: fscontext_type.clone(),
                        fs_name: fs_name.clone(),
                        path: Some(regex_string.clone()),
                        file_type: Some(file_type),
                        context: fs_context.clone(),
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
                                        &format!("In attempting to derive {}, parent functions do not have matching prototypes.", name),
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
                                        &format!("In attempting to derive {}, parent functions do not have matching prototypes.", name),
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
                    &format!("Unable to derive {}, because it has no parent implementations", name),
                    Some(file),
                    name.get_range(),
                    &format!("Attempted to derive an implementation of {}, but couldn't find any derivable parent implementations", name)).into());
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
                &CascadeString::from(self.name.as_ref()),
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
        parent_type: Option<&TypeInfo>,
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
                        Err(CascadeErrors::from(ErrorItem::make_compile_or_internal_error(
                            "fs_context() calls are only allowed in resources",
                            Some(file),
                            c.name.get_range(),
                            "Not allowed here",
                        )))
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

pub type ModuleMap<'a> = AliasMap<ValidatedModule<'a>>;

#[derive(Debug, Clone)]
pub struct ValidatedModule<'a> {
    pub name: CascadeString,
    pub annotations: BTreeSet<AnnotationInfo>,
    pub types: BTreeSet<&'a TypeInfo>,
    pub validated_modules: BTreeSet<&'a CascadeString>,
    declaration_file: Option<SimpleFile<String, String>>,
}

impl Declared for ValidatedModule<'_> {
    fn get_file(&self) -> Option<SimpleFile<String, String>> {
        self.declaration_file.clone()
    }

    fn get_name_range(&self) -> Option<Range<usize>> {
        self.name.get_range()
    }

    fn get_generic_name(&self) -> String {
        String::from("module")
    }
}

impl<'a> Annotated for &ValidatedModule<'a> {
    fn get_annotations(&self) -> std::collections::btree_set::Iter<AnnotationInfo> {
        self.annotations.iter()
    }
}

impl<'a> Eq for ValidatedModule<'a> {}

impl<'a> Ord for ValidatedModule<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

impl<'a> PartialOrd for ValidatedModule<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.name.cmp(&other.name))
    }
}

impl<'a> PartialEq for ValidatedModule<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl<'a> ValidatedModule<'a> {
    pub fn new(
        name: CascadeString,
        types: BTreeSet<&'a TypeInfo>,
        validated_modules: BTreeSet<&'a CascadeString>,
        mod_decl: Option<&'a Module>,
        declaration_file: Option<SimpleFile<String, String>>,
    ) -> Result<ValidatedModule<'a>, CascadeErrors> {
        let mut module_annontations = BTreeSet::new();
        if let Some(md) = mod_decl {
            if let Some(ref df) = declaration_file {
                module_annontations = get_module_annotations(df, &md.annotations)?;
            }
        }
        Ok(ValidatedModule {
            name,
            annotations: module_annontations,
            types,
            validated_modules,
            declaration_file,
        })
    }
}

fn get_module_annotations(
    file: &SimpleFile<String, String>,
    annotations: &Annotations,
) -> Result<BTreeSet<AnnotationInfo>, ErrorItem> {
    let mut infos = BTreeSet::new();
    for annotation in annotations.annotations.iter() {
        match annotation.name.as_ref() {
            "alias" => {
                for arg in &annotation.arguments {
                    match arg {
                        Argument::Var(a) => {
                            infos.insert(AnnotationInfo::Alias(a.clone()));
                        }
                        _ => {
                            return Err(ErrorItem::make_compile_or_internal_error(
                                "Invalid alias",
                                Some(file),
                                annotation.name.get_range(),
                                "Alias name must be a symbol",
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(ErrorItem::make_compile_or_internal_error(
                    "Unknown annotation",
                    Some(file),
                    annotation.name.get_range(),
                    "The only valid annotation for modules is '@alias'",
                ));
            }
        }
    }
    Ok(infos)
}

pub type MachineMap<'a> = AliasMap<ValidatedMachine<'a>>;

#[derive(Debug, Clone)]
pub struct ValidatedMachine<'a> {
    pub name: CascadeString,
    pub modules: BTreeSet<&'a ValidatedModule<'a>>,
    pub configurations: BTreeMap<String, &'a Argument>,
    declaration_file: Option<SimpleFile<String, String>>,
}

impl Declared for ValidatedMachine<'_> {
    fn get_file(&self) -> Option<SimpleFile<String, String>> {
        self.declaration_file.clone()
    }

    fn get_name_range(&self) -> Option<Range<usize>> {
        self.name.get_range()
    }

    fn get_generic_name(&self) -> String {
        String::from("machine")
    }
}

impl<'a> ValidatedMachine<'a> {
    pub fn new(
        name: CascadeString,
        modules: BTreeSet<&'a ValidatedModule<'a>>,
        configurations: BTreeMap<String, &'a Argument>,
        declaration_file: Option<SimpleFile<String, String>>,
    ) -> Self {
        ValidatedMachine {
            name,
            modules,
            configurations,
            declaration_file,
        }
    }
}

// If the class_name is "this", return the parent type name,
// else return the class name.  If the class_name is "this", and the parent type is None, that is
// an internal error
fn convert_class_name_if_this<'a>(
    class_name: &'a CascadeString,
    parent_type: Option<&'a TypeInfo>,
) -> Result<&'a CascadeString, ErrorItem> {
    if class_name != "this" {
        return Ok(class_name);
    }
    match parent_type {
        Some(t) => Ok(&t.name),
        None => Err(InternalError::new().into()),
    }
}

// Some TypeInfos have a string associated with a particular instance.  Most are just the TypeInfo
// These strings might have been generated locally rather than in the source, so we need to own the
// values so they live long enough
#[derive(Clone, Debug)]
enum TypeValue {
    Str(CascadeString),
    Vector(Vec<CascadeString>),
    SEType(Option<Range<usize>>),
}

#[derive(Clone, Debug)]
pub struct TypeInstance<'a> {
    instance_value: TypeValue,
    pub type_info: Cow<'a, TypeInfo>,
    file: Option<&'a SimpleFile<String, String>>,
}

impl<'a> TypeInstance<'a> {
    pub fn get_name_or_string(&self, context: &BlockContext) -> Result<CascadeString, ErrorItem> {
        match &self.instance_value {
            TypeValue::Str(s) => {
                // There are three cases here:
                // 1. "this" is the typeinfo name.  If we are in a function, we leave it as "this"
                //    because it will be passed in by the args and it needs to stay as this for
                //    deriving.  If we are in a non-function, we need to convert it here.
                // 2. Function call args are left alone
                // 3. Locally bound symbols (not args) are converted to what they are bound to
                if s == "this" {
                    if context.in_function_block() {
                        Ok(CascadeString::from("this"))
                    } else {
                        Ok(self.type_info.name.clone())
                    }
                } else {
                    context
                        .get_name_or_string(s)
                        .ok_or_else(|| InternalError::new().into())
                }
            }
            TypeValue::Vector(_) => Err(ErrorItem::make_compile_or_internal_error(
                "Unexpected list",
                self.file,
                self.get_range(),
                "Expected scalar value here",
            )),
            TypeValue::SEType(_) => {
                let ret_string = self.type_info.name.to_string();
                match self.get_range() {
                    Some(range) => Ok(CascadeString::new(ret_string, range)),
                    None => Ok(CascadeString::from(ret_string)),
                }
            }
        }
    }

    fn get_list(&self, context: &BlockContext) -> Result<Vec<CascadeString>, ErrorItem> {
        match &self.instance_value {
            TypeValue::Vector(v) => {
                let mut out_vec = Vec::new();
                for item in v {
                    out_vec.extend(context.get_list(item.as_ref()));
                }
                Ok(out_vec)
            }
            _ => Err(ErrorItem::make_compile_or_internal_error(
                "Expected list",
                self.file,
                self.get_range(),
                "Expected list here",
            )),
        }
    }

    fn get_range(&self) -> Option<Range<usize>> {
        match &self.instance_value {
            TypeValue::Str(s) => s.get_range(),
            TypeValue::Vector(v) => {
                CascadeString::slice_to_range(v.iter().collect::<Vec<&CascadeString>>().as_slice())
            }
            TypeValue::SEType(r) => r.clone(),
        }
    }

    pub fn new(
        arg: &ArgForValidation,
        ti: &'a TypeInfo,
        file: Option<&'a SimpleFile<String, String>>,
        context: &BlockContext,
    ) -> Self {
        let instance_value = match arg {
            ArgForValidation::Var(s) => {
                if ti.name == context.convert_arg_this(s.as_ref()) {
                    TypeValue::SEType(s.get_range())
                } else {
                    TypeValue::Str((*s).clone())
                }
            }
            ArgForValidation::List(vec) => {
                TypeValue::Vector(vec.iter().map(|s| (*s).clone()).collect())
            }
            ArgForValidation::Quote(q) => TypeValue::Str((*q).clone()),
        };

        TypeInstance {
            instance_value,
            type_info: Cow::Borrowed(ti),
            file,
        }
    }

    pub fn new_cast_instance(
        arg: &ArgForValidation,
        type_info: Cow<'a, TypeInfo>,
        file: Option<&'a SimpleFile<String, String>>,
    ) -> Self {
        let instance_value = match arg {
            ArgForValidation::List(vec) => {
                TypeValue::Vector(vec.iter().map(|s| (*s).clone()).collect())
            }
            ArgForValidation::Var(s) | ArgForValidation::Quote(s) => TypeValue::Str((*s).clone()),
        };

        TypeInstance {
            instance_value,
            type_info,
            file,
        }
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

fn validate_arguments<'a>(
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
}

impl<'a> From<&'a Argument> for ArgForValidation<'a> {
    fn from(a: &'a Argument) -> Self {
        match a {
            Argument::Var(s) => ArgForValidation::Var(s),
            Argument::Named(_, a) => ArgForValidation::from(&**a),
            Argument::List(v) => ArgForValidation::List(v.iter().collect()),
            Argument::Quote(s) => ArgForValidation::Quote(s),
        }
    }
}

impl fmt::Display for ArgForValidation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ArgForValidation::Var(a) => write!(f, "'{}'", a),
            ArgForValidation::List(_) => write!(f, "[TODO]",),
            ArgForValidation::Quote(a) => write!(f, "\"{}\"", a),
        }
    }
}

impl<'a> ArgForValidation<'a> {
    fn coerce_list(a: ArgForValidation<'a>) -> Self {
        let vec = match a {
            ArgForValidation::Var(s) => vec![s],
            ArgForValidation::List(v) => v,
            ArgForValidation::Quote(s) => vec![s],
        };
        ArgForValidation::List(vec)
    }

    fn get_range(&self) -> Option<Range<usize>> {
        match self {
            ArgForValidation::Var(s) => s.get_range(),
            ArgForValidation::List(v) => CascadeString::slice_to_range(v),
            ArgForValidation::Quote(s) => s.get_range(),
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
        let err_ret = |s: &CascadeString| {
            ErrorItem::make_compile_or_internal_error(
                "Cannot typecast",
                file,
                s.get_range(),
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
                Err(err_ret(s))
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
            ArgForValidation::Quote(s) => {
                return Err(err_ret(s));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sexp_internal;

    #[test]
    fn typeinstance_test() {
        let type_info = TypeInfo::make_built_in("foo".to_string(), false);
        let file = SimpleFile::new("some_file.txt".to_string(), "contents".to_string());
        let tm = TypeMap::new();
        let context = BlockContext::new(BlockType::Global, &tm, None);
        let type_instance = TypeInstance {
            instance_value: TypeValue::SEType(Some(2..4)),
            type_info: Cow::Borrowed(&type_info),
            file: Some(&file),
        };

        assert_eq!(
            type_instance
                .get_name_or_string(&context)
                .unwrap()
                .get_range(),
            Some(2..4)
        );
        assert_eq!(type_instance.get_range(), Some(2..4));
    }

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
    fn sexp_from_context() {
        let context_sexp = Sexp::from(&Context::new(
            true,
            Some(Cow::Borrowed("u")),
            Some(Cow::Borrowed("r")),
            Cow::Borrowed("t"),
            Some(Cow::Borrowed("s0")),
            Some(Cow::Borrowed("s0")),
        ));
        let cil_expected = "(u r t ((s0) (s0)))";
        assert_eq!(context_sexp.to_string(), cil_expected.to_string());
    }

    #[test]
    fn sexp_from_context_defaults() {
        let context_sexp = Sexp::from(&Context::new(
            true,
            None,
            None,
            Cow::Borrowed("t"),
            None,
            None,
        ));
        let cil_expected = "(system_u system_r t ((s0) (s0)))";
        assert_eq!(context_sexp.to_string(), cil_expected.to_string());
    }

    #[test]
    fn generate_sid_rules_test() {
        let sid1 = Sid::new(
            "foo",
            Context::new(true, None, None, Cow::Borrowed("foo_t"), None, None),
        );
        let sid2 = Sid::new(
            "bar",
            Context::new(false, None, None, Cow::Borrowed("bar_t"), None, None),
        );

        let rules = generate_sid_rules(vec![sid1, sid2]);
        let cil_expected = vec![
            "(sid foo)",
            "(sidcontext foo (system_u system_r foo_t ((s0) (s0))))",
            "(sid bar)",
            "(sidcontext bar (system_u object_r bar_t ((s0) (s0))))",
            "(sidorder (foo bar))",
        ];
        assert_eq!(rules.len(), cil_expected.len());
        let iter = rules.iter().zip(cil_expected.iter());
        for i in iter {
            assert_eq!(i.0.to_string(), i.1.to_string());
        }
    }

    #[test]
    fn classlist_test() {
        let mut classlist = ClassList::new();
        classlist.add_class("file", vec!["read", "write"]);
        classlist.add_class("capability", vec!["mac_override", "mac_admin"]);

        assert!(classlist.is_class("file"));
        assert!(classlist.is_class("capability"));
        assert!(!classlist.is_class("foo"));
        assert!(classlist.is_perm("read"));
        assert!(!classlist.is_perm("bar"));

        let cil = classlist.generate_class_perm_cil();

        assert_eq!(cil.len(), 3);
        // generate_class_perm_cil() doesn't provide an ordering guarantee
        let cil = Sexp::List(cil).to_string();
        assert!(cil.contains("(class capability (mac_override mac_admin))"));
        assert!(cil.contains("(class file (read write))"));
        assert!(
            cil.contains("(classorder (capability file))")
                || cil.contains("(classorder (file capability))")
        );
    }

    #[test]
    fn perm_set_test() {
        let mut classlist = ClassList::new();
        classlist.insert_perm_set("read_file_perms", vec!["read".into(), "getattr".into()]);
        assert!(classlist.is_perm("read_file_perms"));
        assert!(!classlist.is_perm("read"));
    }

    #[test]
    fn verify_permissions_test() {
        let fake_file = SimpleFile::new(String::new(), String::new());
        let mut classlist = ClassList::new();
        classlist.add_class("foo", vec!["bar", "baz"]);
        classlist.add_class("capability", vec!["cap_foo"]);
        classlist.add_class("capability2", vec!["cap_bar"]);
        classlist.add_class("process", vec!["not_foo"]);
        classlist.add_class("process2", vec!["foo"]);

        assert!(classlist
            .verify_permission(&"foo".into(), &"bar".into(), &fake_file)
            .is_ok());
        assert!(classlist
            .verify_permission(&"foo".into(), &"baz".into(), &fake_file)
            .is_ok());
        assert!(classlist
            .verify_permission(&"capability".into(), &"cap_bar".into(), &fake_file)
            .is_ok());
        assert!(classlist
            .verify_permission(&"process".into(), &"foo".into(), &fake_file)
            .is_ok());

        match classlist.verify_permission(
            &CascadeString::new("bar".to_string(), 0..1),
            &CascadeString::new("baz".to_string(), 0..1),
            &fake_file,
        ) {
            Ok(_) => panic!("Nonexistent class verified"),
            Err(e) => {
                if let ErrorItem::Compile(e) = e {
                    assert!(e.diagnostic.inner.message.contains("No such object class"))
                } else {
                    panic!("verify permission returned an internal error")
                }
            }
        }

        match classlist.verify_permission(
            &CascadeString::new("foo".to_string(), 0..1),
            &CascadeString::new("cap_bar".to_string(), 0..1),
            &fake_file,
        ) {
            Ok(_) => panic!("Nonexistent permission verified"),
            Err(e) => {
                if let ErrorItem::Compile(e) = e {
                    assert!(e
                        .diagnostic
                        .inner
                        .message
                        .contains("cap_bar is not defined for"))
                } else {
                    panic!("verify permission returned an internal error")
                }
            }
        }
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
    fn context_from_string_test() {
        let context = Context::try_from("u:r:foo").unwrap();
        assert_eq!(context.user, "u");
        assert_eq!(context.role, "r");
        assert_eq!(context.setype, "foo");
        assert_eq!(context.mls_low, DEFAULT_MLS);
        assert_eq!(context.mls_high, DEFAULT_MLS);
        let context = Context::try_from("foo").unwrap();
        assert_eq!(context.user, DEFAULT_USER);
        assert_eq!(context.role, DEFAULT_OBJECT_ROLE);
        assert_eq!(context.setype, "foo");
        assert_eq!(context.mls_low, DEFAULT_MLS);
        assert_eq!(context.mls_high, DEFAULT_MLS);
        let context = Context::try_from("foo:bar");
        if context.is_ok() {
            panic!("Bad context compiled successfully");
        }
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

        for statement in [statement1, statement2, statement3, statement4] {
            let mut renames = BTreeMap::new();
            renames.insert("old_name".to_string(), "new_name".to_string());
            let renamed_statement = statement.get_renamed_statement(&renames);
            match Sexp::try_from(&renamed_statement) {
                Ok(sexp) => {
                    assert!(sexp.to_string().contains("new_name"));
                    assert!(!sexp.to_string().contains("old_name"));
                }
                Err(_) => {
                    // We should never get here in testing but if we do assert false
                    assert!(false);
                }
            }
        }
    }
}
