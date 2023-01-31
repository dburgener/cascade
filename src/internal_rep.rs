// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use sexp::{atom_s, list, Sexp};

use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt;
use std::ops::Range;

use codespan_reporting::files::SimpleFile;

use crate::alias_map::{AliasMap, Declared};
use crate::ast::{
    Annotation, Annotations, Argument, CascadeString, DeclaredArgument, FuncCall, IpAddr, Port,
    TypeDecl,
};
use crate::constants;
use crate::context::{BlockType, Context as BlockContext};
use crate::error::{CascadeErrors, ErrorItem, InternalError};
use crate::functions::{validate_arguments, ArgForValidation, FunctionArgument, FunctionMap};

const DEFAULT_USER: &str = "system_u";
const DEFAULT_OBJECT_ROLE: &str = "object_r";
const DEFAULT_DOMAIN_ROLE: &str = "system_r";
const DEFAULT_MLS: &str = "s0";

pub type TypeMap = AliasMap<TypeInfo>;

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
    // TODO: Even if we're not doing a nested type annotation, we should be in the global context I
    // think, at least as a parent
    let local_context = BlockContext::new(BlockType::Annotation, types, None, None);
    let file = target_type.declaration_file.as_ref();
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: CascadeString::from("string"),
                is_list_param: true,
                name: CascadeString::from("functions"),
                default: Some(Argument::Var("*".into())),
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
                    "This type does not exist",
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

pub fn typeinfo_from_string<'a>(
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

    pub fn get_renamed_context(&self, renames: &BTreeMap<String, String>) -> Self {
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

// If the class_name is "this", return the parent type name,
// else return the class name.  If the class_name is "this", and the parent type is None, that is
// an internal error
pub fn convert_class_name_if_this<'a>(
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
pub enum TypeValue {
    Str(CascadeString),
    Vector(Vec<CascadeString>),
    SEType(Option<Range<usize>>),
    Port(Port),
    IpAddr(IpAddr),
}

#[derive(Clone, Debug)]
pub struct TypeInstance<'a> {
    pub instance_value: TypeValue,
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
            TypeValue::Port(p) => Ok(CascadeString::from(p)),
            TypeValue::IpAddr(_i) => todo!(),
        }
    }

    pub fn get_list(&self, context: &BlockContext) -> Result<Vec<CascadeString>, ErrorItem> {
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

    pub fn get_range(&self) -> Option<Range<usize>> {
        match &self.instance_value {
            TypeValue::Str(s) => s.get_range(),
            TypeValue::Vector(v) => {
                CascadeString::slice_to_range(v.iter().collect::<Vec<&CascadeString>>().as_slice())
            }
            TypeValue::SEType(r) => r.clone(),
            TypeValue::Port(p) => p.get_range(),
            TypeValue::IpAddr(i) => i.get_range(),
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
            ArgForValidation::Port(p) => TypeValue::Port((*p).clone()),
            ArgForValidation::IpAddr(i) => TypeValue::IpAddr((*i).clone()),
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
            ArgForValidation::Port(p) => TypeValue::Port((*p).clone()),
            ArgForValidation::IpAddr(i) => TypeValue::IpAddr((*i).clone()),
        };

        TypeInstance {
            instance_value,
            type_info,
            file,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typeinstance_test() {
        let type_info = TypeInfo::make_built_in("foo".to_string(), false);
        let file = SimpleFile::new("some_file.txt".to_string(), "contents".to_string());
        let tm = TypeMap::new();
        let context = BlockContext::new(BlockType::Global, &tm, None, None);
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
}
