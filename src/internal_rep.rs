// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use sexp::{atom_s, list, Atom, Sexp};

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use codespan_reporting::files::SimpleFile;

use crate::ast::{
    Annotation, Annotations, Argument, BuiltIns, DeclaredArgument, FuncCall, FuncDecl, HLLString,
    Statement, TypeDecl,
};
use crate::constants;
use crate::error::{HLLCompileError, HLLErrorItem, HLLErrors, HLLInternalError};

const DEFAULT_USER: &str = "system_u";
const DEFAULT_OBJECT_ROLE: &str = "object_r";
const DEFAULT_DOMAIN_ROLE: &str = "system_r";
const DEFAULT_MLS: &str = "s0";

pub struct TypeMap {
    types: BTreeMap<String, TypeInfo>,
    #[allow(dead_code)]
    aliases: BTreeMap<String, String>,
}

impl TypeMap {
    pub fn get(&self, key: &str) -> Option<&TypeInfo> {
        let type_name = if self.aliases.contains_key(key) {
            &self.aliases[key]
        } else {
            key
        };
        self.types.get(type_name)
    }

    pub fn new() -> Self {
        TypeMap {
            types: BTreeMap::new(),
            aliases: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: String, value: TypeInfo) {
        self.types.insert(key, value);
    }

    pub fn values(&self) -> std::collections::btree_map::Values<'_, String, TypeInfo> {
        self.types.values()
    }

    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, String, TypeInfo> {
        self.types.iter()
    }

    pub fn set_aliases(&mut self, aliases: BTreeMap<String, String>) {
        self.aliases = aliases
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Associated {
    pub resources: BTreeSet<HLLString>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnnotationInfo {
    MakeList,
    Associate(Associated),
    Alias(HLLString),
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
    pub name: HLLString,
    pub inherits: Vec<HLLString>,
    pub is_virtual: bool,
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

impl TypeInfo {
    pub fn new(td: TypeDecl, file: &SimpleFile<String, String>) -> Result<TypeInfo, HLLErrors> {
        Ok(TypeInfo {
            name: td.name.clone(),
            inherits: td.inherits.clone(),
            is_virtual: td.is_virtual,
            // TODO: Use AnnotationInfo::MakeList instead
            list_coercion: td.annotations.has_annotation("makelist"),
            declaration_file: Some(file.clone()), // TODO: Turn into reference
            annotations: get_type_annotations(file, &td.annotations)?,
            decl: Some(td),
            bound_type: BoundTypeInfo::Unbound,
        })
    }

    pub fn new_bound_type(
        name: HLLString,
        variant: &str,
        file: &SimpleFile<String, String>,
        bound_type: BoundTypeInfo,
        annotations: &Annotations,
    ) -> Result<TypeInfo, HLLErrors> {
        Ok(TypeInfo {
            name,
            inherits: vec![variant.into()], // Does this need to somehow grab the bound parents? Does this work for the single case?
            is_virtual: true,               // Maybe?
            list_coercion: annotations.has_annotation("makelist"),
            declaration_file: Some(file.clone()),
            annotations: get_type_annotations(file, annotations)?,
            decl: None, // TODO: Where is this used?
            bound_type,
        })
    }

    pub fn make_built_in(name: String, makelist: bool) -> TypeInfo {
        TypeInfo {
            name: HLLString::from(name),
            inherits: Vec::new(),
            is_virtual: true,
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

    // All types must inherit from some built in.  Get one for this type.
    // It's possible to inherit from multiple built-ins, so order matters here.  We return the
    // first type in order of preference.
    pub fn get_built_in_variant(&self, types: &TypeMap) -> Option<&str> {
        for t in constants::BUILT_IN_TYPES {
            if self.is_type_by_name(types, t) {
                return Some(t);
            }
        }

        // I don't think this should be logically possible
        None
    }
}

// This is the sexp for *declaring* the type
impl From<&TypeInfo> for Option<sexp::Sexp> {
    fn from(typeinfo: &TypeInfo) -> Option<sexp::Sexp> {
        let flavor = match typeinfo.get_cil_declaration_type() {
            Some(f) => f,
            None => return None,
        };
        Some(list(&[atom_s(flavor), atom_s(typeinfo.name.as_ref())]))
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
) -> Result<&'a TypeInfo, HLLErrors> {
    let first_type_variant = match type_slice.first() {
        Some(t) => match t.get_built_in_variant(types) {
            Some(v) => v,
            None => return Err(HLLErrorItem::Internal(HLLInternalError {}).into()),
        },
        None => todo!(), // TODO: Return error
    };

    for ti in type_slice {
        let ti_variant = match ti.get_built_in_variant(types) {
            Some(v) => v,
            None => return Err(HLLErrorItem::Internal(HLLInternalError {}).into()),
        };
        if ti_variant != first_type_variant {
            todo!() // TODO: Return error
        }
    }
    match types.get(first_type_variant) {
        Some(t) => Ok(t),
        None => Err(HLLErrorItem::Internal(HLLInternalError {}).into()),
    }
}

fn get_associate(
    file: &SimpleFile<String, String>,
    annotation_name_range: Option<Range<usize>>,
    annotation: &Annotation,
) -> Result<AnnotationInfo, HLLCompileError> {
    let mut args = annotation.arguments.iter();

    let res_list = match args.next() {
        None => {
            return Err(HLLCompileError::new(
                "Missing resource list as first argument",
                file,
                annotation_name_range,
                "You must use a set of resource names, enclosed by square brackets, as first argument.",
            ));
        }
        Some(Argument::List(l)) => l,
        Some(a) => {
            return Err(HLLCompileError::new(
                "Invalid argument type",
                file,
                a.get_range(),
                "You must use a set of resource names, enclosed by square brackets, as first argument.",
            ));
        }
    };

    if let Some(a) = args.next() {
        return Err(HLLCompileError::new(
            "Superfluous argument",
            file,
            a.get_range(),
            "There must be only one argument.",
        ));
    }

    Ok(AnnotationInfo::Associate(Associated {
        // Checks for duplicate resources.
        resources: res_list.iter().try_fold(BTreeSet::new(), |mut s, e| {
            if !s.insert(e.clone()) {
                Err(HLLCompileError::new(
                    "Duplicate resource",
                    file,
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
) -> Result<BTreeSet<AnnotationInfo>, HLLCompileError> {
    let mut infos = BTreeSet::new();

    // Only allow a set of specific annotation names and strictly check their arguments.
    // TODO: Add tests to verify these checks.
    for annotation in annotations.annotations.iter() {
        match annotation.name.as_ref() {
            "makelist" => {
                // TODO: Check arguments
                // Multiple @makelist annotations doesn't make sense.
                if !infos.insert(AnnotationInfo::MakeList) {
                    return Err(HLLCompileError::new(
                        "Multiple @makelist annotations",
                        file,
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
                    return Err(HLLCompileError::new(
                        "Multiple @associate annotations",
                        file,
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
                            return Err(HLLCompileError::new(
                                "Invalid alias",
                                file,
                                a.get_range(),
                                "This must be a symbol",
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(HLLCompileError::new(
                    "Unknown annotation",
                    file,
                    annotation.name.get_range(),
                    "This is not a valid annotation name.",
                ));
            }
        }
    }
    Ok(infos)
}

// strings may be paths or strings
pub fn type_name_from_string(string: &str) -> String {
    if string.contains('/') {
        "path".to_string()
    } else {
        "string".to_string()
    }
}

fn arg_in_context<'a>(arg: &str, context: Option<&[FunctionArgument<'a>]>) -> Option<&'a TypeInfo> {
    match context {
        Some(context) => {
            for context_arg in context {
                if arg == context_arg.name {
                    return Some(context_arg.param_type);
                }
            }
            None
        }
        None => None,
    }
}

fn typeinfo_from_string<'a>(
    s: &str,
    types: &'a TypeMap,
    class_perms: &ClassList,
) -> Option<&'a TypeInfo> {
    if class_perms.is_class(s) {
        types.get("obj_class")
    } else if class_perms.is_perm(s) {
        types.get("perm")
    } else {
        types.get(s)
    }
}

pub fn argument_to_typeinfo<'a>(
    a: &ArgForValidation<'_>,
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: Option<&[FunctionArgument<'a>]>,
    file: &SimpleFile<String, String>,
) -> Result<&'a TypeInfo, HLLErrorItem> {
    let t: Option<&TypeInfo> = match a {
        ArgForValidation::Var(s) => match arg_in_context(s.as_ref(), context) {
            Some(res) => Some(res),
            None => typeinfo_from_string(s.as_ref(), types, class_perms),
        },
        ArgForValidation::Quote(s) => types.get(&type_name_from_string(s.as_ref())),
        ArgForValidation::List(_) => None,
    };

    t.ok_or_else(|| {
        HLLErrorItem::Compile(HLLCompileError::new(
            "Not a valid type",
            file,
            a.get_range(),
            "",
        ))
    })
}

pub fn argument_to_typeinfo_vec<'a>(
    arg: &[&HLLString],
    types: &'a TypeMap,
    class_perms: &ClassList,
    context: Option<&[FunctionArgument<'a>]>,
    file: &SimpleFile<String, String>,
) -> Result<Vec<&'a TypeInfo>, HLLErrorItem> {
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AvRuleFlavor {
    Allow,
    Dontaudit,
    Auditallow,
    Neverallow,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AvRule<'a> {
    pub av_rule_flavor: AvRuleFlavor,
    pub source: &'a HLLString,
    pub target: &'a HLLString,
    pub class: &'a HLLString,
    // Lifetimes get weird once permissions get expanded, so AV rules should just own their permissions
    pub perms: Vec<HLLString>,
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

        ret.push(atom_s(rule.source.as_ref()));
        ret.push(atom_s(rule.target.as_ref()));

        let mut classpermset = vec![Sexp::Atom(Atom::S(rule.class.to_string()))];

        let perms = rule
            .perms
            .iter()
            .map(|p| Sexp::Atom(Atom::S(p.to_string())))
            .collect();

        classpermset.push(Sexp::List(perms));

        ret.push(Sexp::List(classpermset));

        Sexp::List(ret)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Context<'a> {
    user: &'a str,
    role: &'a str,
    setype: &'a str,
    mls_low: &'a str,
    mls_high: &'a str,
}

impl Context<'_> {
    // All fields except setype is optional.  User and role are replaced with defaults if set to None
    pub fn new<'a>(
        is_domain: bool,
        u: Option<&'a str>,
        r: Option<&'a str>,
        t: &'a str,
        ml: Option<&'a str>,
        mh: Option<&'a str>,
    ) -> Context<'a> {
        Context {
            user: u.unwrap_or(DEFAULT_USER),
            role: r.unwrap_or(if is_domain {
                DEFAULT_DOMAIN_ROLE
            } else {
                DEFAULT_OBJECT_ROLE
            }),
            setype: t,
            mls_low: ml.unwrap_or(DEFAULT_MLS),
            mls_high: mh.unwrap_or(DEFAULT_MLS),
        }
    }
}

impl From<Context<'_>> for sexp::Sexp {
    fn from(c: Context) -> sexp::Sexp {
        let mls_range = Sexp::List(vec![
            Sexp::List(vec![atom_s(c.mls_low)]),
            Sexp::List(vec![atom_s(c.mls_high)]),
        ]);
        Sexp::List(vec![
            atom_s(c.user),
            atom_s(c.role),
            atom_s(c.setype),
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
impl<'a> TryFrom<&'a str> for Context<'a> {
    type Error = ();
    fn try_from(s: &'a str) -> Result<Context<'a>, ()> {
        let mut split_string = s.split(':');
        let first_field = split_string.next().ok_or(())?;
        let second_field = split_string.next();

        let role = match second_field {
            None => return Ok(Context::new(false, None, None, first_field, None, None)),
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

        return Ok(Context::new(
            false,
            Some(user),
            Some(role),
            context_type,
            sensitivity,
            category,
        ));
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
            Sexp::from(self.context),
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
        Class { name, perms }
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
    // for overflow permissions.  In HLL, we treat all of those the same.  This function needs to
    // handle that conversion in lookups.  If a permission wasn't found for capability, we check
    // capability2
    pub fn verify_permission(
        &self,
        class: &HLLString,
        permission: &HLLString,
        file: &SimpleFile<String, String>,
    ) -> Result<(), HLLCompileError> {
        let class_struct = match self.classes.get(class.as_ref()) {
            Some(c) => c,
            None => {
                return Err(HLLCompileError::new(
                    "No such object class",
                    file,
                    class.get_range(),
                    "Invalid class",
                ));
            }
        };

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
                    Some(range) => HLLString::new(s.to_string(), range),
                    None => HLLString::from(s.to_string()),
                };
                return self.verify_permission(&hll_string, permission, file);
            }

            Err(HLLCompileError::new(
                &format!(
                    "Permission {} is not defined for object class {}",
                    permission.as_ref(),
                    class.as_ref()
                ),
                file,
                permission.get_range(),
                "Invalid permission",
            ))
        }
    }

    pub fn is_class(&self, class: &str) -> bool {
        self.classes.get(class).is_some()
    }

    pub fn is_perm(&self, perm: &str) -> bool {
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

    pub fn expand_perm_list(&self, perms: Vec<&HLLString>) -> Vec<HLLString> {
        let mut ret = Vec::new();
        for p in perms {
            if let Some(pset) = self.perm_sets.get(&p.to_string()) {
                let pset_strings: Vec<HLLString> =
                    pset.iter().map(|s| HLLString::from(s.as_str())).collect();
                ret.append(&mut self.expand_perm_list(pset_strings.iter().collect()));
            } else {
                ret.push(p.clone());
            }
        }
        ret
    }
}

// TODO: This can be converted into a TryFrom for more compile time gaurantees
fn call_to_av_rule<'a>(
    c: &'a FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    args: Option<&[FunctionArgument<'a>]>,
    file: &'a SimpleFile<String, String>,
) -> Result<AvRule<'a>, HLLErrors> {
    let flavor = match c.name.as_ref() {
        constants::ALLOW_FUNCTION_NAME => AvRuleFlavor::Allow,
        constants::DONTAUDIT_FUNCTION_NAME => AvRuleFlavor::Dontaudit,
        constants::AUDITALLOW_FUNCTION_NAME => AvRuleFlavor::Auditallow,
        constants::NEVERALLOW_FUNCTION_NAME => AvRuleFlavor::Neverallow,
        _ => return Err(HLLErrorItem::Internal(HLLInternalError {}).into()),
    };

    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: HLLString::from(constants::DOMAIN),
                is_list_param: false,
                name: HLLString::from("source"),
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: HLLString::from(constants::RESOURCE),
                is_list_param: false,
                name: HLLString::from("target"),
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: HLLString::from("obj_class"),
                is_list_param: false,
                name: HLLString::from("class"),
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: HLLString::from("perm"),
                is_list_param: true,
                name: HLLString::from("class"),
            },
            types,
            None,
        )?,
    ];

    let validated_args = validate_arguments(c, &target_args, types, class_perms, args, file)?;
    let mut args_iter = validated_args.iter();

    let source = args_iter
        .next()
        .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
        .get_name_or_string()?;
    let target = args_iter
        .next()
        .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
        .get_name_or_string()?;
    let class = args_iter
        .next()
        .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
        .get_name_or_string()?;
    let perms = args_iter
        .next()
        .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
        .get_list()?;

    if args_iter.next().is_some() {
        return Err(HLLErrorItem::Internal(HLLInternalError {}).into());
    }

    for p in &perms {
        class_perms.verify_permission(class, p, file)?;
    }

    let perms = class_perms.expand_perm_list(perms);

    Ok(AvRule {
        av_rule_flavor: flavor,
        source,
        target,
        class,
        perms,
    })
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
}

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

impl FromStr for FileType {
    type Err = ();
    fn from_str(s: &str) -> Result<FileType, ()> {
        match s {
            "file" => Ok(FileType::File),
            "dir" => Ok(FileType::Directory),
            "symlink" => Ok(FileType::SymLink),
            "char_dev" => Ok(FileType::CharDev),
            "block_dev" => Ok(FileType::BlockDev),
            "socket" => Ok(FileType::Socket),
            "pipe" => Ok(FileType::Pipe),
            "" => Ok(FileType::Any),
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

impl From<&FileContextRule<'_>> for sexp::Sexp {
    fn from(f: &FileContextRule) -> sexp::Sexp {
        list(&[
            atom_s("filecon"),
            atom_s(&f.regex_string),
            Sexp::Atom(Atom::S(f.file_type.to_string())),
            Sexp::from(f.context),
        ])
    }
}

fn call_to_fc_rules<'a>(
    c: &'a FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    args: Option<&[FunctionArgument<'a>]>,
    file: &'a SimpleFile<String, String>,
) -> Result<Vec<FileContextRule<'a>>, HLLErrors> {
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: HLLString::from("path"),
                is_list_param: false,
                name: HLLString::from("path_regex"),
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: HLLString::from("obj_class"), //TODO: not really
                is_list_param: true,
                name: HLLString::from("file_type"),
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: HLLString::from(constants::RESOURCE),
                is_list_param: false,
                name: HLLString::from("file_context"),
            },
            types,
            None,
        )?,
    ];

    let validated_args = validate_arguments(c, &target_args, types, class_perms, args, file)?;
    let mut args_iter = validated_args.iter();
    let mut ret = Vec::new();

    let regex_string = args_iter
        .next()
        .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
        .get_name_or_string()?
        .to_string();
    let file_types = args_iter
        .next()
        .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
        .get_list()?;
    let context = args_iter
        .next()
        .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
        .get_name_or_string()?;
    let context = match Context::try_from(context.as_ref()) {
        Ok(c) => c,
        Err(_) => {
            return Err(HLLErrors::from(HLLErrorItem::Compile(
                HLLCompileError::new(
                    "Invalid context",
                    file,
                    context.get_range(),
                    "Cannot parse this into a context",
                ),
            )))
        }
    };

    for file_type in file_types {
        let file_type = match file_type.to_string().parse::<FileType>() {
            Ok(f) => f,
            Err(_) => {
                return Err(HLLErrors::from(HLLErrorItem::Compile(
                    HLLCompileError::new("Not a valid file type", file, file_type.get_range(), ""),
                )))
            }
        };

        ret.push(FileContextRule {
            regex_string: regex_string.clone(),
            file_type,
            context,
        });
    }

    Ok(ret)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomtransRule<'a> {
    pub source: &'a TypeInfo,
    pub target: &'a TypeInfo,
    pub executable: &'a TypeInfo,
}

impl From<&DomtransRule<'_>> for sexp::Sexp {
    fn from(d: &DomtransRule) -> Self {
        list(&[
            atom_s("typetransition"),
            atom_s(&d.source.name.to_string()),
            atom_s(&d.executable.name.to_string()),
            atom_s("process"),
            atom_s(&d.target.name.to_string()),
        ])
    }
}

fn call_to_domain_transition<'a>(
    c: &'a FuncCall,
    types: &'a TypeMap,
    class_perms: &ClassList,
    args: Option<&[FunctionArgument<'a>]>,
    file: &'a SimpleFile<String, String>,
) -> Result<DomtransRule<'a>, HLLErrors> {
    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: HLLString::from(constants::DOMAIN),
                is_list_param: false,
                name: HLLString::from("source"),
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: HLLString::from(constants::RESOURCE),
                is_list_param: false,
                name: HLLString::from("executable"),
            },
            types,
            None,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: HLLString::from(constants::DOMAIN),
                is_list_param: false,
                name: HLLString::from("target"),
            },
            types,
            None,
        )?,
    ];

    let validated_args = validate_arguments(c, &target_args, types, class_perms, args, file)?;
    let mut args_iter = validated_args.iter();

    let source = args_iter
        .next()
        .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
        .type_info;
    let executable = args_iter
        .next()
        .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
        .type_info;
    let target = args_iter
        .next()
        .ok_or(HLLErrorItem::Internal(HLLInternalError {}))?
        .type_info;

    if args_iter.next().is_some() {
        return Err(HLLErrorItem::Internal(HLLInternalError {}).into());
    }

    Ok(DomtransRule {
        source,
        target,
        executable,
    })
}

fn check_associated_call(
    annotation: &Annotation,
    funcdecl: &FuncDecl,
    file: &SimpleFile<String, String>,
) -> Result<bool, HLLCompileError> {
    // Checks that annotation arguments match the expected signature.
    let mut annotation_args = annotation.arguments.iter();

    if let Some(a) = annotation_args.next() {
        return Err(HLLCompileError::new(
            "Superfluous argument",
            file,
            a.get_range(),
            "@associated_call doesn't take argument.",
        ));
    }

    // Checks that annotated functions match the expected signature.
    let mut func_args = funcdecl.args.iter();
    match func_args.next() {
        None => {
            return Err(HLLCompileError::new(
                "Invalid method signature for @associated_call annotation: missing firth argument",
                file,
                funcdecl.name.get_range(),
                "Add a 'domain' argument.",
            ))
        }
        Some(DeclaredArgument {
            param_type,
            is_list_param,
            name: _,
        }) => {
            if param_type.as_ref() != constants::DOMAIN || *is_list_param {
                return Err(HLLCompileError::new(
                    "Invalid method signature for @associated_call annotation: invalid firth argument",
                    file,
                    param_type.get_range(),
                    "The type of the first method argument must be 'domain'.",
                ));
            }
        }
    }
    if let Some(a) = func_args.next() {
        return Err(HLLCompileError::new(
            "Invalid method signature for @associated_call annotation: too much arguments",
            file,
            a.param_type.get_range(),
            "Only one argument of type 'domain' is accepted.",
        ));
    }

    Ok(true)
}

pub type FunctionMap<'a> = BTreeMap<String, FunctionInfo<'a>>;

#[derive(Debug, Clone)]
pub struct FunctionInfo<'a> {
    pub name: String,
    pub class: Option<&'a TypeInfo>,
    pub args: Vec<FunctionArgument<'a>>,
    pub annotations: BTreeSet<AnnotationInfo>,
    pub original_body: &'a Vec<Statement>,
    pub body: Option<BTreeSet<ValidatedStatement<'a>>>,
    pub declaration_file: &'a SimpleFile<String, String>,
    pub is_associated_call: bool,
    pub decl: &'a FuncDecl,
}

impl<'a> FunctionInfo<'a> {
    pub fn new(
        funcdecl: &'a FuncDecl,
        types: &'a TypeMap,
        parent_type: Option<&'a TypeInfo>,
        declaration_file: &'a SimpleFile<String, String>,
    ) -> Result<FunctionInfo<'a>, HLLErrors> {
        let mut args = Vec::new();
        let mut errors = HLLErrors::new();
        let mut annotations = BTreeSet::new();

        // All member functions automatically have "this" available as a reference to their type
        if let Some(parent_type) = parent_type {
            args.push(FunctionArgument::new_this_argument(parent_type));
        }

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
                        return Err(HLLCompileError::new(
                            "Multiple @associated_call annotations",
                            declaration_file,
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
                                annotations.insert(AnnotationInfo::Alias(s.clone()));
                            }
                            _ => {
                                return Err(HLLCompileError::new(
                                    "Invalid alias",
                                    declaration_file,
                                    annotation.name.get_range(),
                                    "Alias name must be a symbol").into());
                            }
                        }
                    }
                }
                _ => {
                    return Err(HLLCompileError::new(
                        "Unknown annotation",
                        declaration_file,
                        annotation.name.get_range(),
                        "The only valid annotation is '@associated_call'",
                    )
                    .into());
                }
            }
        }

        errors.into_result(FunctionInfo {
            name: funcdecl.name.to_string(),
            class: parent_type,
            args,
            annotations,
            original_body: &funcdecl.body,
            body: None,
            declaration_file,
            is_associated_call,
            decl: funcdecl,
        })
    }

    pub fn get_cil_name(&self) -> String {
        self.decl.get_cil_name()
    }

    pub fn validate_body(
        &mut self,
        functions: &'a FunctionMap<'a>,
        types: &'a TypeMap,
        class_perms: &'a ClassList,
        file: &'a SimpleFile<String, String>,
    ) -> Result<(), HLLErrors> {
        let mut new_body = BTreeSet::new();
        let mut errors = HLLErrors::new();

        for statement in self.original_body {
            match ValidatedStatement::new(
                statement,
                functions,
                types,
                class_perms,
                &self.args,
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
}

impl TryFrom<&FunctionInfo<'_>> for sexp::Sexp {
    type Error = HLLErrorItem;

    fn try_from(f: &FunctionInfo) -> Result<sexp::Sexp, HLLErrorItem> {
        let mut macro_cil = vec![
            atom_s("macro"),
            atom_s(&f.get_cil_name()),
            Sexp::List(f.args.iter().map(Sexp::from).collect()),
        ];
        match &f.body {
            None => return Err(HLLInternalError {}.into()),
            Some(statements) => {
                for statement in statements {
                    match statement {
                        ValidatedStatement::Call(c) => macro_cil.push(Sexp::from(&**c)),
                        ValidatedStatement::AvRule(a) => macro_cil.push(Sexp::from(&*a)),
                        ValidatedStatement::FcRule(f) => macro_cil.push(Sexp::from(&*f)),
                        ValidatedStatement::DomtransRule(d) => macro_cil.push(Sexp::from(&*d)),
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
}

impl<'a> FunctionArgument<'a> {
    pub fn new(
        declared_arg: &DeclaredArgument,
        types: &'a TypeMap,
        file: Option<&SimpleFile<String, String>>,
    ) -> Result<Self, HLLErrorItem> {
        let param_type = match types.get(&declared_arg.param_type.to_string()) {
            Some(ti) => ti,
            None => {
                return Err(HLLErrorItem::make_compile_or_internal_error(
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
        })
    }

    pub fn new_this_argument(parent_type: &'a TypeInfo) -> Self {
        FunctionArgument {
            param_type: parent_type,
            name: "this".to_string(),
            is_list_param: false,
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

impl fmt::Display for FunctionArgument<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.param_type.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidatedStatement<'a> {
    Call(Box<ValidatedCall>),
    AvRule(AvRule<'a>),
    FcRule(FileContextRule<'a>),
    DomtransRule(DomtransRule<'a>),
}

impl<'a> ValidatedStatement<'a> {
    pub fn new(
        statement: &'a Statement,
        functions: &FunctionMap<'a>,
        types: &'a TypeMap,
        class_perms: &ClassList<'a>,
        args: &[FunctionArgument<'a>],
        parent_type: Option<&TypeInfo>,
        file: &'a SimpleFile<String, String>,
    ) -> Result<BTreeSet<ValidatedStatement<'a>>, HLLErrors> {
        let in_resource = match parent_type {
            Some(t) => t.is_resource(types),
            None => false,
        };

        match statement {
            Statement::Call(c) => {
                match c.check_builtin() {
                    Some(BuiltIns::AvRule) => Ok(Some(ValidatedStatement::AvRule(
                        call_to_av_rule(c, types, class_perms, Some(args), file)?,
                    ))
                    .into_iter()
                    .collect()),
                    Some(BuiltIns::FileContext) => {
                        if in_resource {
                            Ok(call_to_fc_rules(c, types, class_perms, Some(args), file)?
                                .into_iter()
                                .map(ValidatedStatement::FcRule)
                                .collect())
                        } else {
                            Err(HLLErrors::from(HLLErrorItem::Compile(
                                HLLCompileError::new(
                                    "file_context() calls are only allowed in resources",
                                    file,
                                    c.name.get_range(),
                                    "Not allowed here",
                                ),
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
                                    Some(args),
                                    file,
                                )?))
                                .into_iter()
                                .collect(),
                            )
                        } else {
                            Err(HLLErrors::from(HLLErrorItem::Compile(
                                HLLCompileError::new(
                                    "domain_transition() calls are not allowed in resources",
                                    file,
                                    c.name.get_range(),
                                    "Not allowed here",
                                ),
                            )))
                        }
                    }
                    None => Ok(Some(ValidatedStatement::Call(Box::new(ValidatedCall::new(
                        c,
                        functions,
                        types,
                        class_perms,
                        Some(args),
                        file,
                    )?)))
                    .into_iter()
                    .collect()),
                }
            }
            Statement::LetBinding(_l) => {
                // Global scope let bindings were handled by get_global_bindings() in a previous
                // pass

                // The if half is a TODO.  They'll be different once implemented.  I'd rather leave
                // the switch in for clear code and future reference than make clippy happy for the
                // sake of making clippy happy
                #[allow(clippy::if_same_then_else)]
                if parent_type.is_some() {
                    Ok(BTreeSet::default()) // TODO: This is where local scope let bindings should happen
                } else {
                    // Global scope, nothing to do here
                    Ok(BTreeSet::default())
                }
            }
        }
    }
}

impl From<&ValidatedStatement<'_>> for sexp::Sexp {
    fn from(statement: &ValidatedStatement) -> sexp::Sexp {
        match statement {
            ValidatedStatement::Call(c) => Sexp::from(&**c),
            ValidatedStatement::AvRule(a) => Sexp::from(a),
            ValidatedStatement::FcRule(f) => Sexp::from(f),
            ValidatedStatement::DomtransRule(d) => Sexp::from(d),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValidatedCall {
    cil_name: String,
    args: Vec<String>,
}

impl ValidatedCall {
    fn new(
        call: &FuncCall,
        functions: &FunctionMap<'_>,
        types: &TypeMap,
        class_perms: &ClassList,
        parent_args: Option<&[FunctionArgument]>,
        file: &SimpleFile<String, String>,
    ) -> Result<ValidatedCall, HLLErrors> {
        let cil_name = call.get_cil_name();
        let function_info = match functions.get(&cil_name) {
            Some(function_info) => function_info,
            None => {
                return Err(HLLErrors::from(HLLErrorItem::Compile(
                    HLLCompileError::new("No such function", file, call.get_name_range(), ""),
                )));
            }
        };

        // Each argument must match the type the function signature expects
        let mut args = match &call.class_name {
            Some(c) => vec![c.to_string()], // "this"
            None => Vec::new(),
        };

        for arg in validate_arguments(
            call,
            &function_info.args,
            types,
            class_perms,
            parent_args,
            file,
        )? {
            args.push(arg.get_name_or_string()?.to_string()); // TODO: Handle lists
        }

        Ok(ValidatedCall { cil_name, args })
    }
}

// Some TypeInfos have a string associated with a particular instance.  Most are just the TypeInfo
#[derive(Clone, Debug)]
enum TypeValue<'a> {
    Str(&'a HLLString),
    Vector(Vec<&'a HLLString>),
    SEType(Option<Range<usize>>),
}

#[derive(Clone, Debug)]
struct TypeInstance<'a> {
    instance_value: TypeValue<'a>,
    pub type_info: &'a TypeInfo,
    file: &'a SimpleFile<String, String>,
}

impl<'a> TypeInstance<'a> {
    fn get_name_or_string(&self) -> Result<&'a HLLString, HLLErrorItem> {
        match self.instance_value {
            TypeValue::Str(s) => {
                if s == "this" {
                    // Always convert "this" into its typeinfo.  This is to support the usage of
                    // "this" in domains and resources.  Other instances of TypeValue::Str are in
                    // function calls and should be left as the bound names for cil to handle
                    Ok(&self.type_info.name)
                } else {
                    Ok(s)
                }
            }
            TypeValue::Vector(_) => Err(HLLErrorItem::Compile(HLLCompileError::new(
                "Unexpected list",
                self.file,
                self.get_range(),
                "Expected scalar value here",
            ))),
            TypeValue::SEType(_) => Ok(&self.type_info.name),
        }
    }

    fn get_list(&self) -> Result<Vec<&'a HLLString>, HLLErrorItem> {
        match &self.instance_value {
            TypeValue::Vector(v) => Ok(v.clone()),
            _ => Err(HLLErrorItem::Compile(HLLCompileError::new(
                "Expected list",
                self.file,
                self.get_range(),
                "Expected list here",
            ))),
        }
    }

    fn get_range(&self) -> Option<Range<usize>> {
        match &self.instance_value {
            TypeValue::Str(s) => s.get_range(),
            TypeValue::Vector(v) => HLLString::slice_to_range(v),
            TypeValue::SEType(r) => r.clone(),
        }
    }

    fn new(
        arg: &ArgForValidation<'a>,
        ti: &'a TypeInfo,
        file: &'a SimpleFile<String, String>,
    ) -> Self {
        let instance_value = match arg {
            ArgForValidation::Var(s) => {
                if s == &&ti.name {
                    TypeValue::SEType(s.get_range())
                } else {
                    TypeValue::Str(s)
                }
            }
            ArgForValidation::List(vec) => TypeValue::Vector(vec.clone()),
            ArgForValidation::Quote(q) => TypeValue::Str(q),
        };

        TypeInstance {
            instance_value,
            type_info: ti,
            file,
        }
    }
}

fn validate_arguments<'a>(
    call: &'a FuncCall,
    function_args: &[FunctionArgument],
    types: &'a TypeMap,
    class_perms: &ClassList,
    parent_args: Option<&[FunctionArgument<'a>]>,
    file: &'a SimpleFile<String, String>,
) -> Result<Vec<TypeInstance<'a>>, HLLErrors> {
    // Some functions start with an implicit "this" argument.  If it does, skip it
    let function_args_iter = function_args.iter().skip_while(|a| a.name == "this");

    if function_args_iter.clone().count() != call.args.len() {
        return Err(HLLErrors::from(HLLErrorItem::Compile(
            HLLCompileError::new(
                &format!(
                    "Function {} expected {} arguments, got {}",
                    call.get_display_name(),
                    function_args.len(),
                    call.args.len()
                ),
                file,
                call.get_name_range(), // TODO: this may not be the cleanest way to report this error
                "",
            ),
        )));
    }

    let mut args = Vec::new();
    for (a, fa) in call.args.iter().zip(function_args_iter) {
        args.push(validate_argument(
            ArgForValidation::from(a),
            fa,
            types,
            class_perms,
            parent_args,
            file,
        )?);
    }
    Ok(args)
}

// The ast Argument owns the data, this struct is similar, but has references to the owned data in
// the ast, so we can make copies and manipulate
pub enum ArgForValidation<'a> {
    Var(&'a HLLString),
    List(Vec<&'a HLLString>),
    Quote(&'a HLLString),
}

impl<'a> From<&'a Argument> for ArgForValidation<'a> {
    fn from(a: &'a Argument) -> Self {
        match a {
            Argument::Var(s) => ArgForValidation::Var(s),
            Argument::Named(_n, _a) => todo!(),
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
            ArgForValidation::List(v) => HLLString::slice_to_range(v),
            ArgForValidation::Quote(s) => s.get_range(),
        }
    }
}

fn validate_argument<'a>(
    arg: ArgForValidation<'a>,
    target_argument: &FunctionArgument,
    types: &'a TypeMap,
    class_perms: &ClassList,
    args: Option<&[FunctionArgument<'a>]>,
    file: &'a SimpleFile<String, String>,
) -> Result<TypeInstance<'a>, HLLErrorItem> {
    match &arg {
        ArgForValidation::List(v) => {
            if !target_argument.is_list_param {
                return Err(HLLErrorItem::Compile(HLLCompileError::new(
                    "Unexpected list",
                    file,
                    HLLString::slice_to_range(v),
                    "This function requires a non-list value here",
                )));
            }
            let target_ti = match types.get(&target_argument.param_type.name.to_string()) {
                Some(t) => t,
                None => return Err(HLLInternalError {}.into()),
            };
            let arg_typeinfo_vec = argument_to_typeinfo_vec(v, types, class_perms, args, file)?;

            for arg in arg_typeinfo_vec {
                if !arg.is_child_or_actual_type(target_argument.param_type, types) {
                    return Err(HLLErrorItem::Compile(HLLCompileError::new(
                        &format!("Expected type inheriting {}", target_ti.name),
                        file,
                        arg.name.get_range(),
                        &format!("This type should inherit {}", target_ti.name),
                    )));
                }
            }
            Ok(TypeInstance::new(&arg, target_ti, file))
        }
        _ => {
            let arg_typeinfo = argument_to_typeinfo(&arg, types, class_perms, args, file)?;
            if target_argument.is_list_param {
                if arg_typeinfo.list_coercion
                    || matches!(arg_typeinfo.bound_type, BoundTypeInfo::List(_))
                {
                    return validate_argument(
                        ArgForValidation::coerce_list(arg),
                        target_argument,
                        types,
                        class_perms,
                        args,
                        file,
                    );
                    // TODO: Do we handle bound lists here?
                }
                return Err(HLLErrorItem::Compile(HLLCompileError::new(
                    "Expected list",
                    file,
                    arg.get_range(),
                    "This function requires a list value here",
                )));
            }

            if arg_typeinfo.is_child_or_actual_type(target_argument.param_type, types) {
                Ok(TypeInstance::new(&arg, arg_typeinfo, file))
            } else {
                Err(HLLErrorItem::Compile(HLLCompileError::new(
                    &format!("Expected type inheriting {}", arg_typeinfo.name),
                    file,
                    arg.get_range(),
                    &format!("This type should inherit {}", arg_typeinfo.name),
                )))
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
    fn generate_cil_for_av_rule_test() {
        let cil_sexp = Sexp::from(&AvRule {
            av_rule_flavor: AvRuleFlavor::Allow,
            source: &"foo".into(),
            target: &"bar".into(),
            class: &"file".into(),
            perms: vec!["read".into(), "getattr".into()],
        });

        let cil_expected = "(allow foo bar (file (read getattr)))";

        assert_eq!(cil_sexp.to_string(), cil_expected.to_string());
    }

    #[test]
    fn sexp_from_context() {
        let context_sexp = Sexp::from(Context::new(
            true,
            Some("u"),
            Some("r"),
            "t",
            Some("s0"),
            Some("s0"),
        ));
        let cil_expected = "(u r t ((s0) (s0)))";
        assert_eq!(context_sexp.to_string(), cil_expected.to_string());
    }

    #[test]
    fn sexp_from_context_defaults() {
        let context_sexp = Sexp::from(Context::new(true, None, None, "t", None, None));
        let cil_expected = "(system_u system_r t ((s0) (s0)))";
        assert_eq!(context_sexp.to_string(), cil_expected.to_string());
    }

    #[test]
    fn generate_sid_rules_test() {
        let sid1 = Sid::new("foo", Context::new(true, None, None, "foo_t", None, None));
        let sid2 = Sid::new("bar", Context::new(false, None, None, "bar_t", None, None));

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

        match classlist.verify_permission(&"bar".into(), &"baz".into(), &fake_file) {
            Ok(_) => panic!("Nonexistent class verified"),
            Err(e) => assert!(e.diagnostic.inner.message.contains("No such object class")),
        }

        match classlist.verify_permission(&"foo".into(), &"cap_bar".into(), &fake_file) {
            Ok(_) => panic!("Nonexistent permission verified"),
            Err(e) => assert!(e
                .diagnostic
                .inner
                .message
                .contains("cap_bar is not defined for")),
        }
    }

    #[test]
    fn filecon_to_sexp_test() {
        let fc = FileContextRule {
            regex_string: "\"/bin\"".to_string(),
            file_type: FileType::File,
            context: Context::new(false, Some("u"), Some("r"), "bin_t", None, None),
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
        let file_type = "".parse::<FileType>().unwrap();
        assert!(matches!(file_type, FileType::Any));

        assert!("bad_type".parse::<FileType>().is_err());
    }
}
