// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter;
use std::net::IpAddr as NetIpAddr;
use std::ops::Range;

use codespan_reporting::files::SimpleFile;

use crate::constants;
use crate::context::Context;
use crate::error::{CascadeErrors, ErrorItem, ParseErrorMsg};
use crate::internal_rep::TypeMap;

#[derive(Clone, Debug, Eq)]
pub struct CascadeString {
    string: String,
    range: Option<Range<usize>>,
}

impl fmt::Display for CascadeString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.string)
    }
}

impl CascadeString {
    pub fn new(string: String, range: Range<usize>) -> Self {
        CascadeString {
            string,
            range: Some(range),
        }
    }

    pub fn get_range(&self) -> Option<Range<usize>> {
        self.range.clone()
    }

    // TODO: This doesn't include the brackets at the end, but we haven't saved enough info from
    // the AST for that
    pub fn slice_to_range(v: &[&CascadeString]) -> Option<Range<usize>> {
        let start = v.first();
        let end = v.last();

        match (start, end) {
            (Some(s), Some(e)) => match (s.get_range(), e.get_range()) {
                (Some(s), Some(e)) => Some(s.start..e.end),
                _ => None,
            },
            _ => None,
        }
    }

    // '.' is used in string for name mangled types in block inheritance
    // We also use '.' for name mangled types, but don't implement them as
    // block inheritance, so we translate to '-' in the resulting CIL
    pub fn get_cil_name(&self) -> String {
        self.string.replace('.', "-")
    }
}

impl AsRef<str> for CascadeString {
    fn as_ref(&self) -> &str {
        self.string.as_str()
    }
}

impl From<String> for CascadeString {
    fn from(s: String) -> CascadeString {
        CascadeString {
            string: s,
            range: None,
        }
    }
}

impl From<&str> for CascadeString {
    fn from(s: &str) -> CascadeString {
        CascadeString {
            string: s.to_string(),
            range: None,
        }
    }
}

impl Hash for CascadeString {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.string.hash(h);
    }
}

impl PartialEq for CascadeString {
    fn eq(&self, other: &Self) -> bool {
        self.string == other.string
    }
}

impl PartialEq<String> for CascadeString {
    fn eq(&self, other: &String) -> bool {
        self.string == *other
    }
}

impl PartialEq<str> for CascadeString {
    fn eq(&self, other: &str) -> bool {
        self.string == other
    }
}

impl PartialEq<CascadeString> for str {
    fn eq(&self, other: &CascadeString) -> bool {
        self == other.string
    }
}

impl PartialEq<&str> for CascadeString {
    fn eq(&self, other: &&str) -> bool {
        self.string == *other
    }
}

impl PartialEq<CascadeString> for &str {
    fn eq(&self, other: &CascadeString) -> bool {
        *self == other.string
    }
}

impl PartialOrd for CascadeString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CascadeString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.string.cmp(&other.string)
    }
}

impl From<&Port> for CascadeString {
    fn from(p: &Port) -> Self {
        CascadeString {
            string: p.to_string(),
            range: p.get_range(),
        }
    }
}

impl<const N: usize> From<&[&CascadeString; N]> for CascadeString {
    fn from(cs_slice: &[&CascadeString; N]) -> Self {
        let new_range = Self::slice_to_range(cs_slice);

        let new_string = cs_slice
            .iter()
            .map(|c| c.as_ref())
            .collect::<Vec<&str>>()
            .join("");
        CascadeString {
            string: new_string,
            range: new_range,
        }
    }
}

#[derive(Debug)]
pub struct PolicyFile {
    pub policy: Policy,
    pub file: SimpleFile<String, String>,
}

impl PolicyFile {
    pub fn new(policy: Policy, file: SimpleFile<String, String>) -> Self {
        PolicyFile { policy, file }
    }
}

#[derive(Debug)]
pub struct Policy {
    pub exprs: Vec<Expression>,
}

impl Policy {
    pub fn new(exprs: Vec<Expression>) -> Policy {
        Policy { exprs }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Expression {
    Decl(Declaration),
    Stmt(Statement),
    // Needed for parser grammar.  If this is ever set, we should have bailed
    // prior to using this. If possible encountering this should be an internal
    // error, otherwise it is safe to ignore.
    Error,
}

impl Expression {
    pub fn set_class_name_if_decl(&mut self, name: CascadeString) {
        if let Expression::Decl(Declaration::Func(d)) = self {
            d.class_name = Some(name)
        }
    }

    pub fn add_annotation(&mut self, annotation: Annotation) {
        match self {
            Expression::Decl(d) => d.add_annotation(annotation),
            Expression::Stmt(s) => s.add_annotation(annotation),
            Expression::Error => (),
        }
    }

    pub fn is_virtual_function(&self) -> bool {
        match self {
            Expression::Decl(Declaration::Func(f)) => f.is_virtual,
            _ => false,
        }
    }
}

pub enum DeclarationModifier {
    Virtual(Range<usize>),
    Trait(Range<usize>),
}

pub trait Virtualable {
    fn set_virtual(&mut self, range: Range<usize>) -> Result<(), ParseErrorMsg>;
    fn set_trait(&mut self, range: Range<usize>) -> Result<(), ParseErrorMsg>;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Declaration {
    Type(Box<TypeDecl>),
    Collection(Box<CollectionDecl>),
    Func(Box<FuncDecl>),
    Mod(Module),
    Machine(Machine),
}

impl Virtualable for Declaration {
    fn set_virtual(&mut self, range: Range<usize>) -> Result<(), ParseErrorMsg> {
        match self {
            Declaration::Type(t) => t.set_virtual(range),
            Declaration::Collection(_) => Ok(()), // no-op
            Declaration::Func(f) => f.set_virtual(range),
            Declaration::Mod(m) => m.set_virtual(range),
            Declaration::Machine(s) => s.set_virtual(range),
        }
    }

    // trait implies virtual.  We set trait first for the better error message
    fn set_trait(&mut self, range: Range<usize>) -> Result<(), ParseErrorMsg> {
        match self {
            Declaration::Type(t) => {
                t.set_trait(range.clone())?;
                t.set_virtual(range)
            }
            Declaration::Collection(_) => {
                todo!()
            }
            Declaration::Func(f) => {
                f.set_trait(range.clone())?;
                f.set_virtual(range)
            }
            Declaration::Mod(m) => {
                m.set_trait(range.clone())?;
                m.set_virtual(range)
            }
            Declaration::Machine(s) => {
                s.set_trait(range.clone())?;
                s.set_virtual(range)
            }
        }
    }
}

impl Declaration {
    pub fn add_annotation(&mut self, annotation: Annotation) {
        match self {
            Declaration::Type(t) => t.annotations.push(annotation),
            Declaration::Collection(a) => a.annotations.push(annotation),
            Declaration::Func(f) => f.annotations.push(annotation),
            Declaration::Mod(m) => m.annotations.push(annotation),
            Declaration::Machine(s) => s.annotations.push(annotation),
        }
    }
}

#[derive(Clone, Debug, Eq)]
pub struct TypeDecl {
    pub name: CascadeString,
    pub inherits: Vec<CascadeString>,
    pub is_virtual: bool,
    pub is_trait: bool,
    pub is_extension: bool,
    pub expressions: Vec<Expression>,
    pub annotations: Annotations,
}

impl TypeDecl {
    pub fn new(
        name: CascadeString,
        inherits: Vec<CascadeString>,
        exprs: Vec<Expression>,
    ) -> TypeDecl {
        TypeDecl {
            name,
            inherits,
            is_virtual: false,
            is_trait: false,
            is_extension: false,
            expressions: exprs,
            annotations: Annotations::new(),
        }
    }

    pub fn set_extend(&mut self) {
        self.is_extension = true;
    }
}

impl Hash for TypeDecl {
    fn hash<H: Hasher>(&self, h: &mut H) {
        if self.is_extension {
            self.name.hash(h);
            self.is_extension.hash(h);
            self.inherits.hash(h);
            self.expressions.hash(h);
        } else {
            self.name.hash(h);
        }
    }
}

// Only one real Type declaration allowed per name
// Extensions compare other aspects
impl PartialEq for TypeDecl {
    fn eq(&self, other: &Self) -> bool {
        if self.is_extension || other.is_extension {
            self.name == other.name
                && self.is_extension == other.is_extension
                && self.expressions == other.expressions
                && self.inherits == other.inherits
                && self.annotations == other.annotations
        } else {
            self.name == other.name
        }
    }
}

impl Virtualable for TypeDecl {
    fn set_virtual(&mut self, _range: Range<usize>) -> Result<(), ParseErrorMsg> {
        self.is_virtual = true;
        Ok(())
    }

    fn set_trait(&mut self, _range: Range<usize>) -> Result<(), ParseErrorMsg> {
        self.is_trait = true;
        Ok(())
    }
}

pub fn get_cil_name(class_name: Option<&CascadeString>, func_name: &CascadeString) -> String {
    match &class_name {
        Some(class) => format!("{}-{}", class.get_cil_name(), func_name),
        None => func_name.to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CollectionDecl {
    pub name: CascadeString,
    #[allow(clippy::vec_box)]
    pub functions: Vec<Box<FuncDecl>>,
    pub annotations: Annotations,
}

impl CollectionDecl {
    #[allow(clippy::vec_box)]
    pub fn new(name: CascadeString, functions: Vec<Box<FuncDecl>>) -> Self {
        CollectionDecl {
            name,
            functions,
            annotations: Annotations::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FuncDecl {
    pub class_name: Option<CascadeString>,
    pub name: CascadeString,
    pub is_virtual: bool,
    pub args: Vec<DeclaredArgument>,
    pub body: Vec<Statement>,
    pub annotations: Annotations,
}

impl FuncDecl {
    pub fn new(name: CascadeString, args: Vec<DeclaredArgument>, body: Vec<Statement>) -> Self {
        FuncDecl {
            class_name: None,
            name,
            is_virtual: false,
            args,
            body,
            annotations: Annotations::new(),
        }
    }

    pub fn get_cil_name(&self) -> String {
        get_cil_name(self.class_name.as_ref(), &self.name)
    }

    pub fn add_annotation(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
    }
}

impl Virtualable for FuncDecl {
    fn set_virtual(&mut self, _range: Range<usize>) -> Result<(), ParseErrorMsg> {
        self.is_virtual = true;
        Ok(())
    }

    fn set_trait(&mut self, range: Range<usize>) -> Result<(), ParseErrorMsg> {
        Err(ParseErrorMsg::new(
            "The trait keyword cannot be applied to functions".to_string(),
            Some(range),
            "Remove the trait keyword".to_string(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IfBlock {
    pub keyword_range: Range<usize>,
    // TODO: boolean expression
    // TODO: populate statements
    pub if_statements: Vec<Statement>,
    pub else_statements: Vec<Statement>,
}

impl IfBlock {
    pub fn get_renamed(&self, renames: &BTreeMap<String, String>) -> Self {
        IfBlock {
            keyword_range: self.keyword_range.clone(),
            if_statements: self
                .if_statements
                .iter()
                .map(|s| s.get_renamed_statement(renames))
                .collect(),
            else_statements: self
                .else_statements
                .iter()
                .map(|s| s.get_renamed_statement(renames))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OptionalBlock {
    pub contents: Vec<Statement>,
}

impl OptionalBlock {
    pub fn new(contents: Vec<Statement>) -> Self {
        OptionalBlock { contents }
    }

    pub fn get_renamed(&self, renames: &BTreeMap<String, String>) -> Self {
        OptionalBlock {
            contents: self
                .contents
                .iter()
                .map(|s| s.get_renamed_statement(renames))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Statement {
    Call(Box<FuncCall>),
    LetBinding(Box<LetBinding>),
    IfBlock(Box<IfBlock>),
    OptionalBlock(Box<OptionalBlock>),
}

impl Statement {
    pub fn add_annotation(&mut self, annotation: Annotation) {
        match self {
            Statement::Call(c) => c.add_annotation(annotation),
            Statement::LetBinding(l) => l.add_annotation(annotation),
            Statement::IfBlock(_) => todo!(),
            Statement::OptionalBlock(_) => todo!(),
        }
    }

    // Create a new statement based on the original which changes all the keys in renames into the
    // associated value.  This is used when renaming function arguments during derivation.  If we
    // derive from two parents who have the same signature, but different names for an argument,
    // such as func(domain foo) {} and func(domain bar), then we rename to the argument names
    // combined with an underscore ("foo_bar" in this example)
    pub fn get_renamed_statement(&self, renames: &BTreeMap<String, String>) -> Self {
        match self {
            Statement::Call(c) => Statement::Call(Box::new(c.get_renamed(renames))),
            Statement::LetBinding(l) => Statement::LetBinding(Box::new(l.get_renamed(renames))),
            Statement::IfBlock(i) => Statement::IfBlock(Box::new(i.get_renamed(renames))),
            Statement::OptionalBlock(o) => {
                Statement::OptionalBlock(Box::new(o.get_renamed(renames)))
            }
        }
    }
}

// The function will take a vector of statements and reduce them down
// to only their function calls.
// Note: This will expand out all possible function calls regardless
// of boolean & optional block state.
pub fn get_all_func_calls(statements: &[Statement]) -> Vec<&FuncCall> {
    let mut ret_vec: Vec<&FuncCall> = Vec::new();
    for call in statements {
        match call {
            Statement::Call(call) => {
                ret_vec.push(call);
            }
            Statement::LetBinding(_) => {
                continue;
            }
            Statement::IfBlock(call) => {
                ret_vec.extend(get_all_func_calls(&call.if_statements));
                ret_vec.extend(get_all_func_calls(&call.else_statements));
            }
            Statement::OptionalBlock(call) => {
                ret_vec.extend(get_all_func_calls(&call.contents));
            }
        }
    }

    ret_vec
}

pub enum BuiltIns {
    AvRule,
    FileContext,
    PortCon,
    ResourceTransition,
    FileSystemContext,
    DomainTransition,
    InitialContext,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FuncCall {
    pub class_name: Option<CascadeString>,
    // This is the name of the domain/resource to cast to,
    // if we are explicitly calling their version of
    // a function.  If cast_name is None we will call
    // the function from the class_name.
    pub cast_name: Option<CascadeString>,
    pub name: CascadeString,
    // The second element is an optional typecast
    pub args: Vec<(Argument, Option<CascadeString>)>,
    pub annotations: Annotations,
    pub drop: bool,
}

impl FuncCall {
    pub fn new_with_casts(
        cn: Option<(CascadeString, Option<CascadeString>)>,
        n: CascadeString,
        a: Vec<(Argument, Option<CascadeString>)>,
    ) -> FuncCall {
        match cn {
            Some(cn) => FuncCall {
                class_name: Some(cn.0),
                cast_name: cn.1,
                name: n,
                args: a,
                annotations: Annotations::new(),
                drop: false,
            },
            None => FuncCall {
                class_name: None,
                cast_name: None,
                name: n,
                args: a,
                annotations: Annotations::new(),
                drop: false,
            },
        }
    }

    pub fn new(
        cn: Option<(CascadeString, Option<CascadeString>)>,
        n: CascadeString,
        a: Vec<Argument>,
    ) -> FuncCall {
        Self::new_with_casts(cn, n, a.into_iter().zip(iter::repeat(None)).collect())
    }

    pub fn check_builtin(&self) -> Option<BuiltIns> {
        if self.class_name.is_some() {
            None
        } else if constants::AV_RULES.iter().any(|i| *i == self.name) {
            Some(BuiltIns::AvRule)
        } else if self.name == constants::FILE_CONTEXT_FUNCTION_NAME {
            Some(BuiltIns::FileContext)
        } else if self.name == constants::PORTCON_FUNCTION_NAME {
            Some(BuiltIns::PortCon)
        } else if self.name == constants::FS_CONTEXT_FUNCTION_NAME {
            Some(BuiltIns::FileSystemContext)
        } else if self.name == constants::RESOURCE_TRANS_FUNCTION_NAME {
            Some(BuiltIns::ResourceTransition)
        } else if self.name == constants::DOMTRANS_FUNCTION_NAME {
            Some(BuiltIns::DomainTransition)
        } else if self.name == constants::INITIAL_CONTEXT_FUNCTION_NAME {
            Some(BuiltIns::InitialContext)
        } else {
            None
        }
    }

    pub fn is_avc(&self) -> bool {
        constants::AV_RULES.iter().any(|i| *i == self.name)
    }

    pub fn get_display_name(&self) -> String {
        match &self.class_name {
            Some(class) => format!("{}.{}", class, self.name),
            None => self.name.to_string(),
        }
    }

    pub fn get_cil_name(&self) -> String {
        get_cil_name(self.class_name.as_ref(), &self.name)
    }

    pub fn add_annotation(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
    }

    pub fn get_name_range(&self) -> Option<Range<usize>> {
        match &self.class_name {
            Some(c) => match (c.get_range(), self.name.get_range()) {
                (Some(s), Some(e)) => Some(s.start..e.end),
                _ => None,
            },
            None => self.name.get_range(),
        }
    }

    pub fn set_drop(&mut self) {
        self.drop = true;
    }

    pub fn get_renamed(&self, renames: &BTreeMap<String, String>) -> Self {
        let rename = |s: &CascadeString| {
            CascadeString::from(renames.get(&s.to_string()).unwrap_or(&s.to_string()) as &str)
        };
        FuncCall {
            class_name: self.class_name.as_ref().map(rename),
            cast_name: self.cast_name.as_ref().map(rename),
            name: rename(&self.name),
            args: self
                .args
                .iter()
                .map(|(arg, cast)| (arg.rename(renames), cast.as_ref().map(rename)))
                .collect(),
            annotations: self.annotations.clone(),
            drop: self.drop,
        }
    }

    // Handle this and casting to return the resolved class name
    pub fn get_true_class_name(
        &self,
        context: &Context,
        types: &TypeMap,
        file: Option<&SimpleFile<String, String>>,
    ) -> Result<String, CascadeErrors> {
        // The double as_ref() is kind of weird, but I think it's correct.  Option<T>::as_ref() does
        // &T, rather than T.as_ref().  Since Cascade has implemented the as_ref() trait, we need to
        // call it explicitly
        // convert_arg_this() handles this.*, then we handle a bare "this", since we'll be combining it
        // with a function name ourselves
        let name_to_resolve = self.cast_name.as_ref().map(|s| s.as_ref()).unwrap_or(
            self.class_name
                .as_ref()
                .map(|s| s.as_ref())
                .unwrap_or("this"),
        );

        let mut true_call_class = context
            .symbol_in_context(name_to_resolve, types)
            .map(|ti| ti.name.to_string())
            .unwrap_or_else(|| context.convert_arg_this(name_to_resolve));

        if true_call_class == "this" {
            true_call_class = match context.get_parent_type_name() {
                Some(type_name) => type_name.to_string(),
                None => {
                    return Err(CascadeErrors::from(
                        ErrorItem::make_compile_or_internal_error(
                            "Could not determine class for 'this.' function call",
                            file,
                            self.get_name_range(),
                            "Perhaps you meant to place the function in a resource or domain?",
                        ),
                    ))
                }
            };
        }
        Ok(true_call_class)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LetBinding {
    pub name: CascadeString,
    pub value: Argument,
    pub annotations: Annotations,
}

impl LetBinding {
    pub fn new(name: CascadeString, value: Argument) -> LetBinding {
        LetBinding {
            name,
            value,
            annotations: Annotations::new(),
        }
    }

    pub fn add_annotation(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
    }

    pub fn get_renamed(&self, renames: &BTreeMap<String, String>) -> Self {
        let rename = |s: &CascadeString| {
            CascadeString::from(renames.get(&s.to_string()).unwrap_or(&s.to_string()) as &str)
        };
        LetBinding {
            name: rename(&self.name),
            value: self.value.rename(renames),
            annotations: self.annotations.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Annotation {
    pub name: CascadeString,
    pub arguments: Vec<Argument>,
}

impl Annotation {
    pub fn new(name: CascadeString) -> Self {
        Annotation {
            name,
            arguments: Vec::new(),
        }
    }

    pub fn set_arguments(mut self, args: Vec<Argument>) -> Self {
        self.arguments = args;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Annotations {
    pub annotations: Vec<Annotation>,
}

impl Annotations {
    pub fn push(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
    }

    pub fn new() -> Self {
        Annotations {
            annotations: Vec::new(),
        }
    }

    pub fn has_annotation(&self, annotation_name: &str) -> bool {
        for a in &self.annotations {
            if a.name == annotation_name {
                return true;
            }
        }
        false
    }
}

#[derive(Clone, Debug, Eq)]
pub struct Port {
    pub low_port_num: u16,
    pub high_port_num: Option<u16>,
    pub range: Option<Range<usize>>,
}

impl Port {
    pub fn new(low_port_num: u16, range: Option<Range<usize>>) -> Self {
        Port {
            low_port_num,
            high_port_num: None,
            range,
        }
    }

    pub fn new_port_range(
        low_port_num: u16,
        high_port_num: u16,
        range: Option<Range<usize>>,
    ) -> Self {
        Port {
            low_port_num,
            high_port_num: Some(high_port_num),
            range,
        }
    }

    pub fn get_range(&self) -> Option<Range<usize>> {
        self.range.clone()
    }
}

impl PartialEq for Port {
    fn eq(&self, other: &Self) -> bool {
        self.low_port_num == other.low_port_num && self.high_port_num == other.high_port_num
    }
}

impl Hash for Port {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.low_port_num.hash(h);
        self.high_port_num.hash(h);
    }
}

// This is just for internal sorting, so it's fine if it's ordered on the low end of the range
// while ignoring the high
impl PartialOrd for Port {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Port {
    fn cmp(&self, other: &Self) -> Ordering {
        self.low_port_num.cmp(&other.low_port_num)
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let port_string = match self.high_port_num {
            Some(high) => format!("{}-{}", self.low_port_num, high),
            None => self.low_port_num.to_string(),
        };
        write!(f, "{}", port_string)
    }
}

impl From<&Port> for sexp::Sexp {
    fn from(p: &Port) -> sexp::Sexp {
        match p.high_port_num {
            Some(h) => sexp::list(&[
                sexp::atom_s(&p.low_port_num.to_string()),
                sexp::atom_s(&h.to_string()),
            ]),
            None => sexp::atom_s(&p.low_port_num.to_string()),
        }
    }
}

#[derive(Clone, Debug, Eq)]
pub struct IpAddr {
    inner: NetIpAddr,
    range: Option<Range<usize>>,
}

impl IpAddr {
    pub fn new(inner: NetIpAddr, range: Option<Range<usize>>) -> Self {
        IpAddr { inner, range }
    }

    pub fn get_range(&self) -> Option<Range<usize>> {
        self.range.clone()
    }
}

impl PartialEq for IpAddr {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Hash for IpAddr {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.inner.hash(h);
    }
}

impl PartialOrd for IpAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IpAddr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Argument {
    Var(CascadeString),
    Named(CascadeString, Box<Argument>),
    List(Vec<CascadeString>),
    Quote(CascadeString),
    Port(Port),
    IpAddr(IpAddr),
}

impl Argument {
    pub fn get_range(&self) -> Option<Range<usize>> {
        match self {
            Argument::Var(a) => a.get_range(),
            Argument::Named(n, a) => {
                if let (Some(l), Some(r)) = (n.get_range(), a.get_range()) {
                    Some(Range {
                        start: l.start,
                        end: r.end,
                    })
                } else {
                    None
                }
            }
            Argument::List(l) => CascadeString::slice_to_range(&l.iter().collect::<Vec<_>>()),
            Argument::Quote(a) => a.get_range(),
            Argument::Port(p) => p.get_range(),
            Argument::IpAddr(i) => i.get_range(),
        }
    }

    pub fn rename(&self, renames: &BTreeMap<String, String>) -> Self {
        let rename = |s: &CascadeString| {
            CascadeString::from(renames.get(&s.to_string()).unwrap_or(&s.to_string()) as &str)
        };
        match self {
            Argument::Var(s) => Argument::Var(rename(s)),
            Argument::Named(n, a) => Argument::Named(n.clone(), Box::new(a.rename(renames))),
            Argument::List(strings) => Argument::List(strings.iter().map(rename).collect()),
            Argument::Quote(_) | Argument::Port(_) | Argument::IpAddr(_) => self.clone(),
        }
    }
}

impl fmt::Display for Argument {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Argument::Var(a) => write!(f, "'{a}'"),
            Argument::Named(n, a) => write!(f, "{n}={a}"),
            Argument::List(_) => write!(f, "[TODO]",),
            Argument::Quote(a) => write!(f, "\"{a}\""),
            Argument::Port(p) => write!(f, "{p}"),
            Argument::IpAddr(i) => i.fmt(f),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeclaredArgument {
    pub param_type: CascadeString,
    pub is_list_param: bool,
    pub name: CascadeString,
    pub default: Option<Argument>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Module {
    pub name: CascadeString,
    pub is_virtual: bool,
    pub annotations: Annotations,
    pub domains: Vec<CascadeString>,
    pub resources: Vec<CascadeString>,
    pub modules: Vec<CascadeString>,
}

impl Module {
    pub fn new(name: CascadeString) -> Self {
        Module {
            name,
            is_virtual: false,
            annotations: Annotations::new(),
            domains: Vec::new(),
            resources: Vec::new(),
            modules: Vec::new(),
        }
    }

    pub fn add_annotation(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
    }

    pub fn set_fields(mut self, input: Vec<(CascadeString, CascadeString)>) -> Self {
        for i in input {
            let declared_type = i.0.to_string();
            if declared_type == constants::DOMAIN {
                self.domains.push(i.1);
            } else if declared_type == constants::RESOURCE {
                self.resources.push(i.1);
            } else if declared_type == constants::MODULE {
                self.modules.push(i.1);
            }
        }
        self
    }
}

// Virtual modules cannot be compile targets
// Please see doc/modules.md for more info
impl Virtualable for Module {
    fn set_virtual(&mut self, _range: Range<usize>) -> Result<(), ParseErrorMsg> {
        self.is_virtual = true;
        Ok(())
    }

    fn set_trait(&mut self, range: Range<usize>) -> Result<(), ParseErrorMsg> {
        Err(ParseErrorMsg::new(
            "The trait keyword cannot be applied to modules".to_string(),
            Some(range),
            "Remove the trait keyword".to_string(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Machine {
    pub name: CascadeString,
    pub annotations: Annotations,
    pub modules: Vec<CascadeString>,
    pub configurations: Vec<LetBinding>,
}

impl Machine {
    pub fn new(name: CascadeString) -> Self {
        Machine {
            name,
            annotations: Annotations::new(),
            modules: Vec::new(),
            configurations: Vec::new(),
        }
    }

    pub fn set_fields(mut self, input: Vec<MachineBody>) -> Self {
        for i in input {
            match i {
                MachineBody::Mod(m) => {
                    self.modules.push(m);
                }
                MachineBody::Config(l) => {
                    self.configurations.push(l);
                }
            }
        }

        // Insert the default configurations if they were not provided
        for (config_name, default_value) in constants::SYSTEM_CONFIG_DEFAULTS {
            if !self.configurations.iter().any(|c| c.name == *config_name) {
                self.configurations.push(LetBinding::new(
                    CascadeString::from(*config_name),
                    Argument::Var(CascadeString::from(default_value.to_string())),
                ));
            }
        }
        self
    }
}

impl Virtualable for Machine {
    fn set_virtual(&mut self, range: Range<usize>) -> Result<(), ParseErrorMsg> {
        Err(ParseErrorMsg::new(
            "Machines cannot be virtual".to_string(),
            Some(range),
            "Remove the virtual keyword".to_string(),
        ))
    }

    fn set_trait(&mut self, range: Range<usize>) -> Result<(), ParseErrorMsg> {
        Err(ParseErrorMsg::new(
            "The trait keyword cannot be applied to machines".to_string(),
            Some(range),
            "Remove the trait keyword".to_string(),
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MachineBody {
    Mod(CascadeString),
    Config(LetBinding),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_get_range() {
        let none_range = Argument::Var("foo".into());
        assert!(none_range.get_range().is_none());
        let var_range = Argument::Var(CascadeString::new("bar".into(), Range { start: 1, end: 2 }));
        assert!(matches!(
            var_range.get_range(),
            Some(Range { start: 1, end: 2 })
        ));

        let named_range1 = Argument::Named("foo".into(), Box::new(var_range.clone()));
        assert!(named_range1.get_range().is_none());
        let named_range2 = Argument::Named(
            CascadeString::new("foo".into(), Range { start: 3, end: 4 }),
            Box::new(var_range),
        );
        assert!(matches!(
            named_range2.get_range(),
            Some(Range { start: 3, end: 2 })
        ));

        let list_range = Argument::List(vec![
            CascadeString::new("a".into(), Range { start: 5, end: 6 }),
            CascadeString::new("b".into(), Range { start: 7, end: 8 }),
            CascadeString::new("c".into(), Range { start: 9, end: 10 }),
        ]);
        assert!(matches!(
            list_range.get_range(),
            Some(Range { start: 5, end: 10 })
        ));

        let quote_range = Argument::Quote(CascadeString::new(
            "foo".into(),
            Range { start: 11, end: 12 },
        ));
        assert!(matches!(
            quote_range.get_range(),
            Some(Range { start: 11, end: 12 })
        ));

        let named_range3 = Argument::Named(
            CascadeString::new("foo".into(), Range { start: 13, end: 14 }),
            Box::new(list_range),
        );
        assert!(matches!(
            named_range3.get_range(),
            Some(Range { start: 13, end: 10 })
        ));
    }

    #[test]
    fn set_module_fields() {
        let fields = vec![
            (CascadeString::from("domain"), CascadeString::from("a")),
            (CascadeString::from("resource"), CascadeString::from("b")),
            (CascadeString::from("module"), CascadeString::from("x")),
            (CascadeString::from("module"), CascadeString::from("y")),
            (CascadeString::from("module"), CascadeString::from("z")),
        ];
        let m = Module::new(CascadeString::from("module_name")).set_fields(fields);
        assert_eq!(m.domains.len(), 1);
        assert_eq!(m.resources.len(), 1);
        assert_eq!(m.modules.len(), 3);
        assert_eq!(m.domains[0].string, "a");
        assert_eq!(m.resources[0].string, "b");
        assert_eq!(m.modules[0].string, "x");
        assert_eq!(m.modules[1].string, "y");
        assert_eq!(m.modules[2].string, "z");
    }

    #[test]
    fn set_machine_fields() {
        let fields: Vec<MachineBody> = vec![
            MachineBody::Mod(CascadeString::from("mod")),
            MachineBody::Config(LetBinding::new(
                CascadeString::from("machine_type"),
                Argument::Var(CascadeString::from("standard")),
            )),
            MachineBody::Config(LetBinding::new(
                CascadeString::from("handle_unknown_perms"),
                Argument::Var(CascadeString::from("allow")),
            )),
        ];
        let s = Machine::new(CascadeString::from("machine_name")).set_fields(fields);
        assert_eq!(s.modules.len(), 1);
        assert_eq!(s.configurations.len(), 3);
        assert_eq!(s.modules[0].string, "mod");
        assert_eq!(s.configurations[0].name.string, "machine_type");
        assert_eq!(s.configurations[1].name.string, "handle_unknown_perms");
        assert_eq!(s.configurations[2].name.string, "monolithic");
        assert_eq!(
            s.configurations[2].value,
            Argument::Var(CascadeString::from("true"))
        );
    }

    // According to the rust docs:
    // https://doc.rust-lang.org/std/hash/trait.Hash.html
    // "When implementing both Hash and Eq, it is important that the following property holds:"
    // k1 == k2 -> hash(k1) == hash(k2)
    //
    // If we derive PartialEq, Eq and Hash, we get this for free.  In the cases where we don't, we
    // must provide that property ourselves.  This test is to validate that that is true.
    // The following types in this module manually implement PartialEq and Hash:
    // CascadeString
    // TypeDecl
    // Port
    // IpAddr
    use std::collections::hash_map::DefaultHasher;
    #[test]
    fn hash_ord_equality() {
        fn hash<T>(item: T) -> u64
        where
            T: Hash,
        {
            let mut hasher = DefaultHasher::new();
            item.hash(&mut hasher);
            hasher.finish()
        }

        let a = CascadeString::from("foo".to_string());
        let b = CascadeString::new("foo".to_string(), 10..20);
        assert_eq!(a, b);
        assert_eq!(hash(a), hash(b));

        let c = TypeDecl {
            name: CascadeString::from("foo".to_string()),
            inherits: Vec::new(),
            is_virtual: true,
            is_trait: true,
            is_extension: false,
            expressions: Vec::new(),
            annotations: Annotations::new(),
        };

        let d = TypeDecl {
            name: CascadeString::from("foo".to_string()),
            inherits: vec![CascadeString::from("bar".to_string())],
            is_virtual: false,
            is_trait: false,
            is_extension: false,
            expressions: vec![Expression::Error],
            annotations: Annotations {
                annotations: vec![Annotation::new("some_annotation".into())],
            },
        };
        assert_eq!(c, d);
        assert_eq!(hash(c.clone()), hash(d));

        let mut c_extension = c.clone();
        c_extension.is_extension = true;

        assert_ne!(c, c_extension);
        assert_ne!(hash(c), hash(c_extension.clone()));
        assert_eq!(hash(c_extension.clone()), hash(c_extension));

        let e = Port {
            low_port_num: 2,
            high_port_num: Some(3),
            range: None,
        };

        let f = Port {
            low_port_num: 2,
            high_port_num: Some(3),
            range: Some(8..9),
        };

        assert_eq!(e, f);
        assert_eq!(hash(e), hash(f));

        let g = IpAddr::new("127.0.0.1".parse().unwrap(), None);
        let h = IpAddr::new("127.0.0.1".parse().unwrap(), Some(8..10));

        assert_eq!(g, h);
        assert_eq!(hash(g), hash(h));
    }

    #[test]
    fn test_get_renamed() {
        let statement1 = Statement::Call(Box::new(FuncCall::new(
            Some(("old_name".into(), Some("old_name".into()))),
            "old_name".into(),
            vec![Argument::Var("old_name".into())],
        )));

        let statement2 = statement1.clone();

        let statement3 = Statement::LetBinding(Box::new(LetBinding::new(
            "old_name".into(),
            Argument::Quote("unchanged".into()),
        )));

        let opt_block =
            Statement::OptionalBlock(Box::new(OptionalBlock::new(vec![statement3, statement2])));

        let if_block = Statement::IfBlock(Box::new(IfBlock {
            keyword_range: 1..2,
            if_statements: vec![statement1],
            else_statements: vec![opt_block],
        }));

        let mut renames = BTreeMap::new();
        renames.insert("old_name".to_string(), "new_name".to_string());
        renames.insert("unchanged".to_string(), "changed_in_quote".to_string());
        let result = if_block.get_renamed_statement(&renames);

        // matches!() won't work because matching against box patterns is nightly only
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("new_name"));
        assert!(!debug_str.contains("old_name"));
        assert!(debug_str.contains("unchanged"));
        assert!(!debug_str.contains("changed_in_quote"));
    }
}
