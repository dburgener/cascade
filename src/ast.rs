// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use std::cmp::Ordering;
use std::fmt;
use std::ops::Range;

use codespan_reporting::files::SimpleFile;

use crate::constants;

#[derive(Clone, Debug, Eq, Hash)]
pub struct HLLString {
    string: String,
    range: Option<Range<usize>>,
}

impl fmt::Display for HLLString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.string)
    }
}

impl HLLString {
    pub fn new(string: String, range: Range<usize>) -> Self {
        HLLString {
            string,
            range: Some(range),
        }
    }

    pub fn get_range(&self) -> Option<Range<usize>> {
        self.range.clone()
    }

    // TODO: This doesn't include the brackets at the end, but we haven't saved enough info from
    // the AST for that
    pub fn vec_to_range(v: &Vec<&HLLString>) -> Option<Range<usize>> {
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
}

impl AsRef<str> for HLLString {
    fn as_ref(&self) -> &str {
        self.string.as_str()
    }
}

impl From<String> for HLLString {
    fn from(s: String) -> HLLString {
        HLLString {
            string: s,
            range: None,
        }
    }
}

impl From<&str> for HLLString {
    fn from(s: &str) -> HLLString {
        HLLString {
            string: s.to_string(),
            range: None,
        }
    }
}

impl PartialEq for HLLString {
    fn eq(&self, other: &Self) -> bool {
        self.string == other.string
    }
}

impl PartialEq<String> for HLLString {
    fn eq(&self, other: &String) -> bool {
        self.string == *other
    }
}

impl PartialEq<str> for HLLString {
    fn eq(&self, other: &str) -> bool {
        self.string == other
    }
}

impl PartialEq<HLLString> for str {
    fn eq(&self, other: &HLLString) -> bool {
        self == other.string
    }
}

impl PartialEq<&str> for HLLString {
    fn eq(&self, other: &&str) -> bool {
        self.string == *other
    }
}

impl PartialEq<HLLString> for &str {
    fn eq(&self, other: &HLLString) -> bool {
        *self == other.string
    }
}

impl PartialOrd for HLLString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.string.partial_cmp(&other.string)
    }
}

impl Ord for HLLString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.string.cmp(&other.string)
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
}

impl Expression {
    pub fn set_class_name_if_decl(&mut self, name: HLLString) {
        if let Expression::Decl(Declaration::Func(d)) = self {
            d.class_name = Some(name)
        }
    }

    pub fn add_annotation(&mut self, annotation: Annotation) {
        match self {
            Expression::Decl(d) => d.add_annotation(annotation),
            Expression::Stmt(s) => s.add_annotation(annotation),
        }
    }
}

pub trait Virtualable {
    fn set_virtual(&mut self);
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Declaration {
    Type(Box<TypeDecl>),
    Func(Box<FuncDecl>),
}

impl Virtualable for Declaration {
    fn set_virtual(&mut self) {
        match self {
            Declaration::Type(t) => t.set_virtual(),
            Declaration::Func(_f) => {} // TODO
        }
    }
}

impl Declaration {
    pub fn add_annotation(&mut self, annotation: Annotation) {
        match self {
            Declaration::Type(t) => t.annotations.push(annotation),
            Declaration::Func(f) => f.annotations.push(annotation),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash)]
pub struct TypeDecl {
    pub name: HLLString,
    pub inherits: Vec<HLLString>,
    pub is_virtual: bool,
    pub expressions: Vec<Expression>,
    pub annotations: Annotations,
}

impl TypeDecl {
    pub fn new(name: HLLString, inherits: Vec<HLLString>, exprs: Vec<Expression>) -> TypeDecl {
        TypeDecl {
            name,
            inherits,
            is_virtual: false,
            expressions: exprs,
            annotations: Annotations::new(),
        }
    }
}

// Only one Type declaration allowed per name
impl PartialEq for TypeDecl {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Virtualable for TypeDecl {
    fn set_virtual(&mut self) {
        self.is_virtual = true;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FuncDecl {
    pub class_name: Option<HLLString>,
    pub name: HLLString,
    pub args: Vec<DeclaredArgument>,
    pub body: Vec<Statement>,
    pub annotations: Annotations,
}

impl FuncDecl {
    pub fn get_cil_name(&self) -> String {
        match &self.class_name {
            Some(class) => format!("{}-{}", class, self.name),
            None => self.name.to_string(),
        }
    }

    pub fn add_annotation(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Statement {
    Call(Box<FuncCall>),
}

impl Statement {
    pub fn add_annotation(&mut self, annotation: Annotation) {
        match self {
            Statement::Call(c) => c.add_annotation(annotation),
        }
    }
}

pub enum BuiltIns {
    AvRule,
    FileContext,
    DomainTransition,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FuncCall {
    pub class_name: Option<HLLString>,
    pub name: HLLString,
    pub args: Vec<Argument>,
    pub annotations: Annotations,
}

impl FuncCall {
    pub fn new(cn: Option<HLLString>, n: HLLString, a: Vec<Argument>) -> FuncCall {
        FuncCall {
            class_name: cn,
            name: n,
            args: a,
            annotations: Annotations::new(),
        }
    }

    pub fn check_builtin(&self) -> Option<BuiltIns> {
        if let Some(_) = self.class_name {
            return None;
        }
        if constants::AV_RULES.iter().any(|i| *i == self.name) {
            return Some(BuiltIns::AvRule);
        }
        if self.name == constants::FILE_CONTEXT_FUNCTION_NAME {
            return Some(BuiltIns::FileContext);
        }
        if self.name == constants::DOMTRANS_FUNCTION_NAME {
            return Some(BuiltIns::DomainTransition);
        }
        None
    }

    pub fn get_display_name(&self) -> String {
        match &self.class_name {
            Some(class) => format!("{}.{}", class, self.name),
            None => self.name.to_string(),
        }
    }

    pub fn get_cil_name(&self) -> String {
        match &self.class_name {
            Some(class) => format!("{}-{}", class, self.name),
            None => self.name.to_string(),
        }
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
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Annotation {
    pub name: HLLString,
    pub arguments: Vec<Argument>,
}

impl Annotation {
    pub fn new(name: HLLString) -> Self {
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Argument {
    Var(HLLString),
    List(Vec<HLLString>),
    Quote(HLLString),
}

impl Argument {
    pub fn get_range(&self) -> Option<Range<usize>> {
        match self {
            Argument::Var(a) => a.get_range(),
            Argument::List(l) => HLLString::vec_to_range(&l.iter().collect()),
            Argument::Quote(a) => a.get_range(),
        }
    }
}

impl fmt::Display for Argument {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Argument::Var(a) => write!(f, "'{}'", a),
            Argument::List(_) => write!(f, "[TODO]",),
            Argument::Quote(a) => write!(f, "\"{}\"", a),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeclaredArgument {
    pub param_type: HLLString,
    pub is_list_param: bool,
    pub name: HLLString,
}
