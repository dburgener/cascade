// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Range;

use codespan_reporting::files::SimpleFile;

use crate::constants;

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
        self.string.partial_cmp(&other.string)
    }
}

impl Ord for CascadeString {
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

pub trait Virtualable {
    fn set_virtual(&mut self);
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Declaration {
    Type(Box<TypeDecl>),
    Func(Box<FuncDecl>),
    Mod(Module),
}

impl Virtualable for Declaration {
    fn set_virtual(&mut self) {
        match self {
            Declaration::Type(t) => t.set_virtual(),
            Declaration::Func(f) => f.set_virtual(),
            Declaration::Mod(m) => m.set_virtual(),
        }
    }
}

impl Declaration {
    pub fn add_annotation(&mut self, annotation: Annotation) {
        match self {
            Declaration::Type(t) => t.annotations.push(annotation),
            Declaration::Func(f) => f.annotations.push(annotation),
            Declaration::Mod(m) => m.annotations.push(annotation),
        }
    }
}

#[derive(Clone, Debug, Eq)]
pub struct TypeDecl {
    pub name: CascadeString,
    pub inherits: Vec<CascadeString>,
    pub is_virtual: bool,
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
            expressions: exprs,
            annotations: Annotations::new(),
        }
    }
}

impl Hash for TypeDecl {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.name.hash(h);
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

pub fn get_cil_name(class_name: Option<&CascadeString>, func_name: &CascadeString) -> String {
    match &class_name {
        Some(class) => format!("{}-{}", class, func_name),
        None => func_name.to_string(),
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
    fn set_virtual(&mut self) {
        self.is_virtual = true;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Statement {
    Call(Box<FuncCall>),
    LetBinding(Box<LetBinding>),
    IfBlock, // TODO
}

impl Statement {
    pub fn add_annotation(&mut self, annotation: Annotation) {
        match self {
            Statement::Call(c) => c.add_annotation(annotation),
            Statement::LetBinding(l) => l.add_annotation(annotation),
            Statement::IfBlock => todo!(),
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
    pub class_name: Option<CascadeString>,
    pub name: CascadeString,
    pub args: Vec<Argument>,
    pub annotations: Annotations,
}

impl FuncCall {
    pub fn new(cn: Option<CascadeString>, n: CascadeString, a: Vec<Argument>) -> FuncCall {
        FuncCall {
            class_name: cn,
            name: n,
            args: a,
            annotations: Annotations::new(),
        }
    }

    pub fn check_builtin(&self) -> Option<BuiltIns> {
        if self.class_name.is_some() {
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Argument {
    Var(CascadeString),
    Named(CascadeString, Box<Argument>),
    List(Vec<CascadeString>),
    Quote(CascadeString),
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
        }
    }
}

impl fmt::Display for Argument {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Argument::Var(a) => write!(f, "'{}'", a),
            Argument::Named(n, a) => write!(f, "{}={}", n, a),
            Argument::List(_) => write!(f, "[TODO]",),
            Argument::Quote(a) => write!(f, "\"{}\"", a),
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
    fn set_virtual(&mut self) {
        self.is_virtual = true;
    }
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
        let mut fields = Vec::new();
        fields.push((CascadeString::from("domain"), CascadeString::from("a")));
        fields.push((CascadeString::from("resource"), CascadeString::from("b")));
        fields.push((CascadeString::from("module"), CascadeString::from("x")));
        fields.push((CascadeString::from("module"), CascadeString::from("y")));
        fields.push((CascadeString::from("module"), CascadeString::from("z")));
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
}
