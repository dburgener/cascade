use std::fmt;

use crate::constants;

#[derive(Debug)]
pub struct Policy {
    pub exprs: Vec<Expression>,
}

impl Policy {
    pub fn new(exprs: Vec<Expression>) -> Policy {
        Policy { exprs: exprs }
    }
}

#[derive(Debug)]
pub enum Expression {
    Decl(Declaration),
    Stmt(Statement),
}

impl Expression {
    pub fn set_class_name_if_decl(&mut self, name: String) {
        match self {
            Expression::Decl(Declaration::Func(d)) => d.class_name = Some(name),
            _ => (),
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

#[derive(Debug)]
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

#[derive(Debug)]
pub struct TypeDecl {
    pub name: String,
    pub inherits: Vec<String>,
    pub is_virtual: bool,
    pub expressions: Vec<Expression>,
    pub annotations: Annotations,
}

impl TypeDecl {
    pub fn new(name: String, inherits: Vec<String>, exprs: Vec<Expression>) -> TypeDecl {
        TypeDecl {
            name: name,
            inherits: inherits,
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

#[derive(Debug)]
pub struct FuncDecl {
    pub class_name: Option<String>,
    pub name: String,
    pub args: Vec<DeclaredArgument>,
    pub body: Vec<Statement>,
    pub annotations: Annotations,
}

impl FuncDecl {
    pub fn get_cil_name(&self) -> String {
        match &self.class_name {
            Some(class) => format!("{}-{}", class, self.name),
            None => self.name.clone(),
        }
    }

    pub fn add_annotation(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct FuncCall {
    pub class_name: Option<String>,
    pub name: String,
    pub args: Vec<Argument>,
    pub annotations: Annotations,
}

impl FuncCall {
    pub fn new(cn: Option<String>, n: String, a: Vec<Argument>) -> FuncCall {
        FuncCall {
            class_name: cn,
            name: n,
            args: a,
            annotations: Annotations::new(),
        }
    }

    pub fn check_builtin(&self) -> Option<BuiltIns> {
        match self.class_name {
            Some(_) => return None,
            None => (),
        }
        if constants::AV_RULES.iter().any(|&i| i == &self.name) {
            return Some(BuiltIns::AvRule);
        }
        if &self.name == constants::FILE_CONTEXT_FUNCTION_NAME {
            return Some(BuiltIns::FileContext);
        }
        if &self.name == constants::DOMTRANS_FUNCTION_NAME {
            return Some(BuiltIns::DomainTransition);
        }
        None
    }

    pub fn get_display_name(&self) -> String {
        match &self.class_name {
            Some(class) => format!("{}.{}", class, self.name),
            None => self.name.clone(),
        }
    }

    pub fn get_cil_name(&self) -> String {
        match &self.class_name {
            Some(class) => format!("{}-{}", class, self.name),
            None => self.name.clone(),
        }
    }

    pub fn add_annotation(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
    }
}

#[derive(Debug)]
pub struct Annotation {
    pub name: String,
}

#[derive(Debug)]
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

#[derive(Debug)]
pub enum Argument {
    Var(String),
    List(Vec<String>),
    Quote(String),
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

#[derive(Debug)]
pub struct DeclaredArgument {
    pub param_type: String,
    pub is_list_param: bool,
    pub name: String,
}
