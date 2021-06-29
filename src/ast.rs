#[derive(Debug)]
pub struct Policy {
    pub exprs: Vec<Expression>,
}

impl Policy {
    pub fn new(v: Vec<Expression>) -> Policy {
        Policy {
            exprs: v,
        }
    }
}

#[derive(Debug)]
pub enum Expression {
    Decl(Declaration),
    Stmt(Statement),
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
            Declaration::Func(f) => {}, // TODO
        }
    }
}

#[derive(Debug)]
pub struct TypeDecl {
    pub name: String,
    pub inherits: Vec<String>,
    is_virtual: bool,
    expressions: Vec<Expression>,
}

impl TypeDecl {
    pub fn new(n: String, i: Vec<String>, e: Vec<Expression>) -> TypeDecl {
        TypeDecl { name: n, inherits: i, is_virtual: false, expressions: e }
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
pub struct FuncDecl {}

#[derive(Debug)]
pub enum Statement {
    Call(Box<FuncCall>),
}

#[derive(Debug)]
pub struct FuncCall {
    class_name: Option<String>,
    name: String,
    args: Vec<Argument>,
}

impl FuncCall {
    pub fn new(cn: Option<String>, n: String, a: Vec<Argument>) -> FuncCall {
        FuncCall {
            class_name: cn,
            name: n,
            args: a
        }
    }
}

#[derive(Debug)]
pub struct Annotation {}

#[derive(Debug)]
pub enum Argument {
    Var(String),
    List(Vec<String>),
    Quote(String),
}
