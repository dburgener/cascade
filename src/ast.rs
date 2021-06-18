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
    inherits: Vec<String>,
    is_virtual: bool,
    expressions: Vec<Expression>,
}

impl TypeDecl {
    pub fn new(n: String, i: Vec<String>, e: Vec<Expression>) -> TypeDecl {
        TypeDecl { name: n, inherits: i, is_virtual: false, expressions: e }
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
    Tmp,
}

#[derive(Debug)]
pub struct Annotation {}

#[derive(Debug)]
pub enum Argument {
    Var(String),
    List(Vec<String>),
    Quote(String),
}
