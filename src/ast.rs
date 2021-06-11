#[derive(Debug)]
pub struct Policy {
    exprs: Vec<Expression>,
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

#[derive(Debug)]
pub enum Declaration {
    Type(Box<TypeDecl>),
    Func(Box<FuncDecl>),
}

#[derive(Debug)]
pub struct TypeDecl {}

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
