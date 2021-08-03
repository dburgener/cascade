use std::error::Error;
use std::fmt;
use std::io;

#[derive(Clone, Debug)]
pub struct HLLCompileError {
    pub filename: String,
    pub lineno: u32,
    pub msg: String,
}

impl fmt::Display for HLLCompileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TODO")
    }
}

impl Error for HLLCompileError {}

#[derive(Clone, Debug)]
pub struct HLLInternalError {}
impl Error for HLLInternalError {}

impl fmt::Display for HLLInternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TODO")
    }
}

#[derive(Clone, Debug)]
pub struct HLLParseError {}
impl Error for HLLParseError {}

impl fmt::Display for HLLParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TODO")
    }
}

#[derive(Debug)]
pub enum HLLErrorItem {
    Compile(HLLCompileError),
    Internal(HLLInternalError),
    Parse(HLLParseError),
    IO(io::Error),
}

impl fmt::Display for HLLErrorItem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HLLErrorItem::Compile(e) => write!(f, "Error: {}", e),
            HLLErrorItem::Parse(e) => write!(f, "Error: {}", e),
            HLLErrorItem::Internal(e) => write!(f, "Internal Error: {}", e),
            HLLErrorItem::IO(e) => write!(f, "IO Error: {}", e),
        }
    }
}

impl From<HLLErrorItem> for Vec<HLLErrorItem> {
    fn from(error: HLLErrorItem) -> Self {
        vec![error]
    }
}

impl From<io::Error> for HLLErrorItem {
    fn from(error: io::Error) -> Self {
        HLLErrorItem::IO(error)
    }
}

impl<'a> From<lalrpop_util::ParseError<usize, lalrpop_util::lexer::Token<'a>, &'static str>>
    for HLLErrorItem
{
    fn from(
        error: lalrpop_util::ParseError<usize, lalrpop_util::lexer::Token<'a>, &'static str>,
    ) -> Self {
        // TODO
        HLLErrorItem::Parse(HLLParseError {})
    }
}

pub struct HLLErrors {
    errors: Vec<HLLErrorItem>,
}

impl HLLErrors {
    pub fn new() -> Self {
        HLLErrors { errors: Vec::new() }
    }

    pub fn add_error(&mut self, error: HLLErrorItem) {
        self.errors.push(error);
    }

    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn append(&mut self, other: &mut HLLErrors) {
        self.errors.append(&mut other.errors);
    }
}

impl From<HLLErrorItem> for HLLErrors {
    fn from(error: HLLErrorItem) -> Self {
        HLLErrors {
            errors: vec![error],
        }
    }
}

impl Iterator for HLLErrors {
    type Item = HLLErrorItem;
    fn next(&mut self) -> Option<Self::Item> {
        self.errors.pop() // TODO: This reverses the list of errors
    }
}
