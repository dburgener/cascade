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
pub enum HLLError {
    Compile(HLLCompileError),
    Internal(HLLInternalError),
    Parse(HLLParseError),
    IO(io::Error),
}

impl fmt::Display for HLLError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HLLError::Compile(e) => write!(f, "Error: {}", e),
            HLLError::Parse(e) => write!(f, "Error: {}", e),
            HLLError::Internal(e) => write!(f, "Internal Error: {}", e),
            HLLError::IO(e) => write!(f, "IO Error: {}", e),
        }
    }
}

impl From<HLLError> for Vec<HLLError> {
    fn from(error: HLLError) -> Self {
        vec![error]
    }
}

impl From<io::Error> for HLLError {
    fn from(error: io::Error) -> Self {
        HLLError::IO(error)
    }
}

impl<'a> From<lalrpop_util::ParseError<usize, lalrpop_util::lexer::Token<'a>, &'static str>>
    for HLLError
{
    fn from(
        error: lalrpop_util::ParseError<usize, lalrpop_util::lexer::Token<'a>, &'static str>,
    ) -> Self {
        // TODO
        HLLError::Parse(HLLParseError {})
    }
}
