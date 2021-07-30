use codespan_reporting::diagnostic::{Diagnostic, Label};
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term;
use codespan_reporting::term::termcolor::{ColorChoice, StandardStream};
use lalrpop_util::lexer::Token;
use lalrpop_util::ParseError;
use std::error::Error;
use std::fmt;
use std::io;
use std::ops::Range;

#[derive(Clone, Debug)]
pub struct HLLCompileError {
    pub filename: String,
    pub lineno: u32,
    pub msg: String,
}

impl fmt::Display for HLLCompileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{} {}", self.filename, self.lineno, self.msg)
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
pub struct HLLParseError {
    pub file: SimpleFile<String, String>,
    pub diagnostic: Diagnostic<()>,
}

impl Error for HLLParseError {}

impl fmt::Display for HLLParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.diagnostic.message)
    }
}

struct ParseErrorMsg {
    issue: String,
    range: Option<Range<usize>>,
    help: String,
}

impl From<ParseError<usize, Token<'_>, &str>> for ParseErrorMsg {
    fn from(error: ParseError<usize, Token<'_>, &str>) -> Self {
        match error {
            ParseError::InvalidToken { location } => ParseErrorMsg {
                issue: "Unknown character".into(),
                range: Some(location..location),
                help: String::new(),
            },
            ParseError::UnrecognizedEOF { location, expected } => ParseErrorMsg {
                issue: "Unexpected end of file".into(),
                range: Some(location..location),
                help: format!("Expected {}", expected.join(" or ")),
            },
            ParseError::UnrecognizedToken {
                token: (l, t, r),
                expected,
            } => ParseErrorMsg {
                issue: if r - l == 1 {
                    format!("Unexpected character \"{}\"", t.1)
                } else {
                    format!("Unexpected word \"{}\"", t.1)
                },
                range: Some(l..r),
                help: format!("Expected {}", expected.join(" or ")),
            },
            ParseError::ExtraToken { token: (l, t, r) } => ParseErrorMsg {
                issue: if r - l == 1 {
                    format!("Unintended character \"{}\"", t.1)
                } else {
                    format!("Unintended word \"{}\"", t.1)
                },
                range: Some(l..r),
                help: String::new(),
            },
            ParseError::User { error } => ParseErrorMsg {
                issue: error.into(),
                range: None,
                help: String::new(),
            },
        }
    }
}

impl HLLParseError {
    pub fn new(
        error: ParseError<usize, Token<'_>, &str>,
        file_name: String,
        policy: String,
    ) -> Self {
        let msg: ParseErrorMsg = error.into();
        let diagnostic = Diagnostic::error().with_message(msg.issue);
        HLLParseError {
            file: SimpleFile::new(file_name, policy),
            diagnostic: match msg.range {
                None => diagnostic,
                Some(range) => diagnostic.with_labels(vec![
                    Label::primary((), range.clone()).with_message(msg.help)
                ]),
            },
        }
    }

    pub fn print_diagnostic(&self) {
        let writer = StandardStream::stderr(ColorChoice::Auto);
        let config = term::Config::default();
        // Ignores print errors.
        let _ = term::emit(&mut writer.lock(), &config, &self.file, &self.diagnostic);
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
            HLLErrorItem::Parse(e) => write!(f, "Parsing Error: {}", e),
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

#[derive(Debug)]
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
