// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use codespan_reporting::diagnostic::{Diagnostic, Label};
use codespan_reporting::files::SimpleFile;
use codespan_reporting::term;
use codespan_reporting::term::termcolor::{ColorChoice, StandardStream};
use lalrpop_util::lexer::Token;
use lalrpop_util::ParseError;
use std::fmt;
use std::io;
use std::ops::Range;
use thiserror::Error;

#[derive(Error, Clone, Debug)]
#[error("{diagnostic}")]
pub struct HLLCompileError {
    pub diagnostic: Diag,
    pub file: SimpleFile<String, String>,
}

#[derive(Clone, Debug)]
pub struct Diag {
    pub inner: Diagnostic<()>,
}

impl From<Diagnostic<()>> for Diag {
    fn from(d: Diagnostic<()>) -> Self {
        Self { inner: d }
    }
}

impl fmt::Display for Diag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        //write!(f, "{}:{} {}", self.filename, self.lineno, self.msg)
        write!(f, "{}", self.inner.message)
    }
}

impl HLLCompileError {
    pub fn new(
        msg: &str,
        file: &SimpleFile<String, String>,
        range: Option<Range<usize>>,
        help: &str,
    ) -> Self {
        let diagnostic = Diagnostic::error().with_message(msg);

        let diagnostic = match range {
            None => diagnostic,
            Some(r) => diagnostic.with_labels(vec![Label::primary((), r).with_message(help)]),
        };
        HLLCompileError {
            diagnostic: diagnostic.into(),
            file: file.clone(),
        }
    }
    pub fn print_diagnostic(&self) {
        let writer = StandardStream::stderr(ColorChoice::Auto);
        let config = term::Config::default();
        // Ignores print errors.
        let _ = term::emit(
            &mut writer.lock(),
            &config,
            &self.file,
            &self.diagnostic.inner,
        );
    }
}

#[derive(Error, Clone, Debug)]
#[error("TODO")]
pub struct HLLInternalError {}

#[derive(Error, Clone, Debug)]
#[error("{diagnostic}")]
pub struct HLLParseError {
    pub diagnostic: Diag,
    pub file: SimpleFile<String, String>,
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
            }
            .into(),
        }
    }

    pub fn print_diagnostic(&self) {
        let writer = StandardStream::stderr(ColorChoice::Auto);
        let config = term::Config::default();
        // Ignores print errors.
        let _ = term::emit(
            &mut writer.lock(),
            &config,
            &self.file,
            &self.diagnostic.inner,
        );
    }
}

#[derive(Error, Debug)]
pub enum HLLErrorItem {
    #[error("Compilation error: {0}")]
    Compile(#[from] HLLCompileError),
    #[error("Internal error: {0}")]
    Internal(#[from] HLLInternalError),
    #[error("Parsing error: {0}")]
    Parse(#[from] HLLParseError),
    // TODO: Replace IO() with semantic errors wraping io::Error.
    #[error("I/O error: {0}")]
    IO(#[from] io::Error),
}

impl HLLErrorItem {
    pub fn make_compile_or_internal_error(
        msg: &str,
        file: Option<&SimpleFile<String, String>>,
        range: Option<Range<usize>>,
        help: &str,
    ) -> Self {
        match file {
            Some(f) => HLLErrorItem::Compile(HLLCompileError::new(msg, f, range, help)),
            None => HLLErrorItem::Internal(HLLInternalError {}),
        }
    }
}

impl From<HLLErrorItem> for Vec<HLLErrorItem> {
    fn from(error: HLLErrorItem) -> Self {
        vec![error]
    }
}

#[derive(Error, Debug)]
pub struct HLLErrors {
    errors: Vec<HLLErrorItem>,
}

impl HLLErrors {
    pub fn new() -> Self {
        HLLErrors { errors: Vec::new() }
    }

    pub fn add_error<T>(&mut self, error: T)
    where
        T: Into<HLLErrorItem>,
    {
        self.errors.push(error.into());
    }

    fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn append(&mut self, mut other: HLLErrors) {
        self.errors.append(&mut other.errors);
    }

    pub fn into_result_with<F, T>(self, ok_with: F) -> Result<T, HLLErrors>
    where
        F: FnOnce() -> T,
    {
        if self.is_empty() {
            Ok(ok_with())
        } else {
            Err(self)
        }
    }

    pub fn into_result<T>(self, ok: T) -> Result<T, HLLErrors> {
        self.into_result_with(|| ok)
    }

    /// Enables to easily stop a workflow after a failed major step.  This is
    /// useful to avoid accumulating more errors that may be hard to understand
    /// because of unsatisfied prerequiste.
    ///
    /// For a multi-step workflow, it works as follow:
    /// 1. creates an accumulator with `let mut errors = HLLErrors::new();`
    /// 2. within a major step accumulate errors with `errors.add_error(e);`
    /// 3. between major steps check for any errors with `errors =
    ///    errors.into_result_self()?;` which returns `Err(self)` if there are
    ///    any. If there aren't, just keep the empty list and proceed.
    pub fn into_result_self(self) -> Result<Self, Self> {
        if self.is_empty() {
            Ok(self)
        } else {
            Err(self)
        }
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
}

impl From<HLLErrorItem> for HLLErrors {
    fn from(error: HLLErrorItem) -> Self {
        HLLErrors {
            errors: vec![error],
        }
    }
}

impl From<HLLCompileError> for HLLErrors {
    fn from(error: HLLCompileError) -> Self {
        HLLErrors::from(HLLErrorItem::from(error))
    }
}

impl Iterator for HLLErrors {
    type Item = HLLErrorItem;
    fn next(&mut self) -> Option<Self::Item> {
        self.errors.pop() // TODO: This reverses the list of errors
    }
}

impl fmt::Display for HLLErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let num_errors = self.errors.len();
        let s = match num_errors {
            0 => return writeln!(f, "no error"),
            1 => "",
            _ => "s",
        };
        writeln!(f, "{} error{}:", num_errors, s)?;
        for (i, e) in self.errors.iter().enumerate() {
            writeln!(f, "{}: {:#?}", i + 1, e)?
        }
        Ok(())
    }
}
