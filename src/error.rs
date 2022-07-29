// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT

// If this is named "Backtrace", thiserror assumes its the std::backtrace
// which is only available in nightly, which causes errors on stable.
// https://github.com/dtolnay/thiserror/issues/130
// If Cascade moves to nightly or std::backtrace comes to stable, then
// thiserror can handle backtraces for us with minimal effort
use backtrace::Backtrace as BacktraceCrate;
use codespan_reporting::diagnostic::{Diagnostic, Label};
use codespan_reporting::files::{SimpleFile, SimpleFiles};
use codespan_reporting::term;
use codespan_reporting::term::termcolor::{ColorChoice, StandardStream};
use lalrpop_util::lexer::Token;
use lalrpop_util::ParseError as LalrpopParseError;
use std::fmt;
use std::io;
use std::ops::Range;
use thiserror::Error;

#[derive(Error, Clone, Debug)]
#[error("{diagnostic}")]
pub struct CompileError {
    pub diagnostic: Diag<usize>,
    pub files: SimpleFiles<String, String>,
}

#[derive(Clone, Debug)]
pub struct Diag<FileId> {
    pub inner: Diagnostic<FileId>,
}

impl<FileId> From<Diagnostic<FileId>> for Diag<FileId> {
    fn from(d: Diagnostic<FileId>) -> Self {
        Self { inner: d }
    }
}

impl<FileId> fmt::Display for Diag<FileId> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        //write!(f, "{}:{} {}", self.filename, self.lineno, self.msg)
        write!(f, "{}", self.inner.message)
    }
}

impl CompileError {
    pub fn new(
        msg: &str,
        file: &SimpleFile<String, String>,
        range: Option<Range<usize>>,
        help: &str,
    ) -> Self {
        let mut files = SimpleFiles::new();
        let file_id = files.add(file.name().clone(), file.source().clone());

        let diagnostic = Diagnostic::error().with_message(msg);

        let diagnostic = match range {
            None => diagnostic,
            Some(r) => diagnostic.with_labels(vec![Label::primary(file_id, r).with_message(help)]),
        };

        CompileError {
            diagnostic: diagnostic.into(),
            files,
        }
    }
    pub fn print_diagnostic(&self) {
        let writer = StandardStream::stderr(ColorChoice::Auto);
        let config = term::Config::default();
        // Ignores print errors.
        let _ = term::emit(
            &mut writer.lock(),
            &config,
            &self.files,
            &self.diagnostic.inner,
        );
    }

    pub fn add_additional_message(
        mut self,
        file: &SimpleFile<String, String>,
        range: Range<usize>,
        help: &str,
    ) -> Self {
        let file_id = self.files.add(file.name().clone(), file.source().clone());

        self.diagnostic.inner = self
            .diagnostic
            .inner
            .with_labels(vec![Label::primary(file_id, range).with_message(help)]);
        self
    }
}

#[derive(Error, Clone, Debug)]
#[error("{backtrace:?}")]
pub struct InternalError {
    backtrace: BacktraceCrate,
}

impl InternalError {
    pub fn new() -> Self {
        InternalError {
            backtrace: BacktraceCrate::new(),
        }
    }
}

#[derive(Error, Clone, Debug)]
#[error("{diagnostic}")]
pub struct ParseError {
    pub diagnostic: Diag<()>,
    pub file: SimpleFile<String, String>,
}

struct ParseErrorMsg {
    issue: String,
    range: Option<Range<usize>>,
    help: String,
}

impl From<LalrpopParseError<usize, Token<'_>, &str>> for ParseErrorMsg {
    fn from(error: LalrpopParseError<usize, Token<'_>, &str>) -> Self {
        match error {
            LalrpopParseError::InvalidToken { location } => ParseErrorMsg {
                issue: "Unknown character".into(),
                range: Some(location..location),
                help: String::new(),
            },
            LalrpopParseError::UnrecognizedEOF { location, expected } => ParseErrorMsg {
                issue: "Unexpected end of file".into(),
                range: Some(location..location),
                help: format!("Expected {}", expected.join(" or ")),
            },
            LalrpopParseError::UnrecognizedToken {
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
            LalrpopParseError::ExtraToken { token: (l, t, r) } => ParseErrorMsg {
                issue: if r - l == 1 {
                    format!("Unintended character \"{}\"", t.1)
                } else {
                    format!("Unintended word \"{}\"", t.1)
                },
                range: Some(l..r),
                help: String::new(),
            },
            LalrpopParseError::User { error } => ParseErrorMsg {
                issue: error.into(),
                range: None,
                help: String::new(),
            },
        }
    }
}

impl ParseError {
    pub fn new(
        error: LalrpopParseError<usize, Token<'_>, &str>,
        file_name: String,
        policy: String,
    ) -> Self {
        let msg: ParseErrorMsg = error.into();
        let diagnostic = Diagnostic::error().with_message(msg.issue);
        ParseError {
            file: SimpleFile::new(file_name, policy),
            diagnostic: match msg.range {
                None => diagnostic,
                Some(range) => {
                    diagnostic.with_labels(vec![Label::primary((), range).with_message(msg.help)])
                }
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
pub enum ErrorItem {
    #[error("Compilation error: {0}")]
    Compile(#[from] CompileError),
    #[error("Internal error: {0}")]
    Internal(#[from] InternalError),
    #[error("Parsing error: {0}")]
    Parse(#[from] ParseError),
    // TODO: Replace IO() with semantic errors wraping io::Error.
    #[error("I/O error: {0}")]
    IO(#[from] io::Error),
}

impl ErrorItem {
    pub fn make_compile_or_internal_error(
        msg: &str,
        file: Option<&SimpleFile<String, String>>,
        range: Option<Range<usize>>,
        help: &str,
    ) -> Self {
        match file {
            Some(f) => ErrorItem::Compile(CompileError::new(msg, f, range, help)),
            None => ErrorItem::Internal(InternalError::new()),
        }
    }
}

impl From<ErrorItem> for Vec<ErrorItem> {
    fn from(error: ErrorItem) -> Self {
        vec![error]
    }
}

#[derive(Error, Debug)]
pub struct CascadeErrors {
    errors: Vec<ErrorItem>,
}

impl CascadeErrors {
    pub fn new() -> Self {
        CascadeErrors { errors: Vec::new() }
    }

    pub fn add_error<T>(&mut self, error: T)
    where
        T: Into<ErrorItem>,
    {
        self.errors.push(error.into());
    }

    fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn append(&mut self, mut other: CascadeErrors) {
        self.errors.append(&mut other.errors);
    }

    pub fn into_result_with<F, T>(self, ok_with: F) -> Result<T, CascadeErrors>
    where
        F: FnOnce() -> T,
    {
        if self.is_empty() {
            Ok(ok_with())
        } else {
            Err(self)
        }
    }

    pub fn into_result<T>(self, ok: T) -> Result<T, CascadeErrors> {
        self.into_result_with(|| ok)
    }

    /// Enables to easily stop a workflow after a failed major step.  This is
    /// useful to avoid accumulating more errors that may be hard to understand
    /// because of unsatisfied prerequiste.
    ///
    /// For a multi-step workflow, it works as follow:
    /// 1. creates an accumulator with `let mut errors = CascadeErrors::new();`
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

impl From<ErrorItem> for CascadeErrors {
    fn from(error: ErrorItem) -> Self {
        CascadeErrors {
            errors: vec![error],
        }
    }
}

impl From<CompileError> for CascadeErrors {
    fn from(error: CompileError) -> Self {
        CascadeErrors::from(ErrorItem::from(error))
    }
}

impl From<InternalError> for CascadeErrors {
    fn from(error: InternalError) -> Self {
        CascadeErrors::from(ErrorItem::from(error))
    }
}

impl Iterator for CascadeErrors {
    type Item = ErrorItem;
    fn next(&mut self) -> Option<Self::Item> {
        self.errors.pop() // TODO: This reverses the list of errors
    }
}

impl fmt::Display for CascadeErrors {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_file_errors() {
        let file1 = SimpleFile::new("File1.cas".to_string(), "Contents of file 1".to_string());
        let file2 = SimpleFile::new("File2.cas".to_string(), "Contents of file 2".to_string());

        let mut error = CompileError::new(
            "This message points at multiple files",
            &file1,
            Some(9..11),
            "This is the word 'of' in file 1",
        );

        error = error.add_additional_message(&file2, 12..16, "This is the word file in file 2");

        let labels = error.diagnostic.inner.labels;
        assert_eq!(labels.len(), 2);
    }
}
