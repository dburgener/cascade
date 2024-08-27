// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT

//! Module for Cascade warning support
//!
//! If your function calls a function that adds warnings, first create a
//! Warnings object to store the warnings.  Then call inner() on the
//! WithWarnings object returned from the function generating warnings.
//! Store your warnings in your warnings struct and then use
//! WithWarnings::new() to return them up to the next level
//! If you add warnings yourself, call add_warnings() on a WithWarnings
//! object
//! See the warnings_usage() test in this module for an example workflow

use codespan_reporting::diagnostic::Severity;
use codespan_reporting::files::SimpleFile;
use std::ops::Range;
use termcolor::ColorChoice;

use crate::error::CompileError;

#[derive(Clone, Debug)]
pub struct Warning {
    inner: CompileError,
}

impl Warning {
    pub fn new(
        msg: &str,
        file: &SimpleFile<String, String>,
        range: Range<usize>,
        help: &str,
    ) -> Self {
        let mut error = CompileError::new(msg, file, range, help);
        error.diagnostic.inner.severity = Severity::Warning;
        Warning { inner: error }
    }

    pub fn print_diagnostic(&self, color: ColorChoice) {
        self.inner.print_diagnostic(color)
    }
}

#[derive(Clone, Debug)]
pub struct Warnings {
    // Using a BTreeSet here would require CompileError to implement Ord.
    inner: Vec<Warning>,
}

impl Warnings {
    pub fn new() -> Self {
        Warnings { inner: Vec::new() }
    }

    pub fn append(&mut self, other: &mut Self) {
        self.inner.append(&mut other.inner)
    }

    pub fn push(&mut self, w: Warning) {
        self.inner.push(w)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn print_warnings(&self, color: ColorChoice) {
        for e in &self.inner {
            e.print_diagnostic(color)
        }
    }

    pub fn count(&self) -> usize {
        self.inner.len()
    }
}

/// Wraps a Cascade object with additional information about warnings
pub struct WithWarnings<T> {
    inner: T,
    warnings: Warnings,
}

impl<T> WithWarnings<T> {
    pub fn new(inner: T, warnings: Warnings) -> Self {
        WithWarnings { inner, warnings }
    }

    /// Return the inner, extract the warnings to the warnings variable
    pub fn inner(mut self, warnings: &mut Warnings) -> T {
        warnings.append(&mut self.warnings);
        self.inner
    }

    pub fn add_warning(&mut self, warning: Warning) {
        self.warnings.push(warning);
    }
}

impl<T> From<T> for WithWarnings<T> {
    fn from(inner: T) -> Self {
        WithWarnings {
            inner,
            warnings: Warnings::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Diag;
    use codespan_reporting::diagnostic::Diagnostic;
    use codespan_reporting::files::SimpleFile;

    fn maybe_warn(
        warn_string: String,
        call_count: i8,
        do_warn: bool,
        file: &SimpleFile<String, String>,
    ) -> WithWarnings<String> {
        let mut ret = WithWarnings::from(warn_string);
        if do_warn {
            ret.add_warning(Warning::new(
                &format!("Some warning {}", call_count),
                file,
                2..4, // doesn't matter for the test
                "Some substring",
            ));
        }
        ret
    }

    #[test]
    fn basic_warning_test() {
        let warn = Warning::new(
            "This is a warning",
            &SimpleFile::new("file.cas".to_string(), "File contents".to_string()),
            0..4,
            "This is the word file",
        );

        assert!(matches!(warn,
                         Warning {
                             inner: CompileError {
                                 diagnostic: Diag {
                                     inner: Diagnostic {
                                         message: msg,
                                         ..
                                     }
                                 },
                                 ..
                             }
                         } if msg.contains("This is a warning")));
    }

    #[test]
    fn warnings_usage() {
        let mut my_string = "some_string".to_string();
        let mut warnings = Warnings::new();
        let file = SimpleFile::new("file.cas".to_string(), "File contents".to_string());

        my_string = maybe_warn(my_string, 1, false, &file).inner(&mut warnings);

        assert_eq!(&my_string, "some_string");
        assert_eq!(warnings.inner.len(), 0);

        my_string = maybe_warn(my_string, 2, true, &file).inner(&mut warnings);

        assert_eq!(&my_string, "some_string");
        assert_eq!(warnings.inner.len(), 1);
        assert!(matches!(&warnings.inner[0],
                         Warning {
                             inner: CompileError {
                                 diagnostic: Diag {
                                     inner: Diagnostic {
                                         message: msg,
                                         ..
                                     }
                                 },
                                 ..
                             }
                         } if msg.contains("Some warning 2")));
    }
}
