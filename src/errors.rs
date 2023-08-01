use crate::parse::Input;
use std::fmt;
use std::fmt::Formatter;

#[derive(Debug, Clone)]
pub enum ErrorKind {
    Nom(nom::error::ErrorKind),
    Context(&'static str),
    String(String),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nom(n) => fmt::Display::fmt(n.description(), f),
            Self::Context(c) => fmt::Display::fmt(c, f),
            Self::String(s) => fmt::Display::fmt(s, f),
        }
    }
}

#[derive(Debug)]
pub struct PEError<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

impl<I> PEError<I> {
    pub fn from_string<S: Into<String>>(input: I, s: S) -> nom::Err<Self> {
        let errors = vec![(input, ErrorKind::String(s.into()))];
        nom::Err::Failure(Self { errors })
    }
}

impl<'a> From<PEError<Input<'a>>> for nom::Err<PEError<Input<'a>>> {
    fn from(value: PEError<Input<'a>>) -> Self {
        nom::Err::Failure(value)
    }
}

impl<I> nom::error::ParseError<I> for PEError<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        let errors = vec![(input, ErrorKind::Nom(kind))];
        Self { errors }
    }

    fn append(input: I, kind: nom::error::ErrorKind, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Nom(kind)));
        other
    }
}

impl<I> nom::error::ContextError<I> for PEError<I> {
    fn add_context(input: I, ctx: &'static str, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Context(ctx)));
        other
    }
}

impl<I, E> nom::error::FromExternalError<I, E> for PEError<I> {
    fn from_external_error(input: I, kind: nom::error::ErrorKind, _e: E) -> Self {
        let errors = vec![(input, ErrorKind::Nom(kind))];
        Self { errors }
    }
}

impl<I> fmt::Display for PEError<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for error in &self.errors {
            writeln!(f, "{}", error.1)?;
        }
        Ok(())
    }
}
