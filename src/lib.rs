mod errors;
mod headers;
mod imports;
mod parse;

use crate::headers::PEHeader;
use crate::imports::Imports;
use std::fmt;

#[derive(Debug)]
pub struct PE<'a> {
    pub header: PEHeader<'a>,
    pub imports: Imports,
}

impl<'a> PE<'a> {
    pub fn parse(input: parse::Input<'a>) -> parse::Result<Self> {
        let (i, header) = PEHeader::parse(input)?;
        // @todo wants to avoid clone
        let (_, imports) = Imports::parse(input, header.sections.clone())?;

        Ok((i, Self { header, imports }))
    }
}

impl<'a> fmt::Display for PE<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", self.header)?;
        writeln!(f, "{}", self.imports)
    }
}
