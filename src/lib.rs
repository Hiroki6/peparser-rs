mod errors;
mod headers;
mod imports;
mod parse;

use crate::headers::nt::ImageDirectoryEntry;
use crate::headers::PEHeader;
use crate::imports::Imports;
use std::fmt;

#[derive(Debug)]
pub struct PE<'a> {
    pub file: &'a [u8],
    pub header: PEHeader<'a>,
    pub imports: Option<Imports>,
}

impl<'a> PE<'a> {
    pub fn parse(input: parse::Input<'a>) -> parse::Result<Self> {
        let (i, header) = PEHeader::parse(input)?;
        let import_data_directory_opt = match header.nt_header.optional_header {
            headers::nt::OptionalHeader::Op32(ref op_header) => op_header
                .data_directories
                .find_by_entry(ImageDirectoryEntry::Import),
            headers::nt::OptionalHeader::Op64(ref op_header) => op_header
                .data_directories
                .find_by_entry(ImageDirectoryEntry::Import),
        };

        let (i, imports) = match import_data_directory_opt {
            Some(dir) => {
                // @todo wants to avoid clone
                let (i, imports) = Imports::parse(input, dir.clone(), header.sections.clone())?;
                (i, Some(imports))
            }
            None => (i, None),
        };

        Ok((
            i,
            Self {
                file: input,
                header,
                imports,
            },
        ))
    }
}

impl<'a> fmt::Display for PE<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", self.header)?;
        match &self.imports {
            Some(i) => writeln!(f, "{}", i),
            None => Ok(()),
        }
    }
}
