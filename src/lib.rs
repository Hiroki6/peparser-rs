mod errors;
mod exports;
mod headers;
mod imports;
mod parse;
mod utils;

use crate::exports::export_directory_table::ExportDirectoryTable;
use crate::headers::nt::DirectoryEntry;
use crate::headers::PEHeader;
use crate::imports::Imports;
use std::fmt;

#[derive(Debug)]
pub struct PE<'a> {
    pub file: &'a [u8],
    pub header: PEHeader<'a>,
    pub imports: Option<Imports>,
    pub export: Option<ExportDirectoryTable>,
}

impl<'a> PE<'a> {
    pub fn parse(input: parse::Input<'a>) -> parse::Result<Self> {
        let (i, header) = PEHeader::parse(input)?;

        let import_directory_opt = header
            .nt_header
            .optional_header
            .find_directory_by_entry(DirectoryEntry::Import);
        let (i, imports) = match import_directory_opt {
            Some(import_directory) => {
                // @todo wants to avoid clone
                let (i, imports) =
                    Imports::parse(input, import_directory, header.sections.clone())?;
                (i, Some(imports))
            }
            None => (i, None),
        };

        let export_directory_opt = header
            .nt_header
            .optional_header
            .find_directory_by_entry(DirectoryEntry::Export);
        let (i, export) = match export_directory_opt {
            Some(export_directory) => {
                // @todo wants to avoid clone
                ExportDirectoryTable::parse(input, export_directory, header.sections.clone())?
            }
            None => (i, None),
        };

        Ok((
            i,
            Self {
                file: input,
                header,
                imports,
                export,
            },
        ))
    }
}

impl<'a> fmt::Display for PE<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", self.header)?;
        match &self.imports {
            Some(i) => writeln!(f, "{}", i)?,
            None => (),
        };
        match &self.export {
            Some(e) => writeln!(f, "{}", e),
            None => Ok(()),
        }
    }
}
