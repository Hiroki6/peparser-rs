use std::fmt;

use crate::parse;
pub mod dos;
pub mod nt;
pub mod sections;

#[derive(Debug)]
pub struct PEHeader<'a> {
    pub dos_header: dos::DosHeader<'a>,
    pub nt_header: nt::NTHeader<'a>,
    pub sections: sections::Sections,
}

impl<'a> PEHeader<'a> {
    pub fn parse(i: parse::Input<'a>) -> parse::Result<Self> {
        let (i, dos_header) = dos::DosHeader::parse(i)?;
        let (i, nt_header) = nt::NTHeader::parse(i)?;
        let (i, sections) = sections::Sections::parse(i, nt_header.file_header.num_of_sections)?;
        Ok((
            i,
            Self {
                dos_header,
                nt_header,
                sections,
            },
        ))
    }
}

impl<'a> fmt::Display for PEHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", self.dos_header)?;
        writeln!(f, "{}", self.nt_header)?;
        writeln!(f, "{}", self.sections)
    }
}
