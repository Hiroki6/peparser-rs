mod headers;
mod parse;

use std::fmt;

#[derive(Debug)]
pub struct PE<'a> {
    pub dos_header: headers::dos::DosHeader<'a>,
    pub nt_header: headers::nt::NTHeader<'a>,
    pub sections: headers::sections::Sections,
}

impl<'a> PE<'a> {
    pub fn parse(i: parse::Input<'a>) -> parse::Result<Self> {
        let (i, dos_header) = headers::dos::DosHeader::parse(i)?;
        let (i, nt_header) = headers::nt::NTHeader::parse(i)?;
        let (i, sections) =
            headers::sections::Sections::parse(i, nt_header.file_header.num_of_sections)?;
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

impl<'a> fmt::Display for PE<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", self.dos_header)?;
        writeln!(f, "{}", self.nt_header)?;
        writeln!(f, "{}", self.sections)
    }
}
