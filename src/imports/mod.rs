use crate::headers::sections::Sections;
use crate::imports::import_descriptor::ImportDescriptors;
use crate::parse;
use std::fmt;
use std::fmt::Formatter;

pub mod import_descriptor;

#[derive(Debug)]
pub struct Imports {
    pub descriptors: ImportDescriptors,
}

impl Imports {
    pub fn parse(input: parse::Input, sections: Sections) -> parse::Result<Self> {
        let (_, descriptors) = ImportDescriptors::parse(input, sections)?;

        let imports = Self { descriptors };

        Ok((input, imports))
    }
}
impl fmt::Display for Imports {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Imports")?;
        writeln!(f, "{}", self.descriptors)
    }
}
