use crate::headers::nt::DataDirectory;
use crate::headers::sections::Sections;
use crate::imports::import_directory_table::ImportDirectoryTable;
use crate::parse;
use std::fmt;
use std::fmt::Formatter;

pub mod import_directory_table;

#[derive(Debug)]
pub struct Imports {
    pub directory_table: ImportDirectoryTable,
}

impl Imports {
    pub fn parse(
        input: parse::Input,
        import_directory: DataDirectory,
        sections: Sections,
    ) -> parse::Result<Self> {
        let (_, directory_table) = ImportDirectoryTable::parse(input, import_directory, sections)?;

        let imports = Self { directory_table };

        Ok((input, imports))
    }
}
impl fmt::Display for Imports {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Imports")?;
        writeln!(f, "{}", self.directory_table)
    }
}
