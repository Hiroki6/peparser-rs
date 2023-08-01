use crate::parse;
use nom::number::complete::{le_u16, le_u32};
use nom::{bytes::complete::take, error::context, sequence::tuple};
use std::fmt;
use std::fmt::Formatter;

#[derive(Debug, Clone)]
pub struct Sections(pub Vec<Section>);

impl Sections {
    pub fn parse(i: parse::Input, num_of_sections: u16) -> parse::Result<Self> {
        let mut sections = Vec::new();
        let mut input = i;
        for _ in 0..num_of_sections {
            let (new_input, section) = Section::parse(input)?;
            sections.push(section);
            input = new_input;
        }

        Ok((i, Sections(sections)))
    }

    pub fn find_by_name(self, name: &str) -> Option<Section> {
        self.0.into_iter().find(|section| section.name == name)
    }
}

/// Enum representing common section names in a Portable Executable.
pub enum SectionName {
    Text,
    Data,
    Rdata,
    Bss,
    Idata,
    Tls,
}

impl SectionName {
    pub fn as_str(&self) -> &str {
        match *self {
            SectionName::Text => ".text",
            SectionName::Data => ".data",
            SectionName::Rdata => ".rdata",
            SectionName::Bss => ".bss",
            SectionName::Idata => ".idata",
            SectionName::Tls => ".tls",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub vir_size: u32,
    pub vir_addr: u32,
    pub size_of_raw_data: u32,
    pub ptr_to_raw_data: u32,
    pub ptr_to_relocs: u32,
    pub ptr_to_line_nums: u32,
    pub num_of_relocs: u16,
    pub num_of_line_nums: u16,
    pub characteristics: u32,
}

impl Section {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (
            i,
            (
                name,
                vir_size,
                vir_addr,
                size_of_raw_data,
                ptr_to_raw_data,
                ptr_to_relocs,
                ptr_to_line_nums,
                num_of_relocs,
                num_of_line_nums,
                characteristics,
            ),
        ) = tuple((
            context("Name", take(8usize)),
            context("VirtualSize", le_u32),
            context("VirtualAddress", le_u32),
            context("SizeOfRawData", le_u32),
            context("PointerToRawData", le_u32),
            context("PointerToRelocations", le_u32),
            context("PointerToLinenumbers", le_u32),
            context("NumberOfRelocations", le_u16),
            context("NumberOfLineNumbers", le_u16),
            context("Characteristics", le_u32),
        ))(i)?;

        let section = Self {
            name: String::from_utf8_lossy(name)
                .to_string()
                .trim_end_matches('\0')
                .to_string(),
            vir_size,
            vir_addr,
            size_of_raw_data,
            ptr_to_raw_data,
            ptr_to_relocs,
            ptr_to_line_nums,
            num_of_relocs,
            num_of_line_nums,
            characteristics,
        };

        Ok((i, section))
    }

    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        if rva >= self.vir_addr {
            Some(rva - self.vir_addr + self.ptr_to_raw_data)
        } else {
            None
        }
    }
}

impl fmt::Display for Sections {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Sections")?;
        for section in self.0.iter() {
            writeln!(f, "{}", section)?;
        }
        Ok(())
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "  name: {}", self.name)?;
        writeln!(f, "  Virtual size: {}", self.vir_size)?;
        writeln!(f, "  Virtual Address: {}", self.vir_addr)?;
        writeln!(f, "  Size of raw data: {}", self.size_of_raw_data)?;
        writeln!(f, "  Pointer to raw data: {}", self.ptr_to_raw_data)?;
        writeln!(f, "  Pointer to relocs: {}", self.ptr_to_relocs)?;
        writeln!(f, "  Pointer to line numbers: {}", self.ptr_to_line_nums)?;
        writeln!(f, "  Number of relocations: {}", self.num_of_relocs)?;
        writeln!(f, "  Number of line numbers: {}", self.num_of_line_nums)?;
        writeln!(f, "  Characteristics: {}", self.characteristics)
    }
}
