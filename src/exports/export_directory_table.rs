use crate::headers::nt::DataDirectory;
use crate::headers::sections::Sections;
use crate::{errors, parse};
use chrono::{DateTime, Utc};
use nom::error::context;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;
use std::fmt;
use std::fmt::Formatter;

#[derive(Debug)]
pub struct ExportDirectoryTable {
    pub characteristics: u32,
    pub datetime: DateTime<Utc>,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32, // RVA to the name of the DLL
    pub base: u32,
    pub num_of_funcs: u32,      // Total number of exported functions
    pub num_of_names: u32,      // Number of functions that are exported by name
    pub addr_of_funcs: u32,     // RVA to the address of the Export Address Table
    pub addr_of_names: u32,     // RVA to the address of the Export Names Table
    pub addr_of_name_ordi: u32, // RVA to the address of the Export Ordinals Table
}

impl ExportDirectoryTable {
    pub fn parse(
        pe_file: parse::Input,
        export_directory: DataDirectory,
        sections: Sections,
    ) -> parse::Result<Option<Self>> {
        match sections.find_by_address(export_directory.virtual_address) {
            Some(section) => {
                let offset = section
                    .rva_to_offset(export_directory.virtual_address)
                    .unwrap(); // @todo remove it
                let section_data = &pe_file[offset as usize..];

                let (
                    i,
                    (
                        characteristics,
                        time_date_stamp,
                        major_version,
                        minor_version,
                        name,
                        base,
                        num_of_funcs,
                        num_of_names,
                        addr_of_funcs,
                        addr_of_names,
                        addr_of_name_ordi,
                    ),
                ) = tuple((
                    context("Characteristics", le_u32),
                    context("TimeDateStamp", le_u32),
                    context("MajorVersion", le_u16),
                    context("MinorVersion", le_u16),
                    context("Name", le_u32),
                    context("Base", le_u32),
                    context("NumberOfFunctions", le_u32),
                    context("NumberOfNames", le_u32),
                    context("AddressOfFunctions", le_u32),
                    context("AddressOfNames", le_u32),
                    context("AddressOfNameOrdinals", le_u32),
                ))(section_data)?;

                let datetime = chrono::NaiveDateTime::from_timestamp_opt(time_date_stamp as i64, 0)
                    .ok_or(errors::PEError::from_string(i, "wrong timestamp format"))?;

                let export_directory_table = Self {
                    characteristics,
                    datetime: DateTime::from_utc(datetime, Utc),
                    major_version,
                    minor_version,
                    name,
                    base,
                    num_of_funcs,
                    num_of_names,
                    addr_of_funcs,
                    addr_of_names,
                    addr_of_name_ordi,
                };

                Ok((i, Some(export_directory_table)))
            }
            None => Ok((pe_file, None)),
        }
    }
}

impl fmt::Display for ExportDirectoryTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "  ExportDirectoryTable: ")?;
        writeln!(f, "    Characteristics: {}, DateTime: {}, MajorVersion: {}, MinorVersion: {}, Name: {}, Base: {}, NumberOfFunctions: {}, NumberOfNames: {}, AddressOfFunctions: {}, AddressOfNames: {}, AddressOfNameOrdinals: {}",
            self.characteristics, self.datetime, self.major_version, self.minor_version, self.name, self.base, self.num_of_funcs, self.num_of_names, self.addr_of_funcs, self.addr_of_names, self.addr_of_name_ordi
        )
    }
}
