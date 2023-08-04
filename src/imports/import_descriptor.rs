use crate::headers::sections::{Section, SectionName, Sections};
use crate::parse;

use crate::headers::nt::ImageDataDirectory;
use byteorder::{ByteOrder, LittleEndian};
use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::tuple;
use std::fmt;
use std::fmt::Formatter;

#[derive(Debug)]
pub struct ImportDescriptors(Vec<ImportDescriptor>);

impl ImportDescriptors {
    pub fn parse(
        pe_file: parse::Input,
        import_directory: ImageDataDirectory,
        sections: Sections,
    ) -> parse::Result<Self> {
        match sections.find_by_address(import_directory.virtual_address) {
            Some(section) => {
                let offset = section
                    .rva_to_offset(import_directory.virtual_address)
                    .unwrap();
                let section_data = &pe_file[offset as usize..];
                let mut res = Vec::new();
                let mut cur_input = section_data;

                loop {
                    let (i, descriptor) = ImportDescriptor::parse(pe_file, cur_input, &section)?;

                    if descriptor.original_first_thunk == 0
                        && descriptor.time_date_stamp == 0
                        && descriptor.forwarder_chain == 0
                        && descriptor.name_rva == 0
                        && descriptor.first_thunk == 0
                    {
                        break;
                    }

                    res.push(descriptor);
                    cur_input = i;
                }

                Ok((cur_input, ImportDescriptors(res)))
            }
            None => {
                let empty = vec![];
                Ok((pe_file, ImportDescriptors(empty)))
            }
        }
    }
}

impl fmt::Display for ImportDescriptors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  ImportDescriptors:")?;
        for d in &self.0 {
            writeln!(f, "{}", d)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ImportDescriptor {
    original_first_thunk: u32,
    is_bound: bool,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name_rva: u32,
    name: String,
    first_thunk: u32,
    import_by_names: ImportByNames,
}

impl ImportDescriptor {
    /// pe_file is needed to retrieve the name from the offset
    fn parse<'a>(
        pe_file: parse::Input<'a>,
        i: parse::Input<'a>,
        section: &Section,
    ) -> parse::Result<'a, Self> {
        let (i, (original_first_thunk, time_date_stamp, forwarder_chain, name_rva, first_thunk)) =
            tuple((
                context("OriginalFirstThunk", le_u32),
                context("TimeDateStamp", le_u32),
                context("ForwarderChain", le_u32),
                context("Name", le_u32),
                context("FirstThunk", le_u32),
            ))(i)?;

        let name = Self::get_dll_name(pe_file, name_rva, section).unwrap_or("".to_string());

        let import_by_names = ImportByNames::parse(pe_file, original_first_thunk, section);
        let descriptor = Self {
            original_first_thunk,
            is_bound: time_date_stamp != 0,
            time_date_stamp,
            forwarder_chain,
            name_rva,
            name,
            first_thunk,
            import_by_names,
        };

        Ok((i, descriptor))
    }

    fn read_c_string(input: &[u8]) -> nom::IResult<&[u8], String> {
        let pos = input.iter().position(|&c| c == 0).unwrap_or(input.len());
        let (head, tail) = input.split_at(pos);
        let string = String::from_utf8_lossy(head); // Handle the Result properly in your code
        let (_, tail) = tail.split_at(1); // Skip the null terminator
        Ok((tail, string.to_string()))
    }

    fn get_dll_name(input: &[u8], name_rva: u32, section: &Section) -> Option<String> {
        section.rva_to_offset(name_rva).map(|offset| {
            let (_, name) = Self::read_c_string(&input[offset as usize..]).unwrap(); // Handle the Result properly in your code
            name
        })
    }
}

#[derive(Debug)]
pub struct ImportByNames(Vec<ImportByName>);

impl ImportByNames {
    pub fn parse(pe_file: parse::Input, original_first_thunk: u32, section: &Section) -> Self {
        let ilt = Self::read_import_lookup_table(pe_file, original_first_thunk, section);
        let mut import_by_names = vec![];
        for entry in ilt {
            if entry & 0x80000000 != 0 {
                // original import case
                // @todo figure out what I should do
                ()
            } else {
                match ImportByName::parse(pe_file, entry, section) {
                    Some(import_by_name) => import_by_names.push(import_by_name),
                    None => (),
                }
            }
        }
        Self(import_by_names)
    }

    fn read_import_lookup_table(pe_file: parse::Input, rva: u32, section: &Section) -> Vec<u32> {
        let offset = match section.rva_to_offset(rva) {
            Some(offset) => offset as usize,
            None => return vec![], // Return empty vector if the RVA couldn't be converted to an offset
        };

        // Read the ILT entries
        let mut entries = Vec::new();
        let mut current_offset = offset;
        loop {
            let entry = LittleEndian::read_u32(&pe_file[current_offset..]);
            if entry == 0 {
                break; // Stop reading when you reach a zero entry
            }
            entries.push(entry);
            current_offset += 4; // Move to the next entry
        }

        entries
    }
}
#[derive(Debug)]
pub struct ImportByName {
    hint: u16,
    name: String,
}

impl ImportByName {
    pub fn parse(pe_file: parse::Input, rva: u32, section: &Section) -> Option<ImportByName> {
        section.rva_to_offset(rva).map(|offset| {
            let hint = LittleEndian::read_u16(&pe_file[offset as usize..]);
            let name = Self::read_null_terminated_string(&pe_file[(offset as usize + 2)..]);
            Self { hint, name }
        })
    }

    // Function to read a null-terminated string from a slice
    fn read_null_terminated_string(slice: &[u8]) -> String {
        let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[0..len]).into_owned()
    }
}

impl fmt::Display for ImportDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "    OriginalFirstThunk: {}, IsBound: {}, TimeDateStamp: {}, ForwarderChain: {}, Name: {}, FirstThunk: {}",
               self.original_first_thunk,
               self.is_bound,
               self.time_date_stamp,
               self.forwarder_chain,
               self.name,
               self.first_thunk)?;
        write!(f, "{}", self.import_by_names)
    }
}

impl fmt::Display for ImportByNames {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "      ImportByNames:")?;
        for i in &self.0 {
            writeln!(f, "{}", i)?;
        }
        Ok(())
    }
}

impl fmt::Display for ImportByName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "        hint: {}, name: {}", self.hint, self.name)
    }
}
