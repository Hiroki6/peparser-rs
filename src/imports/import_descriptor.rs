use crate::headers::sections::{Section, SectionName, Sections};
use crate::parse;

use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::tuple;
use std::fmt;

#[derive(Debug)]
pub struct ImportDescriptors(Vec<ImportDescriptor>);

impl ImportDescriptors {
    pub fn parse(origin_input: parse::Input, sections: Sections) -> parse::Result<Self> {
        match sections.find_by_name(SectionName::Idata.as_str()) {
            Some(idata_section) => {
                let section_data = &origin_input[idata_section.ptr_to_raw_data as usize..];
                let mut res = Vec::new();
                let mut cur_input = section_data;

                loop {
                    let (input, descriptor) =
                        ImportDescriptor::parse(origin_input, cur_input, &idata_section)?;

                    if descriptor.original_first_thunk == 0
                        && descriptor.time_date_stamp == 0
                        && descriptor.forwarder_chain == 0
                        && descriptor.name_rva == 0
                        && descriptor.first_thunk == 0
                    {
                        break;
                    }

                    res.push(descriptor);
                    cur_input = input;
                }

                Ok((origin_input, ImportDescriptors(res)))
            }
            None => {
                let empty = vec![];
                Ok((origin_input, ImportDescriptors(empty)))
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
    // @todo look up functions based on the original first thunk address
    original_first_thunk: u32,
    is_bound: bool,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name_rva: u32,
    name: String,
    first_thunk: u32,
}

impl ImportDescriptor {
    /// original_input is needed to retrieve the name from the offset
    fn parse<'a>(
        original_input: parse::Input<'a>,
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

        let name = ImportDescriptor::get_dll_name(original_input, name_rva, section)
            .unwrap_or("".to_string());
        let descriptor = Self {
            original_first_thunk,
            is_bound: time_date_stamp != 0,
            time_date_stamp,
            forwarder_chain,
            name_rva,
            name,
            first_thunk,
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
            let (_, name) = ImportDescriptor::read_c_string(&input[offset as usize..]).unwrap(); // Handle the Result properly in your code
            name
        })
    }
}

impl fmt::Display for ImportDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "    OriginalFirstThunk: {}, IsBound: {}, TimeDateStamp: {}, ForwarderChain: {}, Name: {}, FirstThunk: {}",
               self.original_first_thunk,
               self.is_bound,
               self.time_date_stamp,
               self.forwarder_chain,
               self.name,
               self.first_thunk)
    }
}
