use crate::{errors, parse};
use chrono::{DateTime, Utc};
use derive_try_from_primitive::TryFromPrimitive;
use nom::{
    bytes::complete::tag,
    combinator::map_res,
    error::{context, ErrorKind},
    number::complete::{be_u8, le_u16, le_u32},
    sequence::tuple,
};
use std::fmt;

extern crate derive_more;
use derive_more::Display;
use nom::number::complete::le_u64;

#[derive(Debug)]
pub struct NTHeader<'a> {
    pub signature: &'a [u8],
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
}

impl<'a> NTHeader<'a> {
    const SIGNAUTRE: &'static [u8] = &[0x50, 0x45, 0x00, 0x00];

    pub fn parse(i: parse::Input<'a>) -> parse::Result<Self> {
        let (i, (signature,)) = tuple((context("Signature", tag(Self::SIGNAUTRE)),))(i)?;

        let (i, file_header) = FileHeader::parse(i)?;

        let (i, magic) = OptionalHeaderMagic::parse(i)?;

        let (i, optional_header) = OptionalHeader::parse(i, magic)?;

        let nt_header = NTHeader {
            signature,
            file_header,
            optional_header,
        };

        Ok((i, nt_header))
    }
}

#[derive(Debug)]
pub struct FileHeader {
    pub machine: Machine,
    pub num_of_sections: u16,
    pub datetime: DateTime<Utc>,
    pub ptr_to_sym_tbl: u32,
    pub num_of_syms: u32,
    pub size_of_optional_header: u16,
    // @todo separate into [u8; 2]
    pub characteristics: u16,
}

impl FileHeader {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, machine) = Machine::parse(i)?;

        let (
            i,
            (
                num_of_sections,
                timestamp,
                ptr_to_sym_tbl,
                num_of_syms,
                size_of_optional_header,
                characteristics,
            ),
        ) = tuple((
            context("NumOfSections", le_u16),
            context("Timestamp", le_u32),
            context("PtrToSymbolTable", le_u32),
            context("NumOfSymbols", le_u32),
            context("SizeOfHeader", le_u16),
            context("Characteristics", le_u16),
        ))(i)?;

        let timestamp = chrono::NaiveDateTime::from_timestamp_opt(timestamp as i64, 0)
            .ok_or(errors::PEError::from_string(i, "wrong timestamp format"))?;
        let datetime: DateTime<Utc> = DateTime::from_utc(timestamp, Utc);

        Ok((
            i,
            FileHeader {
                machine,
                num_of_sections,
                datetime,
                ptr_to_sym_tbl,
                num_of_syms,
                size_of_optional_header,
                characteristics,
            },
        ))
    }
}

/// Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, Display)]
#[repr(u16)]
pub enum Machine {
    Unknown = 0x0,
    Alpha = 0x184,
    Alpha64 = 0x284,
    Am33 = 0x1d3,
    Amd64 = 0x8664,
    Arm = 0x1c0,
    Arm64 = 0xaa64,
    Armnt = 0x1c4,
    Ebc = 0xebc,
    I386 = 0x14c,
    Ia64 = 0x200,
    LoongArch32 = 0x6232,
    LoongArch64 = 0x6264,
    M32R = 0x9041,
    Mips16 = 0x266,
    MipsFpu = 0x366,
    MipsFpu16 = 0x466,
    PowerPc = 0x1f0,
    PowerPcfp = 0x1f1,
    R4000 = 0x166,
    RiscV32 = 0x5032,
    RiscV64 = 0x5064,
    RiscV128 = 0x5128,
    Sh3 = 0x1a2,
    Sh3DSP = 0x1a3,
    Sh4 = 0x1a6,
    Sh5 = 0x1a8,
    Thumb = 0x1c2,
    WceMipsV2 = 0x169,
}

impl Machine {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        map_res(le_u16, |x| match Self::try_from(x) {
            Ok(x) => Ok(x),
            Err(_) => Err(ErrorKind::Alt),
        })(i)
    }
}

#[derive(Debug)]
pub enum OptionalHeader {
    Op32(OptionalHeader32),
    Op64(OptionalHeader64),
}

impl OptionalHeader {
    pub fn parse(i: parse::Input, magic: OptionalHeaderMagic) -> parse::Result<Self> {
        match magic {
            OptionalHeaderMagic::Pe32 => {
                let (i, optional_header) = OptionalHeader32::parse(i)?;
                Ok((i, OptionalHeader::Op32(optional_header)))
            }
            OptionalHeaderMagic::Pe32Plus => {
                let (i, optional_header) = OptionalHeader64::parse(i)?;
                Ok((i, OptionalHeader::Op64(optional_header)))
            }
            OptionalHeaderMagic::Rom => Err(errors::PEError::from_string(
                i,
                "ROM Images are not supported",
            )),
        }
    }

    pub fn find_directory_by_entry(&self, entry: DirectoryEntry) -> Option<DataDirectory> {
        match self {
            Self::Op32(ref op_header) => op_header.data_directories.find_by_entry(entry),
            Self::Op64(ref op_header) => op_header.data_directories.find_by_entry(entry),
        }
    }
}

#[derive(Debug)]
pub struct OptionalHeader32 {
    pub magic: OptionalHeaderMagic,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,               // .text
    pub size_of_initialized_code: u32,   // .data
    pub size_of_uninitialized_code: u32, // .bss
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_of_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_sub_system_version: u16,
    pub minor_sub_system_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub sub_system: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: DataDirectories,
}

impl OptionalHeader32 {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (
            i,
            (
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_code,
                size_of_uninitialized_code,
                address_of_entry_point,
                base_of_code,
                base_of_data,
                image_base,
                section_of_alignment,
                file_alignment,
                major_operating_system_version,
                minor_operating_system_version,
                major_image_version,
                minor_image_version,
                major_sub_system_version,
                minor_sub_system_version,
            ),
        ) = tuple((
            context("MajorLinkerVersion", be_u8),
            context("MinorLinkerVersion", be_u8),
            context("SizeOfCode", le_u32),
            context("SizeOfInitializedCode", le_u32),
            context("SizeOfUninitializedCode", le_u32),
            context("AddressOfEntryPoint", le_u32),
            context("BaseOfCode", le_u32),
            context("BaseOfData", le_u32),
            context("ImageBase", le_u32),
            context("SectionOfAlignment", le_u32),
            context("FileAlignment", le_u32),
            context("MajorOperatingSystemVersion", le_u16),
            context("MinorOperatingSystemVersion", le_u16),
            context("MajorImageVersion", le_u16),
            context("MinorImageVersion", le_u16),
            context("MajorSubSystemVersion", le_u16),
            context("MinorSubSystemVersion", le_u16),
        ))(i)?;

        let (
            i,
            (
                win32_version_value,
                size_of_image,
                size_of_headers,
                check_sum,
                sub_system,
                dll_characteristics,
                size_of_stack_reserve,
                size_of_stack_commit,
                size_of_heap_reserve,
                size_of_heap_commit,
                loader_flags,
                number_of_rva_and_sizes,
            ),
        ) = tuple((
            context("Win32VersionValue", le_u32),
            context("SizeOfImage", le_u32),
            context("SizeOfHeaders", le_u32),
            context("CheckSum", le_u32),
            context("Subsystem", le_u16),
            context("DllCharacteristics", le_u16),
            context("SizeOfStackReserve", le_u32),
            context("SizeOfStackCommit", le_u32),
            context("SizeOfHeapReserve", le_u32),
            context("SizeOfHeapCommit", le_u32),
            context("LoaderFlags", le_u32),
            context("NumberOfRvaAndSizes", le_u32),
        ))(i)?;

        let (i, data_directories) = DataDirectories::parse(i, number_of_rva_and_sizes as usize)?;

        Ok((
            i,
            Self {
                magic: OptionalHeaderMagic::Pe32,
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_code,
                size_of_uninitialized_code,
                address_of_entry_point,
                base_of_code,
                base_of_data,
                image_base,
                section_of_alignment,
                file_alignment,
                major_operating_system_version,
                minor_operating_system_version,
                major_image_version,
                minor_image_version,
                major_sub_system_version,
                minor_sub_system_version,
                win32_version_value,
                size_of_image,
                size_of_headers,
                check_sum,
                sub_system,
                dll_characteristics,
                size_of_stack_reserve,
                size_of_stack_commit,
                size_of_heap_reserve,
                size_of_heap_commit,
                loader_flags,
                number_of_rva_and_sizes,
                data_directories,
            },
        ))
    }
}

#[derive(Debug)]
pub struct OptionalHeader64 {
    pub magic: OptionalHeaderMagic,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,               // .text
    pub size_of_initialized_code: u32,   // .data
    pub size_of_uninitialized_code: u32, // .bss
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_of_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_sub_system_version: u16,
    pub minor_sub_system_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub sub_system: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: DataDirectories,
}

impl OptionalHeader64 {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (
            i,
            (
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_code,
                size_of_uninitialized_code,
                address_of_entry_point,
                base_of_code,
                image_base,
                section_of_alignment,
                file_alignment,
                major_operating_system_version,
                minor_operating_system_version,
                major_image_version,
                minor_image_version,
                major_sub_system_version,
                minor_sub_system_version,
            ),
        ) = tuple((
            context("MajorLinkerVersion", be_u8),
            context("MinorLinkerVersion", be_u8),
            context("SizeOfCode", le_u32),
            context("SizeOfInitializedCode", le_u32),
            context("SizeOfUninitializedCode", le_u32),
            context("AddressOfEntryPoint", le_u32),
            context("BaseOfCode", le_u32),
            context("ImageBase", le_u64),
            context("SectionOfAlignment", le_u32),
            context("FileAlignment", le_u32),
            context("MajorOperatingSystemVersion", le_u16),
            context("MinorOperatingSystemVersion", le_u16),
            context("MajorImageVersion", le_u16),
            context("MinorImageVersion", le_u16),
            context("MajorSubSystemVersion", le_u16),
            context("MinorSubSystemVersion", le_u16),
        ))(i)?;

        let (
            i,
            (
                win32_version_value,
                size_of_image,
                size_of_headers,
                check_sum,
                sub_system,
                dll_characteristics,
                size_of_stack_reserve,
                size_of_stack_commit,
                size_of_heap_reserve,
                size_of_heap_commit,
                loader_flags,
                number_of_rva_and_sizes,
            ),
        ) = tuple((
            context("Win32VersionValue", le_u32),
            context("SizeOfImage", le_u32),
            context("SizeOfHeaders", le_u32),
            context("CheckSum", le_u32),
            context("Subsystem", le_u16),
            context("DllCharacteristics", le_u16),
            context("SizeOfStackReserve", le_u64),
            context("SizeOfStackCommit", le_u64),
            context("SizeOfHeapReserve", le_u64),
            context("SizeOfHeapCommit", le_u64),
            context("LoaderFlags", le_u32),
            context("NumberOfRvaAndSizes", le_u32),
        ))(i)?;

        let (i, data_directories) = DataDirectories::parse(i, number_of_rva_and_sizes as usize)?;

        Ok((
            i,
            Self {
                magic: OptionalHeaderMagic::Pe32Plus,
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_code,
                size_of_uninitialized_code,
                address_of_entry_point,
                base_of_code,
                image_base,
                section_of_alignment,
                file_alignment,
                major_operating_system_version,
                minor_operating_system_version,
                major_image_version,
                minor_image_version,
                major_sub_system_version,
                minor_sub_system_version,
                win32_version_value,
                size_of_image,
                size_of_headers,
                check_sum,
                sub_system,
                dll_characteristics,
                size_of_stack_reserve,
                size_of_stack_commit,
                size_of_heap_reserve,
                size_of_heap_commit,
                loader_flags,
                number_of_rva_and_sizes,
                data_directories,
            },
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, Display)]
#[repr(u16)]
pub enum OptionalHeaderMagic {
    Pe32 = 0x10b,
    Pe32Plus = 0x20b,
    Rom = 0x107,
}

impl OptionalHeaderMagic {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        map_res(le_u16, |x| match Self::try_from(x) {
            Ok(x) => Ok(x),
            Err(_) => Err(ErrorKind::Alt),
        })(i)
    }
}

#[derive(Debug)]
pub struct DataDirectories(Vec<DataDirectory>);

impl DataDirectories {
    fn parse(input: parse::Input, count: usize) -> parse::Result<Self> {
        let mut directories = Vec::new();
        let mut input = input;
        for i in 0..count {
            let entry = DirectoryEntry::try_from(i).map_err(|e| {
                errors::PEError::from_string(input, format!("unknown image directory. {}", e))
            })?;
            let (new_input, directory) = DataDirectory::parse(entry, input)?;
            directories.push(directory);
            input = new_input;
        }
        Ok((input, Self(directories)))
    }

    pub fn find_by_entry(&self, entry: DirectoryEntry) -> Option<DataDirectory> {
        if entry.value() >= self.0.len() {
            None
        } else {
            Some(self.0[entry.value()])
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    pub entry: DirectoryEntry,
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    pub fn parse(entry: DirectoryEntry, input: parse::Input) -> parse::Result<Self> {
        let (input, (virtual_address, size)) = tuple((le_u32, le_u32))(input)?;
        Ok((
            input,
            Self {
                entry,
                virtual_address,
                size,
            },
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, Display)]
#[repr(usize)]
pub enum DirectoryEntry {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Certificate = 4,
    BaseRelocation = 5,
    Debug = 6,
    Architecture = 7,
    Globalptr = 8,
    Tls = 9,
    LoadConfig = 10,
    BoundImport = 11,
    ImportAddressTable = 12,
    DelayImport = 13,
    ClrRuntime = 14,
    Reserved = 15,
}

impl DirectoryEntry {
    fn value(&self) -> usize {
        *self as usize
    }
}

impl<'a> fmt::Display for NTHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "NTHeader:")?;
        writeln!(f, "  Signature: {:?}", self.signature)?;
        writeln!(f, "  {}", self.file_header)?;
        writeln!(f, "  {}", self.optional_header)
    }
}

impl fmt::Display for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "FileHeader:")?;
        writeln!(f, "    Machine: {}", self.machine)?;
        writeln!(f, "    Number of sections: {}", self.num_of_sections)?;
        writeln!(f, "    Datetime: {}", self.datetime)?;
        writeln!(f, "    Pointer to symbol table: {}", self.ptr_to_sym_tbl)?;
        writeln!(f, "    Number of symbols: {}", self.num_of_syms)?;
        writeln!(
            f,
            "    Size of optional header: {}",
            self.size_of_optional_header
        )?;
        writeln!(f, "    characteristics: {}", self.characteristics)
    }
}

impl fmt::Display for OptionalHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OptionalHeader::Op32(op) => {
                writeln!(f, "{}", op)
            }
            OptionalHeader::Op64(op) => {
                writeln!(f, "{}", op)
            }
        }
    }
}
impl fmt::Display for OptionalHeader32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "OptionalHeader:")?;
        writeln!(f, "    Magic: {}", self.magic)?;
        writeln!(f, "    Major linker version: {}", self.major_linker_version)?;
        writeln!(f, "    Minor linker version: {}", self.minor_linker_version)?;
        writeln!(f, "    Size of code: {}", self.size_of_code)?;
        writeln!(
            f,
            "    Size of initialized code: {}",
            self.size_of_initialized_code
        )?;
        writeln!(
            f,
            "    Size of uninitialized code: {}",
            self.size_of_uninitialized_code
        )?;
        writeln!(
            f,
            "    Address of entry point: {}",
            self.address_of_entry_point
        )?;
        writeln!(f, "    Base of code: {}", self.base_of_code)?;
        writeln!(f, "    Base of data: {}", self.base_of_data)?;
        writeln!(f, "    Image base: {}", self.image_base)?;
        writeln!(f, "    Section of alignment: {}", self.section_of_alignment)?;
        writeln!(f, "    File alignment: {}", self.file_alignment)?;
        writeln!(
            f,
            "    Major operating system version: {}",
            self.major_operating_system_version
        )?;
        writeln!(
            f,
            "    Minor operating system version: {}",
            self.minor_operating_system_version
        )?;
        writeln!(f, "    Major image version: {}", self.major_image_version)?;
        writeln!(f, "    Minor image version: {}", self.minor_image_version)?;
        writeln!(
            f,
            "    Major sub system version: {}",
            self.major_sub_system_version
        )?;
        writeln!(
            f,
            "    Minor sub system version: {}",
            self.minor_sub_system_version
        )?;
        writeln!(f, "    Win32 version value: {}", self.win32_version_value)?;
        writeln!(f, "    Size of image: {}", self.size_of_image)?;
        writeln!(f, "    Size of headers: {}", self.size_of_headers)?;
        writeln!(f, "    Checksum: {}", self.check_sum)?;
        writeln!(f, "    Sub system: {}", self.sub_system)?;
        writeln!(f, "    Dll characteristics: {}", self.dll_characteristics)?;
        writeln!(
            f,
            "    Size of stack reserve: {}",
            self.size_of_stack_reserve
        )?;
        writeln!(f, "    Size of stack commit: {}", self.size_of_stack_commit)?;
        writeln!(f, "    Size of heap reserve: {}", self.size_of_heap_reserve)?;
        writeln!(f, "    Size of heap commit: {}", self.size_of_heap_commit)?;
        writeln!(f, "    Loader flags: {}", self.loader_flags)?;
        writeln!(
            f,
            "    Mumber of rva and sizes: {}",
            self.number_of_rva_and_sizes
        )?;
        writeln!(f, "    Data Directory:")?;
        writeln!(f, "      {}", self.data_directories)
    }
}

impl fmt::Display for OptionalHeader64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "OptionalHeader:")?;
        writeln!(f, "    Magic: {}", self.magic)?;
        writeln!(f, "    Major linker version: {}", self.major_linker_version)?;
        writeln!(f, "    Minor linker version: {}", self.minor_linker_version)?;
        writeln!(f, "    Size of code: {}", self.size_of_code)?;
        writeln!(
            f,
            "    Size of initialized code: {}",
            self.size_of_initialized_code
        )?;
        writeln!(
            f,
            "    Size of uninitialized code: {}",
            self.size_of_uninitialized_code
        )?;
        writeln!(
            f,
            "    Address of entry point: {}",
            self.address_of_entry_point
        )?;
        writeln!(f, "    Base of code: {}", self.base_of_code)?;
        writeln!(f, "    Image base: {}", self.image_base)?;
        writeln!(f, "    Section of alignment: {}", self.section_of_alignment)?;
        writeln!(f, "    File alignment: {}", self.file_alignment)?;
        writeln!(
            f,
            "    Major operating system version: {}",
            self.major_operating_system_version
        )?;
        writeln!(
            f,
            "    Minor operating system version: {}",
            self.minor_operating_system_version
        )?;
        writeln!(f, "    Major image version: {}", self.major_image_version)?;
        writeln!(f, "    Minor image version: {}", self.minor_image_version)?;
        writeln!(
            f,
            "    Major sub system version: {}",
            self.major_sub_system_version
        )?;
        writeln!(
            f,
            "    Minor sub system version: {}",
            self.minor_sub_system_version
        )?;
        writeln!(f, "    Win32 version value: {}", self.win32_version_value)?;
        writeln!(f, "    Size of image: {}", self.size_of_image)?;
        writeln!(f, "    Size of headers: {}", self.size_of_headers)?;
        writeln!(f, "    Checksum: {}", self.check_sum)?;
        writeln!(f, "    Sub system: {}", self.sub_system)?;
        writeln!(f, "    Dll characteristics: {}", self.dll_characteristics)?;
        writeln!(
            f,
            "    Size of stack reserve: {}",
            self.size_of_stack_reserve
        )?;
        writeln!(f, "    Size of stack commit: {}", self.size_of_stack_commit)?;
        writeln!(f, "    Size of heap reserve: {}", self.size_of_heap_reserve)?;
        writeln!(f, "    Size of heap commit: {}", self.size_of_heap_commit)?;
        writeln!(f, "    Loader flags: {}", self.loader_flags)?;
        writeln!(
            f,
            "    Mumber of rva and sizes: {}",
            self.number_of_rva_and_sizes
        )?;
        writeln!(f, "    Data Directory:")?;
        writeln!(f, "      {}", self.data_directories)
    }
}

impl fmt::Display for DataDirectories {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Entry Address Size")?;
        for (_, dir) in self.0.iter().enumerate() {
            writeln!(f, "  {}", dir)?;
        }
        Ok(())
    }
}

impl fmt::Display for DataDirectory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "    {} Entry {} {}",
            self.entry, self.virtual_address, self.size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Machine;
    use std::convert::TryFrom;

    #[test]
    fn try_enums() {
        assert_eq!(Machine::Alpha as u16, 0x184);
        assert_eq!(Machine::try_from(0x9041), Ok(Machine::M32R));
        assert_eq!(Machine::try_from(0x1234), Err(0x1234));
    }
}
