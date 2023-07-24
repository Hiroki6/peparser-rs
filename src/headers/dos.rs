use crate::parse;
use nom::{
    bytes::complete::{tag, take},
    error::context,
    number::complete::le_u16,
    sequence::tuple,
};
use std::fmt;

// @todo add descriptions for each field
// @todo check if the parsing is correct
#[derive(Debug)]
pub struct DosHeader<'a> {
    pub magic: &'a [u8],
    pub cblp: u16,
    pub cp: u16,
    pub crlc: u16,
    pub cparhdr: u16,
    pub minalloc: u16,
    pub maxalloc: u16,
    pub ss: u16,
    pub sp: u16,
    pub csum: u16,
    pub ip: u16,
    pub cs: u16,
    pub lfarlc: u16,
    pub ovno: u16,
    pub res: &'a [u8],
    pub oemid: u16,
    pub oeminfo: u16,
    pub res2: &'a [u8],
    pub lfanew: &'a [u8],
}

impl<'a> DosHeader<'a> {
    const MAGIC: &'static [u8] = &[0x4d, 0x5a];

    pub fn parse(i: parse::Input<'a>) -> parse::Result<Self> {
        let (
            i,
            (
                magic,
                cblp,
                cp,
                crlc,
                cparhdr,
                minalloc,
                maxalloc,
                ss,
                sp,
                csum,
                ip,
                cs,
                lfarlc,
                ovno,
                res,
                oemid,
                oeminfo,
                res2,
                lfanew,
                _,
            ),
        ) = tuple((
            context("magic", tag(Self::MAGIC)),
            context("cblp", le_u16),
            context("cp", le_u16),
            context("crlc", le_u16),
            context("cparhdr", le_u16),
            context("minalloc", le_u16),
            context("maxalloc", le_u16),
            context("ss", le_u16),
            context("sp", le_u16),
            context("csum", le_u16),
            context("ip", le_u16),
            context("cs", le_u16),
            context("lfarlc", le_u16),
            context("ovno", le_u16),
            context("res", take(8usize)),
            context("oemid", le_u16),
            context("oeminfo", le_u16),
            context("res2", take(20usize)),
            context("lfanew", take(4usize)),
            context("stub", take(64usize)),
        ))(i)?;

        let dos_header = Self {
            magic,
            cblp,
            cp,
            crlc,
            cparhdr,
            minalloc,
            maxalloc,
            ss,
            sp,
            csum,
            ip,
            cs,
            lfarlc,
            ovno,
            res,
            oemid,
            oeminfo,
            res2,
            lfanew,
        };
        Ok((i, dos_header))
    }
}

impl<'a> fmt::Display for DosHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "DosHeader:")?;
        writeln!(f, "  Magic number: {:?}", self.magic)?;
        writeln!(f, "  Bytes on last page of file: {}", self.cblp)?;
        writeln!(f, "  Pages in file: {}", self.cp)?;
        writeln!(f, "  Relocations: {}", self.crlc)?;
        writeln!(f, "  Size of header in paragraphs: {}", self.cparhdr)?;
        writeln!(f, "  Minimum extra paragraphs needed: {}", self.minalloc)?;
        writeln!(f, "  Maximum extra paragraphs needed: {}", self.maxalloc)?;
        writeln!(f, "  Initial (relative) SS value: {}", self.ss)?;
        writeln!(f, "  Initial SP value: {}", self.sp)?;
        writeln!(f, "  CheckSum: {}", self.csum)?;
        writeln!(f, "  Initial IP value: {}", self.ip)?;
        writeln!(f, "  Initial (relative) CS value: {}", self.cs)?;
        writeln!(f, "  File address of relocation table: {}", self.lfarlc)?;
        writeln!(f, "  Overlay number: {}", self.ovno)?;
        writeln!(f, "  Reserved words: {:?}", self.res)?;
        writeln!(f, "  OEM identifier (for e_oeminfo): {}", self.oemid)?;
        writeln!(f, "  OEM information; e_oemid specific: {}", self.oeminfo)?;
        writeln!(f, "  Reserved words: {:?}", self.res2)?;
        writeln!(f, "  File address of new exe header: {:?}", self.lfanew)
    }
}
