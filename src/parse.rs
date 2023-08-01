use crate::errors;

pub type Input<'a> = &'a [u8];
pub type Result<'a, O> = nom::IResult<Input<'a>, O, errors::PEError<Input<'a>>>;
