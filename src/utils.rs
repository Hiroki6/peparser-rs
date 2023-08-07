use byteorder::{ByteOrder, LittleEndian};

/// Reads a null-terminated string from a byte buffer, starting at a specified index.
///
/// # Arguments
///
/// * `buffer` - A byte slice from which to read data.
/// * `start` - The index at which to begin reading.
///
/// # Returns
///
/// A string read from the buffer. If the data in the buffer is not valid UTF-8,
/// invalid sequences are replaced with the Unicode replacement character.
pub fn read_null_terminated_string(slice: &[u8]) -> String {
    let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[0..len]).into_owned()
}

/// Reads an array of u32 values from a byte buffer, starting at a specified index.
///
/// # Arguments
///
/// * `buffer` - A byte slice from which to read data.
/// * `start` - The index at which to begin reading.
/// * `count` - The number of u32 values to read.
///
/// # Returns
///
/// A vector of u32 values read from the buffer.
pub fn read_array(buffer: &[u8], start: usize, count: usize) -> Vec<u32> {
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let offset = start + i * 4;
        if offset + 4 <= buffer.len() {
            let value = LittleEndian::read_u32(&buffer[offset..offset + 4]);
            result.push(value);
        } else {
            break;
        }
    }
    result
}
