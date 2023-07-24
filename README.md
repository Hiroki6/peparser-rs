# peparser-rs
`peparser-rs` is a Rust library for parsing Portable Executable (PE) files. 

## Usage
```rust
use peparser::PE;

fn main() {
    let input = fs::read("hello_world.exe").unwrap();
    let result = PE::parse(&input[..]).map_err(|e| format!("{:?}", e)).unwrap();

    println!("{}", result.1);
    println!("input is a supported PE file!");
}

```

```
DosHeader:
  Magic number: [77, 90]
  Bytes on last page of file: 144
  Pages in file: 3
  Relocations: 0
  ...

NTHeader:
  Signature: [80, 69, 0, 0]
  FileHeader:
    Machine: I386
    Number of sections: 13
    Datetime: 2023-07-08 11:49:31 UTC
    ...
    
  OptionalHeader:
    Magic: Pe32
    Major linker version: 2
    Minor linker version: 28
    Size of code: 11264
    Size of initialized code: 17920
    Size of uninitialized code: 512
    Address of entry point: 4832
    ...
    Mumber of rva and sizes: 16
    Data Directory:
      Entry Address Size
      Export Entry 0 0
      Import Entry 32768 1468
      Resource Entry 0 0
      ...

Sections
  name: .text
  Virtual size: 11140
  Virtual Address: 4096
  Size of raw data: 11264
  Pointer to raw data: 1024
  Pointer to relocs: 0
  Pointer to line numbers: 0
  Number of relocations: 0
  Number of line numbers: 0
  Characteristics: 1615855712

  name: .data
  ...
```

## TODO
- [ ] Support Imports
- [ ] Support Relocations
- [ ] Add more tests
- [ ] Add more documents
- [ ] Publish