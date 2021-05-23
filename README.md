# ABNF parser
Simple ABNF parser in Rust.  Supporting RFC5324 and RFC7405.

## Usage
To dump ABNF rulelist, simply run the command with FILENAME.
```
cargo run FILENAME
```

## Limitation
For simplicity, it treats blank lines as ABNF rule delimiter.
