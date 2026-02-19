## syscalls-rust 
This is the library for different kernel syscalls, all are signatures and types are 
available. it use libc implementation of os target it using rust.
By default rust links a libc implementation with rust binary either `musl` or `glibc` for linux and for windows also have different libc implementation and
shared library this library just use those to target specific syscall 
`it doesnot use raw syscall` at all. If you want to use raw syscall see other 
library.

## License
This library is licensed under the gpl-3.0 license. So you can use this library
and use it under the conditions of gpl-3.0 license.

## Install

Using cargo 

```bash
cargo add syscalls-rust
```
or<br>

using Cargo.toml

```toml
[dependencies.syscalls-rust]
version = "0.2.10" # latest version
```

# Target os

In previous version it used features to target a version but now it only
targets only host os. 

So only host os syscall function are available for use.


## Cargo.toml

See [Cargo.toml](./Cargo.toml) for more details



## Contribution

If you want to contribute to this project you are welcome.<br>
You can make a pull request to contribute to this library.

