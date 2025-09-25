# PEX: Packaged Executable Format

<div align="center">

**A Rust-based tool for packaging, obfuscating, and securely running executable files.**

</div>

## Overview

PEX provides a method for bundling executable files into a custom `.pex` format. It incorporates obfuscation techniques and, in its latest version, integrity verification to protect the contents. The toolchain consists of two core Rust binaries:

*   **`Packer`**: Converts standard executable files into the `.pex` format using configurable obfuscation and sorting strategies.
*   **`Runner`**: Automatically detects, unpacks, verifies (where applicable), and executes `.pex` files from its current directory.

The project emphasizes **backwards compatibility**, allowing the `Runner` to handle files created by older versions of the `Packer`.

## Features

*   **Custom File Format (`.pex`)**: A binary format designed for packaged executables using `bincode` serialization.
*   **Multi-Version Obfuscation & Verification**:
    *   **V1 (Legacy)**: Basic XOR obfuscation of the original binary data.
    *   **V2 (Sorted)**: XOR obfuscation applied *after* sorting the binary data by byte value, using a sort map for restoration.
    *   **V3 (Verified)**: Includes V2 features plus a SHA-256 hash of the original data for integrity verification before execution.
*   **Backwards Compatibility**: The `Runner` can automatically detect and correctly process `.pex` files created by V1, V2, or V3 versions of the `Packer`.

## Prerequisites

*   [Rust](https://www.rust-lang.org/tools/install) (latest stable recommended)

## Building

1.  Clone the repository (or download the source files `Packer.rs` and `Runner.rs`).
2.  Navigate to the directory containing the source files.
3.  Run the following command to build both tools in release mode:
    ```bash
    rustc -O Packer.rs -o packer
    rustc -O Runner.rs -o runner
    ```
    *Note: Ensure all necessary dependencies (`serde`, `bincode`, `anyhow`, `sha2`, `hex`, `tempfile`) are available, which they are if you have a standard Rust installation and internet access for `rustc` to fetch them.*

## Usage

### Packer

The `Packer` application takes an executable file as input and packages it into a `.pex` file based on the chosen version.

1.  Build the `Packer` executable as described above.
2.  Run the `packer` executable from your terminal:
    ```bash
    ./packer
    ```
3.  Follow the on-screen prompts:
    *   Enter the path to the executable you want to pack (e.g., `path/to/your/executable`).
    *   Choose the desired packing version (1 for V3, 2 for V2, 3 for V1, or 4 for all versions).

The new `.pex` file(s) will be created in the current directory.

### Runner

The `Runner` application automatically scans its current directory for `.pex` files. When found, it unpacks, verifies (if V3), and executes the original binary.

1.  Build the `Runner` executable as described above.
2.  Place the `runner` executable in the same directory as the `.pex` file(s) you want to run.
3.  Run the `runner` executable from your terminal:
    ```bash
    ./runner
    ```
4.  The application will automatically detect, process, and execute compatible `.pex` files.

## Security Considerations

*   **XOR Obfuscation**: The primary obfuscation method is XOR with a fixed key. This is **not** a strong cryptographic measure and should be considered obfuscation rather than encryption. It can deter casual analysis but is not secure against determined reverse engineering.
*   **Integrity Verification (V3)**: Version 3 adds a SHA-256 hash to detect tampering or corruption, enhancing security for the integrity of the packaged executable.
*   **Execution**: The `Runner` executes unpacked binaries in a temporary file. Be cautious when running `.pex` files from untrusted sources, as the underlying executable will be executed.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
