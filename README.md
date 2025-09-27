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
*   **Multi-Version Obfuscation, Compression & Verification**:
    *   **V1 (Legacy)**: Basic XOR obfuscation of the original binary data.
    *   **V2 (Sorted)**: XOR obfuscation applied *after* sorting the binary data by byte value, using a sort map for restoration.
    *   **V3 (Verified)**: Includes V2 features plus a SHA-256 hash of the original data for integrity verification before execution.
    *   **V4 (Compressed)**: Includes V3 features plus zlib compression of the original data before sorting and obfuscation.
    *   **V5 (Conditional Sort)**: Includes V4 features plus conditional binary sorting with randomized order for same-value bytes, using a file-derived salt.
    *   **V6 (PDMO - Payload-Derived Map Obfuscation)**: Includes V5 features plus the sort map itself is encrypted using a key derived from the obfuscated payload data, adding another layer of obfuscation.
    *   **V7 (DLL Support)**: Includes V6 features and adds support for packaging and running Dynamic Link Libraries (DLLs) alongside executables.
    *   **V8 (Time-Based Expiration)**: Includes V7 features plus time-based expiration control with configurable grace periods and time-derived keys for enhanced security.

*   **Backwards Compatibility**: The `Runner` can automatically detect and correctly process `.pex` files created by V1 through V8 versions of the `Packer`. V1-V7 files are run without expiration checks.
  


## Prerequisites

*   [Rust](https://www.rust-lang.org/tools/install) (latest stable recommended)

## Building

1.  Download the `make_pex` folder (containing the `Packer` project) and the `run_pex` folder (containing the `Runner` project).
2.  Navigate into the `make_pex` directory.
3.  Build the packer tool using Cargo:
    ```bash
    cargo build --release
    ```
    The executable will be located at `make_pex/target/release/make_pex`.
4.  Navigate into the `run_pex` directory.
5.  Build the runner tool using Cargo:
    ```bash
    cargo build --release
    ```
    The executable will be located at `run_pex/target/release/run_pex`.
    
## Usage

### Packer

The `Packer` application takes an executable file as input and packages it into a `.pex` file based on the chosen version.

1.  Build the `Packer` executable as described above.
2.  Run the `packer` executable from your terminal:
    ```bash
    ./make_pex/target/release/make_pex # Or the specific name if built with Cargo
    ```
3.  Follow the on-screen prompts:
    *   Enter the path to the executable you want to pack (e.g., `path/to/your/executable.exe` or `path/to/your/library.dll`).
    *   If packing a DLL, specify the entry point function name.
    *   For V8, configure the expiration date and grace period.
    *   Choose the desired packing version (1 for V8, 2 for V7, 3 for V6, 4 for V5, 5 for V4, 6 for V3, 7 for V2, 8 for V1, or 9 for all versions).

The new `.pex` file(s) will be created in the current directory.

### Runner

The `Runner` application automatically scans its current directory for `.pex` files. When found, it unpacks, verifies (if applicable), checks expiration (if V8), and executes the original binary.

1.  Build the `Runner` executable as described above.
2.  Place the `runner` executable in the same directory as the `.pex` file(s) you want to run.
3.  Run the `runner` executable from your terminal:
    ```bash
    ./run_pex/target/release/run_pex # Or the specific name if built with Cargo
    ```
4.  The application will automatically detect, process, and execute compatible `.pex` files. For V8 files, it will check the expiration date before execution.

# Security Considerations

*   **XOR Obfuscation**: The primary obfuscation method is XOR with a fixed key per version. This is **not** a strong cryptographic measure and should be considered obfuscation rather than encryption. It can deter casual analysis but is not secure against determined reverse engineering.
*   **Map Obfuscation (V6+)**: The sort map in V6+ is encrypted using a key derived from the payload itself, adding complexity to the reverse engineering process.
*   **Time-Based Expiration (V8)**: V8 adds time-based expiration checks and uses time-derived keys for additional security layers.
*   **Integrity Verification (V3+)**: Versions V3 and later add a SHA-256 hash to detect tampering or corruption, enhancing security for the integrity of the packaged executable.
*   **Execution**: The `Runner` executes unpacked binaries in a temporary file. Be cautious when running `.pex` files from untrusted sources, as the underlying executable will be executed.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
