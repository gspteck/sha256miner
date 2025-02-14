# SHA256d Cryptocurrency Miner

This repository contains a simple, educational SHA256d cryptocurrency miner written in C++.  It's designed for learning purposes and might not be the most efficient miner available. Use it at your own risk.

## Features

*   Basic SHA256d mining implementation.
*   Uses `boost::asio` for networking.
*   Uses `nlohmann/json` for JSON parsing.
*   Uses `openssl/evp.h` for SHA256 hashing.

## Dependencies

*   **Boost Asio:**  For network communication.
*   **nlohmann/json:** For handling JSON data.
*   **OpenSSL:** For SHA256 hashing.

## Installation

Before compiling, ensure you have the necessary dependencies installed.  Instructions vary depending on your operating system.

### Linux

1.  **Install Boost:**

    ```bash
    sudo apt-get update
    sudo apt-get install libboost-all-dev
    ```

2.  **Install nlohmann/json:**

    This is a header-only library.  Download the `json.hpp` file from the [nlohmann/json](https://github.com/nlohmann/json) repository and place it in a suitable include directory (e.g., `/usr/local/include`).  Alternatively, you can use a package manager:

    ```bash
    sudo apt-get install nlohmann-json-dev
    ```

3.  **Install OpenSSL:**

    ```bash
    sudo apt-get install libssl-dev
    ```

### macOS

1.  **Install Boost:**

    You can use Homebrew:

    ```bash
    brew install boost
    ```

2.  **Install nlohmann/json:**

    ```bash
    brew install nlohmann_json
    ```

    Or download the header file from the [nlohmann/json](https://github.com/nlohmann/json) repository and place it in a suitable include directory.

3.  **Install OpenSSL:**

    macOS usually has OpenSSL installed, but it might be an older version. You can install a newer version using Homebrew:

    ```bash
    brew install openssl
    ```

    If you install OpenSSL with Homebrew, you might need to update your compiler flags to point to the Homebrew-installed version.

### Windows

1.  **Install Boost:**

    *   Download the pre-built binaries from the [Boost website](https://www.boost.org/users/download/).  Choose the appropriate version for your compiler.
    *   Extract the downloaded archive to a directory (e.g., `C:\boost`).
    *   You'll need to tell your compiler where to find the Boost headers and libraries. This is typically done through environment variables or compiler flags.

2.  **Install nlohmann/json:**

    *   Download the `json.hpp` header file from the [nlohmann/json](https://github.com/nlohmann/json) repository.
    *   Place the header file in your project directory or a standard include directory (e.g., `C:\Program Files\include`).

3.  **Install OpenSSL:**

    *   Download pre-built binaries from a reputable source (e.g., [Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html)).
    *   Install OpenSSL and ensure the installation directory is added to your system's `PATH` environment variable.  Also, set the `OPENSSL_CONF` environment variable to the path of the `openssl.cnf` file (e.g., `C:\OpenSSL-Win64\bin\openssl.cnf`).
    *   You might need to copy the OpenSSL DLLs (e.g., `libcrypto-*.dll`, `libssl-*.dll`) to your system's `System32` directory or the directory where your executable will be located.

    **Important (Windows):**  When compiling on Windows, ensure you're using the correct architecture (x86 or x64) matching your OpenSSL installation.  You might need to configure your IDE or build environment to link against the correct OpenSSL libraries.

## Compilation

Once you have installed the necessary libraries, you can compile the miner using the following command:

```bash
g++ -o miner sha256miner.cpp -lssl -lcrypto -ljsoncpp -lboost_system
