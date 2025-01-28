# Installation

## Compile from Source

### Linux Debian/Ubuntu

 - Open a terminal to run the following commands.
 - Install curl: `sudo apt install curl`
 - Install the rust compiler and accessories: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y`
 - Source the rust environment: `source "$HOME/.cargo/env"`
 - Install build tools: `sudo apt install build-essential`
 - Install LevelDB: `sudo apt install libleveldb-dev libsnappy-dev cmake`
 - Download the repository: `git clone https://github.com/Neptune-Crypto/neptune-core.git`
 - Enter the repository: `cd neptune-core`
 - Checkout the release branch `git checkout release`. (Alternatively, for the *unstable development* branch, skip this step.)

 - Build for release and put the binaries in your local path (`~/.cargo/bin/`): `cargo install --locked --path .` (needs at least 3 GB of RAM and a few minutes)

### Windows

To install Rust and cargo on Windows, you can follow [these instructions](https://doc.rust-lang.org/cargo/getting-started/installation.html).
Installing cargo might require you to install Visual Studio with some C++ support but the cargo installer for Windows should handle that.
With a functioning version of cargo, compilation on Windows should just work out-of-the-box with cargo build etc.
- Download and run the CMake installer from the [website](https://cmake.org/download/).
- Open PowerShell to run the following commands.
- Download the repository: `git clone https://github.com/Neptune-Crypto/neptune-core.git`
- Enter the repository: `cd neptune-core`
- Checkout the release branch `git checkout release`. (Alternatively, for the *unstable development* branch, skip this step.)

- Run `cargo install --locked --path .`

## Automatic

Go to the [releases](https://github.com/Neptune-Crypto/neptune-core/releases) page, scroll down to the section "Assets" and select and install the right package for your system.
