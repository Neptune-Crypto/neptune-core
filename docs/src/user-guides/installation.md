# Installation

## Build with [Nix](https://nixos.org/)

 -  Make sure you have `nix` installed or install it with:
    ```shell
    sh <(curl --proto '=https' --tlsv1.2 -L https://nixos.org/nix/install) --daemon
    ```
 -  Now simply run it with:
    - `nix run github:Neptune-Crypto/neptune-core` will run the `neptune-core` binary, fetching the git repo automatically.
    - Or run a specific package with `nix run github:Neptune-Crypto/neptune-core#neptune-cli`.
    - Or locally in the repo with `nix run` or `nix run .#neptune-cli`
    - To globally install use `nix profile install` or a specific package with `nix profile install .#neptune-cli`

All required build dependencies are packaged reproducibly and defined in `flake.nix`.
A development shell is included and can be accessed by running `nix develop` or use `direnv allow` if available.

## Compile from Source

### Linux Debian/Ubuntu

 - Open a terminal to run the following commands.
 - Install curl: `sudo apt install curl`
 - Install the rust compiler and accessories: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y`
 - Source the rust environment: `source "$HOME/.cargo/env"`
 - Install build tools: `sudo apt install build-essential`
 - Install LevelDB: `sudo apt install libleveldb-dev libsnappy-dev cmake`
 - Install clang and its linker: `sudo apt install clang && sudo apt install libstdc++-14-dev`
 - Download the repository: `git clone https://github.com/Neptune-Crypto/neptune-core.git`
 - Enter the repository: `cd neptune-core`
 - Checkout the latest release, which is tagged `release`: `git checkout release`. (Alternatively, for the *unstable development* branch, skip this step.)

   Any commit except the one tagged `release` is considered an *unstable development* commit and thus carries a higher risk of database corruption and/or loss of funds. However, known bug fixes make their way into `master` before being part of a release.

 - Build for release and put the binaries in your local path (`~/.cargo/bin/`): `make install-linux` (needs at least 3 GB of RAM and a few minutes)

### MacOS

 - Open a terminal to run the following commands.
 - Make sure you have `Homebrew` installed. If not, install it from [here](https://brew.sh/).
 - Install curl: `brew install curl`
 - Install the rust compiler and accessories: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
 - Source the rust environment: `source "$HOME/.cargo/env"`
 - Install Xcode command line tools: `xcode-select --install`
 - Install LevelDB: `brew install leveldb`
 - Install cmake: `brew install cmake`
 - Install git: `brew install git`
 - Download the repository: `git clone https://github.com/Neptune-Crypto/neptune-core.git`
 - Enter the repository: `cd neptune-core`
 - Build for release and put the binaries in your local path: `make install`

### Windows

To install Rust and cargo on Windows, you can follow [these instructions](https://doc.rust-lang.org/cargo/getting-started/installation.html).
Installing cargo might require you to install Visual Studio with some C++ support but the cargo installer for Windows should handle that.
With a functioning version of cargo, compilation on Windows should just work out-of-the-box with cargo build etc.
- Download and run the CMake installer from the [website](https://cmake.org/download/).
- Open PowerShell to run the following commands.
- Download the repository: `git clone https://github.com/Neptune-Crypto/neptune-core.git`
- Enter the repository: `cd neptune-core`
- Checkout the latest release, which is tagged `release`: `git checkout release`. (Alternatively, for the *unstable development* branch, skip this step.)

  Any commit except the one tagged `release` is considered an *unstable development* commit and thus carries a higher risk of database corruption and/or loss of funds. However, known bug fixes make their way into `master` before being part of a release.

- Build for release and put the binaries in your local path (`~/.cargo/bin/`):
  ```
  cargo install --locked --path neptune-core
  cargo install --locked --path neptune-core-cli
  cargo install --locked --path neptune-dashboard
  ```

## Automatic

Go to the [releases](https://github.com/Neptune-Crypto/neptune-core/releases) page, scroll down to the section "Assets" and select and install the right package for your system.
