# Documentation

The documentation for Neptune Cash lives in the [`neptune-core`](https://github.com/Neptune-Crypto/neptune-core) repository under `docs/`. It uses [mdBook](https://rust-lang.github.io/mdBook/), a documentation-as-a-website engine popular with rust projects. The source material consists of [Markdown](https://commonmark.org/) files, and MdBook renders them as HTML pages.

## Running Locally

 1. Make sure `mdbook` is installed: `cargo install mdbook`.
 2. Go to the `docs/` directory: `cd docs/`.
 3. (Optional:) use MdBook as a HTTP server: `mdbook serve` with an optional `--open` flag. This command is useful for verifying that everything compiles in good order. It also rebuilds the website every time there is a change to the source material.
 4. Build the files for a static website: `mdbook build`. The static files are located in `book/`.

## Contributing

Due to resource constraints, this documentation is incomplete and may even deviate from the source code. Nevertheless, the goal *is* to have a complete and accurate documentation. You are warmly invited to help out and add to it – or fix it, if necessary. To do this, please open a pull request on [Github](https://github.com/Neptune-Crypto/neptune-core).
