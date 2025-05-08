# Publishing Guide

This document outlines the steps to publish the obfuscator crate to crates.io.

## Prerequisites

1. Create a crates.io account if you don't have one already: [https://crates.io/](https://crates.io/)
2. Log in with cargo:
   ```
   cargo login
   ```
   You'll be prompted to enter your API token from crates.io.

## Before Publishing

1. Update the version in `Cargo.toml` if needed
2. Make sure all your tests pass:
   ```
   cargo test
   ```
3. Verify your package:
   ```
   cargo package --list
   ```
   This ensures that all necessary files are included in the package.

4. Check for any potential issues:
   ```
   cargo publish --dry-run
   ```

## Publishing

When you're ready to publish:

```
cargo publish
```

## After Publishing

1. Create a git tag for the version:
   ```
   git tag -a v0.1.0 -m "Release version 0.1.0"
   git push origin v0.1.0
   ```

2. Update the version in `Cargo.toml` for the next development cycle, for example from `0.1.0` to `0.1.1-dev`.

## Checking Your Published Crate

After publishing, you can view your crate at:
```
https://crates.io/crates/obfuscator
```

The documentation will be automatically built and published at:
```
https://docs.rs/obfuscator
```

## Maintenance

For future releases:

1. Make your changes
2. Update the version in `Cargo.toml` (following semantic versioning)
3. Update the CHANGELOG.md if you have one
4. Run the tests
5. Publish the new version
6. Tag the release
