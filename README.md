
![Logo](https://avatars2.githubusercontent.com/u/12774718?s=150)

# Up1: A Client-side Encrypted Image Host

Up1 is a simple host that client-side encrypts images, text, and other data, and stores them, with the server knowing nothing about the contents.
It has the ability to view images, text with syntax highlighting, short videos, and arbitrary binaries as downloadables.


# Rust

This is the Rust server implementation of Up1. For more information about Up1 in general, visit https://github.com/Upload/Up1.


# Usage

After cloning this repo, there are two ways to run this:

## Rustup

Install rustup from https://rustup.rs/, then run:

```
cargo run --release
```

## Nix

Install nix from https://github.com/DeterminateSystems/nix-installer, then run:

```
  nix run
```
