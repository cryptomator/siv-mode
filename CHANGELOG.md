# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/cryptomator/siv-mode/compare/1.6.0...HEAD)

## [1.6.0](https://github.com/cryptomator/siv-mode/compare/1.5.2...1.6.0)

### Added

- This CHANGELOG file
- `encrypt(SecretKey key, byte[] plaintext, byte[]... associatedData)` and `decrypt(SecretKey key, byte[] ciphertext, byte[]... associatedData)` using a single 256, 384, or 512 bit key

### Changed

- use `maven-gpg-plugin`'s bc-based signer 
