# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/cryptomator/siv-mode/compare/1.6.1...HEAD)

### Added
- new lowlevel API:
   * `new SivEngine(key).encrypt(plaintext, associatedData...)`
   * `new SivEngine(key).decrypt(plaintext, associatedData...)`
- implement JCA `Cipher` SPI:
    ```
    Cipher siv = Cipher.getInstance("AES/SIV/NoPadding");
    siv.init(Cipher.ENCRYPT_MODE, key);
    siv.updateAAD(aad1);
    siv.updateAAD(aad2);
    byte[] ciphertext = siv.doFinal(plaintext);
    ```
  
### Changed
- remove dependencies on BouncyCastle and Jetbrains Annotations
- simplify build by removing `maven-shade-plugin`
- update test dependencies
- update build plugins

### Deprecated
- old lowlevel API:
   * `new SivMode().encrypt(key, plaintext, associatedData...)`
   * `new SivMode().encrypt(ctrKey, macKey, plaintext, associatedData...)`
   * `new SivMode().decrypt(key, ciphertext, associatedData...)`
   * `new SivMode().decrypt(ctrKey, macKey, ciphertext, associatedData...)`
  


## [1.6.1](https://github.com/cryptomator/siv-mode/compare/1.6.0...1.6.1)

### Changed
- update dependencies

## [1.6.0](https://github.com/cryptomator/siv-mode/compare/1.5.2...1.6.0)

### Added
- This CHANGELOG file
- `encrypt(SecretKey key, byte[] plaintext, byte[]... associatedData)` and `decrypt(SecretKey key, byte[] ciphertext, byte[]... associatedData)` using a single 256, 384, or 512 bit key

### Changed
- use `maven-gpg-plugin`'s bc-based signer 
