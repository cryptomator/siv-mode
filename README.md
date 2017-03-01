# RFC 5297 SIV mode of operation in Java

[![Build Status](https://travis-ci.org/cryptomator/siv-mode.svg?branch=master)](https://travis-ci.org/cryptomator/siv-mode)
[![codecov](https://codecov.io/gh/cryptomator/siv-mode/branch/master/graph/badge.svg)](https://codecov.io/gh/cryptomator/siv-mode)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/8b274788dab046259a40e56688236790)](https://www.codacy.com/app/cryptomator/siv-mode)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/10005/badge.svg)](https://scan.coverity.com/projects/cryptomator-siv-mode)
[![Maven Central](https://img.shields.io/maven-central/v/org.cryptomator/siv-mode.svg?maxAge=86400)](https://repo1.maven.org/maven2/org/cryptomator/siv-mode/)
[![Javadocs](http://www.javadoc.io/badge/org.cryptomator/siv-mode.svg)](http://www.javadoc.io/doc/org.cryptomator/siv-mode)

## Features
- No dependencies (required BouncyCastle classes are repackaged)
- Passes official RFC 5297 test vectors
- Constant time authentication
- Defaults on AES, but supports any block cipher with a 128-bit block size.
- Supports any key sizes that the block cipher supports (e.g. 128/192/256-bit keys for AES)
- Thread-safe
- Compatible with Android API Level 16 (since version 1.2.0)

## Audits
- [Version 1.0.8 audit by Tim McLean](https://www.chosenplaintext.ca/publications/20161104-siv-mode-report.pdf) (Issues fixed with 1.1.0)

## Usage
```java
private static final SivMode AES_SIV = new SivMode();

public void encrypt() {
  byte[] encrypted = AES_SIV.encrypt(ctrKey, macKey, "hello world".getBytes());
  byte[] decrypted = AES_SIV.decrypt(ctrKey, macKey, encrypted);
}

public void encryptWithAssociatedData() {
  byte[] encrypted = AES_SIV.encrypt(ctrKey, macKey, "hello world".getBytes(), "associated".getBytes(), "data".getBytes());
  byte[] decrypted = AES_SIV.decrypt(ctrKey, macKey, encrypted, "associated".getBytes(), "data".getBytes());
}
```

## Maven integration

```xml
<dependencies>
  <dependency>
    <groupId>org.cryptomator</groupId>
    <artifactId>siv-mode</artifactId>
    <version>1.2.1</version>
  </dependency>
</dependencies>
```

## License
Distributed under the MIT X Consortium license. See the LICENSE file for more info.
