# RFC 5297 SIV mode of operation in Java

[![Build Status](https://travis-ci.org/cryptomator/siv-mode.svg?branch=master)](https://travis-ci.org/cryptomator/siv-mode)
[![Coverage Status](https://coveralls.io/repos/cryptomator/siv-mode/badge.svg?branch=master&service=github)](https://coveralls.io/github/cryptomator/siv-mode?branch=master)
[![Maven Central](https://img.shields.io/maven-central/v/org.cryptomator/siv-mode.svg?maxAge=86400)](https://repo1.maven.org/maven2/org/cryptomator/siv-mode/)

## Features
- Depends only on BouncyCastle
- Passes official RFC 5297 test vectors
- Constant time authentication
- Defaults on AES, but supports any block cipher
- Thread-safe

## Usage
```java
private static final SivMode AES_SIV = new SivMode();

public void encrypt() {
  byte[] encrypted = AES_SIV.encrypt(ctrKey, macKey, "hello world".getBytes());
  byte[] decrypted = AES_SIV.decrypt(ctrKey, macKey, encrypted);
}

public void encryptWithAdditionalData() {
  byte[] encrypted = AES_SIV.encrypt(ctrKey, macKey, "hello world".getBytes(), "additional".getBytes(), "data".getBytes());
  byte[] decrypted = AES_SIV.decrypt(ctrKey, macKey, encrypted, "additional".getBytes(), "data".getBytes());
}
```

## Dependencies:
- JDK 7+
- SpongyCastle (BouncyCastle fork)

## Maven integration

```xml
<dependencies>
  <dependency>
    <groupId>org.cryptomator</groupId>
    <artifactId>siv-mode</artifactId>
    <version>1.0.3</version>
  </dependency>
</dependencies>
```

## License
Distributed under the MIT X Consortium license. See the LICENSE file for more info.
