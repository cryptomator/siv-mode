# RFC 5297 SIV mode of operation in Java

[![Build Status](https://travis-ci.org/cryptomator/siv-mode.svg?branch=master)](https://travis-ci.org/cryptomator/siv-mode)
[![Coverage Status](https://coveralls.io/repos/cryptomator/siv-mode/badge.svg?branch=master&service=github)](https://coveralls.io/github/cryptomator/siv-mode?branch=master)
[![Release](https://img.shields.io/github/release/org.cryptomator/siv-mode.svg?label=maven)](https://jitpack.io/#org.cryptomator/siv-mode)


## Features
- Depends only on BouncyCastle
- Passes official RFC 5297 test vectors
- Constant time authentication (also on JDK7)
- Defaults on AES, but supports any block cipher

## Dependencies:
- JDK 7+
- BouncyCastle

## Maven integration

```
  <repositories>
    <repository>
      <id>jitpack.io</id>
      <url>https://jitpack.io</url>
    </repository>
  </repositories>
  
  <dependencies>
    <dependency>
      <groupId>org.cryptomator</groupId>
      <artifactId>siv-mode</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
```

## License
Distributed under the MIT X Consortium license. See the LICENSE file for more info.
