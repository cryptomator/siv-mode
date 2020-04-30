package org.cryptomator.siv;
/*******************************************************************************
 * Copyright (c) 2015 Sebastian Stenzel
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 * 
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 ******************************************************************************/

import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.cryptomator.siv.SivMode.BlockCipherFactory;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.mockito.Mockito;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Official RFC 5297 test vector taken from https://tools.ietf.org/html/rfc5297#appendix-A.1 and https://tools.ietf.org/html/rfc5297#appendix-A.2
 */
public class SivModeTest {

	@Test
	public void testEncryptWithInvalidKey1() {
		SecretKey key1 = Mockito.mock(SecretKey.class);
		Mockito.when(key1.getEncoded()).thenReturn(null);
		SecretKey key2 = Mockito.mock(SecretKey.class);
		Mockito.when(key2.getEncoded()).thenReturn(new byte[16]);

		SivMode sivMode = new SivMode();
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			sivMode.encrypt(key1, key2, new byte[10]);
		});
	}

	@Test
	public void testEncryptWithInvalidKey2() {
		SecretKey key1 = Mockito.mock(SecretKey.class);
		Mockito.when(key1.getEncoded()).thenReturn(new byte[16]);
		SecretKey key2 = Mockito.mock(SecretKey.class);
		Mockito.when(key2.getEncoded()).thenReturn(null);

		SivMode sivMode = new SivMode();
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			sivMode.encrypt(key1, key2, new byte[10]);
		});
	}

	@Test
	public void testInvalidCipher1() {
		BlockCipherFactory factory = () -> null;

		Assertions.assertThrows(NullPointerException.class, () -> {
			new SivMode(factory);
		});
	}

	@Test
	public void testInvalidCipher2() {
		BlockCipherFactory factory = DESEngine::new; // wrong block size

		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new SivMode(factory);
		});
		MatcherAssert.assertThat(e.getMessage(), CoreMatchers.containsString("cipherFactory must create BlockCipher objects with a 16-byte block size"));
	}

	@Test
	public void testDecryptWithInvalidKey1() {
		SecretKey key1 = Mockito.mock(SecretKey.class);
		Mockito.when(key1.getEncoded()).thenReturn(null);
		SecretKey key2 = Mockito.mock(SecretKey.class);
		Mockito.when(key2.getEncoded()).thenReturn(new byte[16]);

		SivMode sivMode = new SivMode();
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			sivMode.decrypt(key1, key2, new byte[16]);
		});
	}

	@Test
	public void testDecryptWithInvalidKey2() {
		SecretKey key1 = Mockito.mock(SecretKey.class);
		Mockito.when(key1.getEncoded()).thenReturn(new byte[16]);
		SecretKey key2 = Mockito.mock(SecretKey.class);
		Mockito.when(key2.getEncoded()).thenReturn(null);

		SivMode sivMode = new SivMode();
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			sivMode.decrypt(key1, key2, new byte[10]);
		});
	}

	@Test
	public void testDecryptWithInvalidBlockSize() {
		final byte[] dummyKey = new byte[16];
		final SecretKey ctrKey = new SecretKeySpec(dummyKey, "AES");
		final SecretKey macKey = new SecretKeySpec(dummyKey, "AES");

		SivMode sivMode = new SivMode();
		Assertions.assertThrows(IllegalBlockSizeException.class, () -> {
			sivMode.decrypt(ctrKey, macKey, new byte[10]);
		});
	}

	@Test
	public void testEncryptAssociatedDataLimit() {
		final byte[] ctrKey = new byte[16];
		final byte[] macKey = new byte[16];
		final byte[] plaintext = new byte[30];

		SivMode sivMode = new SivMode();
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			sivMode.encrypt(ctrKey, macKey, plaintext, new byte[127][0]);
		});
	}

	@Test
	public void testDecryptAssociatedDataLimit() {
		final byte[] ctrKey = new byte[16];
		final byte[] macKey = new byte[16];
		final byte[] plaintext = new byte[80];

		SivMode sivMode = new SivMode();
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			sivMode.decrypt(ctrKey, macKey, plaintext, new byte[127][0]);
		});
	}

	// CTR-AES https://tools.ietf.org/html/rfc5297#appendix-A.1
	@Test
	public void testComputeCtr1() {
		final byte[] ctrKey = {(byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, //
				(byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, //
				(byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, //
				(byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff};

		final byte[] ctr = {(byte) 0x85, (byte) 0x63, (byte) 0x2d, (byte) 0x07, //
				(byte) 0xc6, (byte) 0xe8, (byte) 0xf3, (byte) 0x7f, //
				(byte) 0x15, (byte) 0x0a, (byte) 0xcd, (byte) 0x32, //
				(byte) 0x0a, (byte) 0x2e, (byte) 0xcc, (byte) 0x93};

		final byte[] expected = {(byte) 0x51, (byte) 0xe2, (byte) 0x18, (byte) 0xd2, //
				(byte) 0xc5, (byte) 0xa2, (byte) 0xab, (byte) 0x8c, //
				(byte) 0x43, (byte) 0x45, (byte) 0xc4, (byte) 0xa6, //
				(byte) 0x23, (byte) 0xb2, (byte) 0xf0, (byte) 0x8f};

		final byte[] result = new SivMode().computeCtr(new byte[16], ctrKey, ctr);
		Assertions.assertArrayEquals(expected, result);

		final byte[] sunJceResult = new SivMode(getSunJceProvider()).computeCtr(new byte[16], ctrKey, ctr);
		Assertions.assertArrayEquals(expected, sunJceResult);

		final byte[] bcResult = new SivMode(AESLightEngine::new).computeCtr(new byte[16], ctrKey, ctr);
		Assertions.assertArrayEquals(expected, bcResult);
	}

	// CTR-AES https://tools.ietf.org/html/rfc5297#appendix-A.2
	@Test
	public void testComputeCtr2() {
		final byte[] ctrKey = {(byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, //
				(byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47, //
				(byte) 0x48, (byte) 0x49, (byte) 0x4a, (byte) 0x4b, //
				(byte) 0x4c, (byte) 0x4d, (byte) 0x4e, (byte) 0x4f};

		final byte[] ctr = {(byte) 0x7b, (byte) 0xdb, (byte) 0x6e, (byte) 0x3b, //
				(byte) 0x43, (byte) 0x26, (byte) 0x67, (byte) 0xeb, //
				(byte) 0x06, (byte) 0xf4, (byte) 0xd1, (byte) 0x4b, //
				(byte) 0x7f, (byte) 0x2f, (byte) 0xbd, (byte) 0x0f};

		final byte[] expected = {(byte) 0xbf, (byte) 0xf8, (byte) 0x66, (byte) 0x5c, //
				(byte) 0xfd, (byte) 0xd7, (byte) 0x33, (byte) 0x63, //
				(byte) 0x55, (byte) 0x0f, (byte) 0x74, (byte) 0x00, //
				(byte) 0xe8, (byte) 0xf9, (byte) 0xd3, (byte) 0x76, //
				(byte) 0xb2, (byte) 0xc9, (byte) 0x08, (byte) 0x8e, //
				(byte) 0x71, (byte) 0x3b, (byte) 0x86, (byte) 0x17, //
				(byte) 0xd8, (byte) 0x83, (byte) 0x92, (byte) 0x26, //
				(byte) 0xd9, (byte) 0xf8, (byte) 0x81, (byte) 0x59, //
				(byte) 0x9e, (byte) 0x44, (byte) 0xd8, (byte) 0x27, //
				(byte) 0x23, (byte) 0x49, (byte) 0x49, (byte) 0xbc, //
				(byte) 0x1b, (byte) 0x12, (byte) 0x34, (byte) 0x8e, //
				(byte) 0xbc, (byte) 0x19, (byte) 0x5e, (byte) 0xc7};

		final byte[] result = new SivMode().computeCtr(new byte[48], ctrKey, ctr);
		Assertions.assertArrayEquals(expected, result);
	}

	@Test
	public void testS2v() {
		final byte[] macKey = {(byte) 0xff, (byte) 0xfe, (byte) 0xfd, (byte) 0xfc, //
				(byte) 0xfb, (byte) 0xfa, (byte) 0xf9, (byte) 0xf8, //
				(byte) 0xf7, (byte) 0xf6, (byte) 0xf5, (byte) 0xf4, //
				(byte) 0xf3, (byte) 0xf2, (byte) 0xf1, (byte) 0xf0};

		final byte[] ad = {(byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, //
				(byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, //
				(byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, //
				(byte) 0x1c, (byte) 0x1d, (byte) 0x1e, (byte) 0x1f, //
				(byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23, //
				(byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27};

		final byte[] plaintext = {(byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, //
				(byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, //
				(byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, //
				(byte) 0xdd, (byte) 0xee};

		final byte[] expected = {(byte) 0x85, (byte) 0x63, (byte) 0x2d, (byte) 0x07, //
				(byte) 0xc6, (byte) 0xe8, (byte) 0xf3, (byte) 0x7f, //
				(byte) 0x95, (byte) 0x0a, (byte) 0xcd, (byte) 0x32, //
				(byte) 0x0a, (byte) 0x2e, (byte) 0xcc, (byte) 0x93};

		final byte[] result = new SivMode().s2v(macKey, plaintext, ad);
		Assertions.assertArrayEquals(expected, result);

		final byte[] resultProvider = new SivMode(getSunJceProvider()).s2v(macKey, plaintext, ad);
		Assertions.assertArrayEquals(expected, resultProvider);
	}

	@Test
	public void testSivEncrypt() {
		final byte[] macKey = {(byte) 0xff, (byte) 0xfe, (byte) 0xfd, (byte) 0xfc, //
				(byte) 0xfb, (byte) 0xfa, (byte) 0xf9, (byte) 0xf8, //
				(byte) 0xf7, (byte) 0xf6, (byte) 0xf5, (byte) 0xf4, //
				(byte) 0xf3, (byte) 0xf2, (byte) 0xf1, (byte) 0xf0};

		final byte[] aesKey = {(byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, //
				(byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, //
				(byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, //
				(byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff};

		final byte[] ad = {(byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, //
				(byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, //
				(byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, //
				(byte) 0x1c, (byte) 0x1d, (byte) 0x1e, (byte) 0x1f, //
				(byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23, //
				(byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27};

		final byte[] plaintext = {(byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, //
				(byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, //
				(byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, //
				(byte) 0xdd, (byte) 0xee};

		final byte[] expected = {(byte) 0x85, (byte) 0x63, (byte) 0x2d, (byte) 0x07, //
				(byte) 0xc6, (byte) 0xe8, (byte) 0xf3, (byte) 0x7f, //
				(byte) 0x95, (byte) 0x0a, (byte) 0xcd, (byte) 0x32, //
				(byte) 0x0a, (byte) 0x2e, (byte) 0xcc, (byte) 0x93, //
				(byte) 0x40, (byte) 0xc0, (byte) 0x2b, (byte) 0x96, //
				(byte) 0x90, (byte) 0xc4, (byte) 0xdc, (byte) 0x04, //
				(byte) 0xda, (byte) 0xef, (byte) 0x7f, (byte) 0x6a, //
				(byte) 0xfe, (byte) 0x5c};

		final byte[] result = new SivMode().encrypt(aesKey, macKey, plaintext, ad);
		Assertions.assertArrayEquals(expected, result);
	}

	@Test
	public void testSivDecrypt() throws UnauthenticCiphertextException, IllegalBlockSizeException {
		final byte[] macKey = {(byte) 0xff, (byte) 0xfe, (byte) 0xfd, (byte) 0xfc, //
				(byte) 0xfb, (byte) 0xfa, (byte) 0xf9, (byte) 0xf8, //
				(byte) 0xf7, (byte) 0xf6, (byte) 0xf5, (byte) 0xf4, //
				(byte) 0xf3, (byte) 0xf2, (byte) 0xf1, (byte) 0xf0};

		final byte[] aesKey = {(byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, //
				(byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, //
				(byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, //
				(byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff};

		final byte[] ad = {(byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, //
				(byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, //
				(byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, //
				(byte) 0x1c, (byte) 0x1d, (byte) 0x1e, (byte) 0x1f, //
				(byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23, //
				(byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27};

		final byte[] ciphertext = {(byte) 0x85, (byte) 0x63, (byte) 0x2d, (byte) 0x07, //
				(byte) 0xc6, (byte) 0xe8, (byte) 0xf3, (byte) 0x7f, //
				(byte) 0x95, (byte) 0x0a, (byte) 0xcd, (byte) 0x32, //
				(byte) 0x0a, (byte) 0x2e, (byte) 0xcc, (byte) 0x93, //
				(byte) 0x40, (byte) 0xc0, (byte) 0x2b, (byte) 0x96, //
				(byte) 0x90, (byte) 0xc4, (byte) 0xdc, (byte) 0x04, //
				(byte) 0xda, (byte) 0xef, (byte) 0x7f, (byte) 0x6a, //
				(byte) 0xfe, (byte) 0x5c};

		final byte[] expected = {(byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, //
				(byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, //
				(byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, //
				(byte) 0xdd, (byte) 0xee};

		final byte[] result = new SivMode().decrypt(aesKey, macKey, ciphertext, ad);
		Assertions.assertArrayEquals(expected, result);
	}

	@Test
	public void testSivDecryptWithInvalidKey() {
		final byte[] macKey = {(byte) 0xff, (byte) 0xfe, (byte) 0xfd, (byte) 0xfc, //
				(byte) 0xfb, (byte) 0xfa, (byte) 0xf9, (byte) 0xf8, //
				(byte) 0xf7, (byte) 0xf6, (byte) 0xf5, (byte) 0xf4, //
				(byte) 0xf3, (byte) 0xf2, (byte) 0xf1, (byte) 0xf0};

		final byte[] aesKey = {(byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, //
				(byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, //
				(byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, //
				(byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0x00};

		final byte[] ad = {(byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, //
				(byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, //
				(byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, //
				(byte) 0x1c, (byte) 0x1d, (byte) 0x1e, (byte) 0x1f, //
				(byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23, //
				(byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27};

		final byte[] ciphertext = {(byte) 0x85, (byte) 0x63, (byte) 0x2d, (byte) 0x07, //
				(byte) 0xc6, (byte) 0xe8, (byte) 0xf3, (byte) 0x7f, //
				(byte) 0x95, (byte) 0x0a, (byte) 0xcd, (byte) 0x32, //
				(byte) 0x0a, (byte) 0x2e, (byte) 0xcc, (byte) 0x93, //
				(byte) 0x40, (byte) 0xc0, (byte) 0x2b, (byte) 0x96, //
				(byte) 0x90, (byte) 0xc4, (byte) 0xdc, (byte) 0x04, //
				(byte) 0xda, (byte) 0xef, (byte) 0x7f, (byte) 0x6a, //
				(byte) 0xfe, (byte) 0x5c};

		SivMode sivMode = new SivMode();
		Assertions.assertThrows(UnauthenticCiphertextException.class, () -> {
			sivMode.decrypt(aesKey, macKey, ciphertext, ad);
		});
	}

	@Test
	public void testSivDecryptWithInvalidCiphertext() {
		final byte[] macKey = {(byte) 0xff, (byte) 0xfe, (byte) 0xfd, (byte) 0xfc, //
				(byte) 0xfb, (byte) 0xfa, (byte) 0xf9, (byte) 0xf8, //
				(byte) 0xf7, (byte) 0xf6, (byte) 0xf5, (byte) 0xf4, //
				(byte) 0xf3, (byte) 0xf2, (byte) 0xf1, (byte) 0xf0};

		final byte[] aesKey = {(byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, //
				(byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, //
				(byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, //
				(byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0x00};

		final byte[] ciphertext = {(byte) 0x85, (byte) 0x63, (byte) 0x2d, (byte) 0x07, //
				(byte) 0xc6, (byte) 0xe8, (byte) 0xf3, (byte) 0x7f, //
				(byte) 0x95, (byte) 0x0a, (byte) 0xcd, (byte) 0x32, //
				(byte) 0x0a, (byte) 0x2e, (byte) 0xcc};

		SivMode sivMode = new SivMode();
		Assertions.assertThrows(IllegalBlockSizeException.class, () -> {
			sivMode.decrypt(aesKey, macKey, ciphertext);
		});
	}

	/**
	 * https://tools.ietf.org/html/rfc5297#appendix-A.2
	 */
	@Test
	public void testNonceBasedAuthenticatedEncryption() {
		final byte[] macKey = {(byte) 0x7f, (byte) 0x7e, (byte) 0x7d, (byte) 0x7c, //
				(byte) 0x7b, (byte) 0x7a, (byte) 0x79, (byte) 0x78, //
				(byte) 0x77, (byte) 0x76, (byte) 0x75, (byte) 0x74, //
				(byte) 0x73, (byte) 0x72, (byte) 0x71, (byte) 0x70};

		final byte[] aesKey = {(byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, //
				(byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47, //
				(byte) 0x48, (byte) 0x49, (byte) 0x4a, (byte) 0x4b, //
				(byte) 0x4c, (byte) 0x4d, (byte) 0x4e, (byte) 0x4f};

		final byte[] ad1 = {(byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, //
				(byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, //
				(byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, //
				(byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff, //
				(byte) 0xde, (byte) 0xad, (byte) 0xda, (byte) 0xda, //
				(byte) 0xde, (byte) 0xad, (byte) 0xda, (byte) 0xda, //
				(byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, //
				(byte) 0xbb, (byte) 0xaa, (byte) 0x99, (byte) 0x88, //
				(byte) 0x77, (byte) 0x66, (byte) 0x55, (byte) 0x44, //
				(byte) 0x33, (byte) 0x22, (byte) 0x11, (byte) 0x00};

		final byte[] ad2 = {(byte) 0x10, (byte) 0x20, (byte) 0x30, (byte) 0x40, //
				(byte) 0x50, (byte) 0x60, (byte) 0x70, (byte) 0x80, //
				(byte) 0x90, (byte) 0xa0};

		final byte[] nonce = {(byte) 0x09, (byte) 0xf9, (byte) 0x11, (byte) 0x02, //
				(byte) 0x9d, (byte) 0x74, (byte) 0xe3, (byte) 0x5b, //
				(byte) 0xd8, (byte) 0x41, (byte) 0x56, (byte) 0xc5, //
				(byte) 0x63, (byte) 0x56, (byte) 0x88, (byte) 0xc0};

		final byte[] plaintext = {(byte) 0x74, (byte) 0x68, (byte) 0x69, (byte) 0x73, //
				(byte) 0x20, (byte) 0x69, (byte) 0x73, (byte) 0x20, //
				(byte) 0x73, (byte) 0x6f, (byte) 0x6d, (byte) 0x65, //
				(byte) 0x20, (byte) 0x70, (byte) 0x6c, (byte) 0x61, //
				(byte) 0x69, (byte) 0x6e, (byte) 0x74, (byte) 0x65, //
				(byte) 0x78, (byte) 0x74, (byte) 0x20, (byte) 0x74, //
				(byte) 0x6f, (byte) 0x20, (byte) 0x65, (byte) 0x6e, //
				(byte) 0x63, (byte) 0x72, (byte) 0x79, (byte) 0x70, //
				(byte) 0x74, (byte) 0x20, (byte) 0x75, (byte) 0x73, //
				(byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x20, //
				(byte) 0x53, (byte) 0x49, (byte) 0x56, (byte) 0x2d, //
				(byte) 0x41, (byte) 0x45, (byte) 0x53};

		final byte[] result = new SivMode().encrypt(aesKey, macKey, plaintext, ad1, ad2, nonce);

		final byte[] expected = {(byte) 0x7b, (byte) 0xdb, (byte) 0x6e, (byte) 0x3b, //
				(byte) 0x43, (byte) 0x26, (byte) 0x67, (byte) 0xeb, //
				(byte) 0x06, (byte) 0xf4, (byte) 0xd1, (byte) 0x4b, //
				(byte) 0xff, (byte) 0x2f, (byte) 0xbd, (byte) 0x0f, //
				(byte) 0xcb, (byte) 0x90, (byte) 0x0f, (byte) 0x2f, //
				(byte) 0xdd, (byte) 0xbe, (byte) 0x40, (byte) 0x43, //
				(byte) 0x26, (byte) 0x60, (byte) 0x19, (byte) 0x65, //
				(byte) 0xc8, (byte) 0x89, (byte) 0xbf, (byte) 0x17, //
				(byte) 0xdb, (byte) 0xa7, (byte) 0x7c, (byte) 0xeb, //
				(byte) 0x09, (byte) 0x4f, (byte) 0xa6, (byte) 0x63, //
				(byte) 0xb7, (byte) 0xa3, (byte) 0xf7, (byte) 0x48, //
				(byte) 0xba, (byte) 0x8a, (byte) 0xf8, (byte) 0x29, //
				(byte) 0xea, (byte) 0x64, (byte) 0xad, (byte) 0x54, //
				(byte) 0x4a, (byte) 0x27, (byte) 0x2e, (byte) 0x9c, //
				(byte) 0x48, (byte) 0x5b, (byte) 0x62, (byte) 0xa3, //
				(byte) 0xfd, (byte) 0x5c, (byte) 0x0d};

		Assertions.assertArrayEquals(expected, result);
	}

	@Test
	public void testEncryptionAndDecryptionUsingJavaxCryptoApi() throws UnauthenticCiphertextException, IllegalBlockSizeException {
		final byte[] dummyKey = new byte[16];
		final SecretKey ctrKey = new SecretKeySpec(dummyKey, "AES");
		final SecretKey macKey = new SecretKeySpec(dummyKey, "AES");
		final SivMode sivMode = new SivMode();
		final byte[] cleartext = "hello world".getBytes();
		final byte[] ciphertext = sivMode.encrypt(ctrKey, macKey, cleartext);
		final byte[] decrypted = sivMode.decrypt(ctrKey, macKey, ciphertext);
		Assertions.assertArrayEquals(cleartext, decrypted);
	}

	@Test
	public void testShiftLeft() {
		final byte[] output = new byte[4];

		SivMode.shiftLeft(new byte[] {(byte) 0x77, (byte) 0x3A, (byte) 0x87, (byte) 0x22}, output);
		Assertions.assertArrayEquals(new byte[] {(byte) 0xEE, (byte) 0x75, (byte) 0x0E, (byte) 0x44}, output);

		SivMode.shiftLeft(new byte[] {(byte) 0x56, (byte) 0x12, (byte) 0x34, (byte) 0x99}, output);
		Assertions.assertArrayEquals(new byte[] {(byte) 0xAC, (byte) 0x24, (byte) 0x69, (byte) 0x32}, output);

		SivMode.shiftLeft(new byte[] {(byte) 0xCF, (byte) 0xAB, (byte) 0xBA, (byte) 0x78}, output);
		Assertions.assertArrayEquals(new byte[] {(byte) 0x9F, (byte) 0x57, (byte) 0x74, (byte) 0xF0}, output);

		SivMode.shiftLeft(new byte[] {(byte) 0x89, (byte) 0x65, (byte) 0x43, (byte) 0x21}, output);
		Assertions.assertArrayEquals(new byte[] {(byte) 0x12, (byte) 0xCA, (byte) 0x86, (byte) 0x42}, output);
	}

	@Test
	public void testDouble() {
		Assertions.assertArrayEquals(
				new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
						(byte) 0x00, (byte) 0x00,},
				SivMode.dbl(new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
						(byte) 0x00, (byte) 0x00, (byte) 0x00,}));

		Assertions.assertArrayEquals(
				new byte[] {(byte) 0x22, (byte) 0x44, (byte) 0x66, (byte) 0x88, (byte) 0xAA, (byte) 0xCC, (byte) 0xEF, (byte) 0x10, (byte) 0x22, (byte) 0x44, (byte) 0x66, (byte) 0x88, (byte) 0x22, (byte) 0x44,
						(byte) 0x22, (byte) 0x44,},
				SivMode.dbl(new byte[] {(byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x11,
						(byte) 0x22, (byte) 0x11, (byte) 0x22,}));

		Assertions.assertArrayEquals(
				new byte[] {(byte) 0x10, (byte) 0x88, (byte) 0x44, (byte) 0x23, (byte) 0x32, (byte) 0xEE, (byte) 0xAA, (byte) 0x66, (byte) 0x22, (byte) 0x66, (byte) 0xAA, (byte) 0xEE, (byte) 0x22, (byte) 0x44,
						(byte) 0x89, (byte) 0x97,},
				SivMode.dbl(new byte[] {(byte) 0x88, (byte) 0x44, (byte) 0x22, (byte) 0x11, (byte) 0x99, (byte) 0x77, (byte) 0x55, (byte) 0x33, (byte) 0x11, (byte) 0x33, (byte) 0x55, (byte) 0x77, (byte) 0x11,
						(byte) 0x22, (byte) 0x44, (byte) 0x88,}));

		Assertions.assertArrayEquals(
				new byte[] {(byte) 0xF5, (byte) 0x79, (byte) 0xF5, (byte) 0x78, (byte) 0x02, (byte) 0x46, (byte) 0x02, (byte) 0x46, (byte) 0xAD, (byte) 0xB8, (byte) 0x24, (byte) 0x68, (byte) 0xAD, (byte) 0xB8,
						(byte) 0x24, (byte) 0xEF,},
				SivMode.dbl(new byte[] {(byte) 0xFA, (byte) 0xBC, (byte) 0xFA, (byte) 0xBC, (byte) 0x01, (byte) 0x23, (byte) 0x01, (byte) 0x23, (byte) 0x56, (byte) 0xDC, (byte) 0x12, (byte) 0x34, (byte) 0x56,
						(byte) 0xDC, (byte) 0x12, (byte) 0x34,}));
	}

	@Test
	public void testXor() {
		Assertions.assertArrayEquals(new byte[] {}, SivMode.xor(new byte[0], new byte[0]));
		Assertions.assertArrayEquals(new byte[3], SivMode.xor(new byte[3], new byte[3]));
		Assertions.assertArrayEquals(new byte[] {(byte) 0x01, (byte) 0x02, (byte) 0x03}, SivMode.xor(new byte[] {(byte) 0xFF, (byte) 0x55, (byte) 0x81}, new byte[] {(byte) 0xFE, (byte) 0x57, (byte) 0x82}));
		Assertions.assertArrayEquals(new byte[] {(byte) 0x01, (byte) 0x02, (byte) 0x03}, SivMode.xor(new byte[] {(byte) 0xFF, (byte) 0x55, (byte) 0x81}, new byte[] {(byte) 0xFE, (byte) 0x57, (byte) 0x82}));
		Assertions.assertArrayEquals(new byte[] {(byte) 0xAB, (byte) 0x87, (byte) 0x34}, SivMode.xor(new byte[] {(byte) 0xB9, (byte) 0xB3, (byte) 0x62}, new byte[] {(byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78}));
	}

	@Test
	public void testXorend() {
		Assertions.assertArrayEquals(new byte[] {}, SivMode.xorend(new byte[0], new byte[0]));
		Assertions.assertArrayEquals(new byte[3], SivMode.xorend(new byte[3], new byte[3]));
		Assertions.assertArrayEquals(new byte[] {(byte) 0x01, (byte) 0x02, (byte) 0x03}, SivMode.xorend(new byte[] {(byte) 0xFF, (byte) 0x55, (byte) 0x81}, new byte[] {(byte) 0xFE, (byte) 0x57, (byte) 0x82}));
		Assertions.assertArrayEquals(new byte[] {(byte) 0x01, (byte) 0x02, (byte) 0x03}, SivMode.xorend(new byte[] {(byte) 0xFF, (byte) 0x55, (byte) 0x81}, new byte[] {(byte) 0xFE, (byte) 0x57, (byte) 0x82}));
		Assertions.assertArrayEquals(new byte[] {(byte) 0xB8, (byte) 0xA9, (byte) 0xAB, (byte) 0x87, (byte) 0x34},
				SivMode.xorend(new byte[] {(byte) 0xB8, (byte) 0xA9, (byte) 0xB9, (byte) 0xB3, (byte) 0x62}, new byte[] {(byte) 0x12, (byte) 0x34, (byte) 0x56}));
		Assertions.assertArrayEquals(new byte[] {(byte) 0x23, (byte) 0x80, (byte) 0x32, (byte) 0xEF, (byte) 0xDE, (byte) 0xCD, (byte) 0xAB, (byte) 0x87, (byte) 0x34},
				SivMode.xorend(new byte[] {(byte) 0x23, (byte) 0x80, (byte) 0x32, (byte) 0xEF, (byte) 0xDE, (byte) 0xCD, (byte) 0xB9, (byte) 0xB3, (byte) 0x62,}, new byte[] {(byte) 0x12, (byte) 0x34, (byte) 0x56}));
	}

	@TestFactory
	public Stream<DynamicContainer> testGeneratedTestCases() {
		InputStream in = EncryptionTestCase.class.getResourceAsStream("/testcases.txt");
		Reader reader = new InputStreamReader(in, StandardCharsets.US_ASCII);
		BufferedReader bufferedReader = new BufferedReader(reader);
		Stream<String> lines = bufferedReader.lines().onClose(() -> {
			try {
				bufferedReader.close();
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		});
		SivMode sivMode = new SivMode();
		return lines.map(EncryptionTestCase::fromLine).map(testCase -> {
			int testIdx = testCase.getTestCaseNumber();
			return DynamicContainer.dynamicContainer("test case " + testIdx, Arrays.asList(
					DynamicTest.dynamicTest("decrypt", () -> {
						byte[] actualPlaintext = sivMode.decrypt(testCase.getCtrKey(), testCase.getMacKey(), testCase.getCiphertext(), testCase.getAssociatedData());
						Assertions.assertArrayEquals(testCase.getPlaintext(), actualPlaintext);
					}),
					DynamicTest.dynamicTest("encrypt", () -> {
						byte[] actualCiphertext = sivMode.encrypt(testCase.getCtrKey(), testCase.getMacKey(), testCase.getPlaintext(), testCase.getAssociatedData());
						Assertions.assertArrayEquals(testCase.getCiphertext(), actualCiphertext);
					}),
					DynamicTest.dynamicTest("decrypt fails due to tampered MAC", () -> {
						byte[] macKey = testCase.getMacKey();

						// Pick some arbitrary key byte to tamper with
						int tamperedByteIndex = testIdx % macKey.length;

						// Flip a single bit
						macKey[tamperedByteIndex] ^= 0x10;

						Assertions.assertThrows(UnauthenticCiphertextException.class, () -> {
							sivMode.decrypt(testCase.getCtrKey(), macKey, testCase.getCiphertext(), testCase.getAssociatedData());
						});
					}),
					DynamicTest.dynamicTest("decrypt fails due to tampered ciphertext", () -> {
						byte[] ciphertext = testCase.getCiphertext();

						// Pick some arbitrary key byte to tamper with
						int tamperedByteIndex = testIdx % ciphertext.length;

						// Flip a single bit
						ciphertext[tamperedByteIndex] ^= 0x10;

						Assertions.assertThrows(UnauthenticCiphertextException.class, () -> {
							sivMode.decrypt(testCase.getCtrKey(), testCase.getMacKey(), ciphertext, testCase.getAssociatedData());
						});
					}),
					DynamicTest.dynamicTest("decrypt fails due to tampered associated data", () -> {
						byte[][] ad = testCase.getAssociatedData();

						// Try flipping bits in the associated data elements
						for (int adIdx = 0; adIdx < ad.length; adIdx++) {
							// Skip if this ad element is empty
							if (ad[adIdx].length == 0) {
								continue;
							}

							// Pick some arbitrary byte to tamper with
							int tamperedByteIndex = testIdx % ad[adIdx].length;

							// Flip a single bit
							ad[adIdx][tamperedByteIndex] ^= 0x04;

							Assertions.assertThrows(UnauthenticCiphertextException.class, () -> {
								sivMode.decrypt(testCase.getCtrKey(), testCase.getMacKey(), testCase.getCiphertext(), ad);
							});

							// Restore ad to original value
							ad[adIdx][tamperedByteIndex] ^= 0x04;
						}
					}),
					DynamicTest.dynamicTest("decrypt fails due to prepended associated data", () -> {
						// Skip if there is no more room for additional AD
						if (testCase.getAssociatedData().length > 125) {
							return;
						}

						byte[][] ad = testCase.getAssociatedData();
						byte[][] prependedAd = new byte[ad.length + 1][];
						prependedAd[0] = new byte[testIdx % 16];
						System.arraycopy(ad, 0, prependedAd, 1, ad.length);

						Assertions.assertThrows(UnauthenticCiphertextException.class, () -> {
							sivMode.decrypt(testCase.getCtrKey(), testCase.getMacKey(), testCase.getCiphertext(), prependedAd);
						});
					}),
					DynamicTest.dynamicTest("decrypt fails due to appended associated data", () -> {
						// Skip if there is no more room for additional AD
						if (testCase.getAssociatedData().length > 125) {
							return;
						}

						byte[][] ad = testCase.getAssociatedData();
						byte[][] appendedAd = new byte[ad.length + 1][];
						appendedAd[ad.length] = new byte[testIdx % 16];
						System.arraycopy(ad, 0, appendedAd, 0, ad.length);

						Assertions.assertThrows(UnauthenticCiphertextException.class, () -> {
							sivMode.decrypt(testCase.getCtrKey(), testCase.getMacKey(), testCase.getCiphertext(), appendedAd);
						});
					})
			));
		});
	}

	private Provider getSunJceProvider() {
		Provider provider = Security.getProvider("SunJCE");
		Assertions.assertNotNull(provider);
		return provider;
	}
}
