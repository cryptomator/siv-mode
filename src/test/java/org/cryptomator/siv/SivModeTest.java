package org.cryptomator.siv;
/*******************************************************************************
 * Copyright (c) 2015 Sebastian Stenzel
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 * 
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 ******************************************************************************/

import java.security.InvalidKeyException;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;

/**
 * Official RFC 5297 test vector taken from https://tools.ietf.org/html/rfc5297#appendix-A.1
 */
public class SivModeTest {

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
		Assert.assertArrayEquals(expected, result);
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
		Assert.assertArrayEquals(expected, result);
	}

	@Test
	public void testSivDecrypt() throws AEADBadTagException, IllegalBlockSizeException {
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
		Assert.assertArrayEquals(expected, result);
	}

	@Test(expected = AEADBadTagException.class)
	public void testSivDecryptWithInvalidKey() throws AEADBadTagException, IllegalBlockSizeException {
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

		new SivMode().decrypt(aesKey, macKey, ciphertext, ad);
	}

	@Test(expected = IllegalBlockSizeException.class)
	public void testSivDecryptWithInvalidCiphertext() throws AEADBadTagException, IllegalBlockSizeException {
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

		new SivMode().decrypt(aesKey, macKey, ciphertext);
	}

	/**
	 * https://tools.ietf.org/html/rfc5297#appendix-A.2
	 */
	@Test
	public void testNonceBasedAuthenticatedEncryption() throws InvalidKeyException {
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

		Assert.assertArrayEquals(expected, result);
	}

	@Test
	public void testEncryptionAndDecryptionUsingJavaxCryptoApi() throws AEADBadTagException, IllegalBlockSizeException {
		final byte[] dummyKey = new byte[16];
		final SecretKey ctrKey = new SecretKeySpec(dummyKey, "AES");
		final SecretKey macKey = new SecretKeySpec(dummyKey, "AES");
		final SivMode sivMode = new SivMode();
		final byte[] cleartext = "hello world".getBytes();
		final byte[] ciphertext = sivMode.encrypt(ctrKey, macKey, cleartext);
		final byte[] decrypted = sivMode.decrypt(ctrKey, macKey, ciphertext);
		Assert.assertArrayEquals(cleartext, decrypted);
	}
}
