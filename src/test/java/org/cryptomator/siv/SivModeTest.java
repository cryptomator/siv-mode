package org.cryptomator.siv;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

@Deprecated
@DisplayName("test deprecated SivMode API")
class SivModeTest {

	@Test
	@DisplayName("encrypt/decrypt with 512 bit key")
	public void testEncryptAndDecryptWithSingleKey() throws UnauthenticCiphertextException, IllegalBlockSizeException {
		byte[] key = new byte[64];
		byte[] plaintext = "Hello, World!".getBytes();
		byte[] aad = "AdditionalData".getBytes();
		byte[] encrypted = new SivMode().encrypt(new SecretKeySpec(key, "AES"), plaintext, aad);
		byte[] decrypted = new SivMode().decrypt(new SecretKeySpec(key, "AES"), encrypted, aad);
		Assertions.assertArrayEquals(plaintext, decrypted);
	}

	@Test
	@DisplayName("encrypt/decrypt with two 256 bit keys")
	public void testEncryptAndDecryptWithSeparateKeys() throws UnauthenticCiphertextException, IllegalBlockSizeException {
		byte[] key = new byte[32];
		byte[] plaintext = "Hello, World!".getBytes();
		byte[] aad = "AdditionalData".getBytes();
		byte[] encrypted = new SivMode().encrypt(new SecretKeySpec(key, "AES"), new SecretKeySpec(key, "AES"), plaintext, aad);
		byte[] decrypted = new SivMode().decrypt(new SecretKeySpec(key, "AES"), new SecretKeySpec(key, "AES"), encrypted, aad);
		Assertions.assertArrayEquals(plaintext, decrypted);
	}

}