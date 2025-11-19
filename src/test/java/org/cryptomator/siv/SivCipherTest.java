package org.cryptomator.siv;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class SivCipherTest {

	private SivCipher cipher;
	private SecretKey key;

	@BeforeEach
	public void setUp() {
		this.cipher = new SivCipher();
		this.key = new SecretKeySpec(new byte[64], "AES");
	}

	@Test
	public void testEngineGetBlockSize() {
		Assertions.assertEquals(16, cipher.engineGetBlockSize());
	}

	@ParameterizedTest
	@ValueSource(strings = {"SIV", "siv", "sIv"})
	public void testEngineSetModeValid(String mode) {
		Assertions.assertDoesNotThrow(() -> cipher.engineSetMode(mode));
	}

	@ParameterizedTest
	@ValueSource(strings = {"CBC", "GCM", "invalid"})
	public void testEngineSetModeInvalid(String mode) {
		Assertions.assertThrows(NoSuchAlgorithmException.class, () -> cipher.engineSetMode(mode));
	}

	@ParameterizedTest
	@ValueSource(strings = {"NoPadding", "nopadding"})
	public void testEngineSetPaddingValid(String padding) {
		Assertions.assertDoesNotThrow(() -> cipher.engineSetPadding(padding));
	}

	@ParameterizedTest
	@ValueSource(strings = {"PKCS5Padding", "PKCS7Padding", "invalid"})
	public void testEngineSetPaddingInvalid(String padding) {
		Assertions.assertThrows(NoSuchPaddingException.class, () -> cipher.engineSetPadding(padding));
	}

	@Test
	public void testEngineGetIV() {
		Assertions.assertNull(cipher.engineGetIV());
	}

	@Test
	public void testEngineGetParameters() {
		Assertions.assertNull(cipher.engineGetParameters());
	}

	@ParameterizedTest
	@ValueSource(ints = {32, 48, 64})
	public void testEngineInitWithValidKeySize(int keysize) {
		SecretKeySpec key = new SecretKeySpec(new byte[keysize], "AES");
		Assertions.assertDoesNotThrow(() -> cipher.engineInit(Cipher.ENCRYPT_MODE, key, null));
	}

	@ParameterizedTest
	@ValueSource(ints = {16, 24, 1337})
	public void testEngineInitWithInvalidKeySize(int keysize) {
		SecretKeySpec key = new SecretKeySpec(new byte[keysize], "AES");
		Assertions.assertThrows(InvalidKeyException.class,() -> cipher.engineInit(Cipher.ENCRYPT_MODE, key, null));
	}

	@Test
	public void testEngineInitWithAlgorithmParameterSpec() {
		Assertions.assertDoesNotThrow(() -> cipher.engineInit(Cipher.ENCRYPT_MODE, key, (java.security.spec.AlgorithmParameterSpec) null, null));
	}

	@Test
	public void testEngineInitWithAlgorithmParameters() {
		Assertions.assertDoesNotThrow(() -> cipher.engineInit(Cipher.ENCRYPT_MODE, key, (java.security.AlgorithmParameters) null, null));
	}

	@ParameterizedTest
	@ValueSource(ints = {0, 1, 15, 16, 17, 100})
	public void testEngineGetOutputSizeEncryptMode(int inLen) throws InvalidKeyException {
		cipher.engineInit(Cipher.ENCRYPT_MODE, key, null);
		Assertions.assertEquals(16 + inLen, cipher.engineGetOutputSize(inLen));
	}

	@ParameterizedTest
	@ValueSource(ints = {16, 17, 100})
	public void testEngineGetOutputSizeDecryptMode(int inLen) throws InvalidKeyException {
		cipher.engineInit(Cipher.DECRYPT_MODE, key, null);
		Assertions.assertEquals(inLen - 16, cipher.engineGetOutputSize(inLen));
	}

	@Test
	public void testWrapAndUnwrap() throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		// wrap:
		cipher.engineInit(Cipher.WRAP_MODE, key, null);
		cipher.engineUpdateAAD(StandardCharsets.UTF_8.encode("aad1"));
		cipher.engineUpdateAAD("aad2".getBytes(StandardCharsets.UTF_8), 1, 2);
		byte[] wrapped1 = cipher.engineUpdate("hello".getBytes(StandardCharsets.UTF_8), 0, "hello".length());
		byte[] wrapped2 = new byte[0];
		int wrapped2Len = cipher.engineUpdate("world".getBytes(StandardCharsets.UTF_8), 0, "world".length(), wrapped2, 0);
		Assertions.assertEquals(0, wrapped1.length);
		Assertions.assertEquals(0, wrapped2Len);
		byte[] wrapped = cipher.engineDoFinal("!".getBytes(StandardCharsets.UTF_8), 0, 1);

		// unwrap:
		cipher.engineInit(Cipher.UNWRAP_MODE, key, null);
		cipher.engineUpdateAAD(StandardCharsets.UTF_8.encode("aad1"));
		cipher.engineUpdateAAD("aad2".getBytes(StandardCharsets.UTF_8), 1, 2);
		byte[] unwrapped1 = cipher.engineUpdate(wrapped, 0, 5);
		byte[] unwrapped2 = new byte[0];
		int unwrapped2Len = cipher.engineUpdate(wrapped, 5, 5, unwrapped2, 0);
		Assertions.assertEquals(0, unwrapped1.length);
		Assertions.assertEquals(0, unwrapped2Len);
		byte[] unwrapped = cipher.engineDoFinal(wrapped, 10, wrapped.length - 10);

		// compare:
		Assertions.assertEquals("helloworld!", new String(unwrapped, StandardCharsets.UTF_8));
	}
}