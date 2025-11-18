package org.cryptomator.siv;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

class SivProviderTest {

	@Test
	public void getMac() {
		Security.addProvider(SivProvider.INSTANCE);

		Assertions.assertDoesNotThrow(() -> Mac.getInstance("CMAC", SivProvider.INSTANCE));
		Assertions.assertDoesNotThrow(() -> Mac.getInstance("CMAC", "SIV"));
		Assertions.assertDoesNotThrow(() -> Mac.getInstance("CMAC"));
	}

	@Test
	public void getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Security.addProvider(SivProvider.INSTANCE);

		Assertions.assertDoesNotThrow(() -> Cipher.getInstance("AES/SIV/NoPadding", SivProvider.INSTANCE));
		Assertions.assertDoesNotThrow(() -> Cipher.getInstance("AES/SIV/NoPadding", "SIV"));
		Assertions.assertDoesNotThrow(() -> Cipher.getInstance("AES/SIV/NoPadding"));

		Cipher cipher = Cipher.getInstance("AES/SIV/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[64], "AES"));
		cipher.updateAAD(new byte[1]);
		cipher.updateAAD(new byte[2]);
		cipher.update("hello".getBytes(StandardCharsets.UTF_8));
		byte[] ciphertext = cipher.doFinal("world".getBytes(StandardCharsets.UTF_8));

		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(new byte[64], "AES"));
		cipher.updateAAD(new byte[1]);
		cipher.updateAAD(new byte[2]);
		byte[] plaintext = cipher.doFinal(ciphertext);

		Assertions.assertArrayEquals("helloworld".getBytes(StandardCharsets.UTF_8), plaintext);
	}

}