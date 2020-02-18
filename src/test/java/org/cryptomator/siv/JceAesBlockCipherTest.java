package org.cryptomator.siv;
/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 ******************************************************************************/

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;

public class JceAesBlockCipherTest {

	@Test
	public void testInitWithNullParam() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () -> {
			cipher.init(true, null);
		});
		MatcherAssert.assertThat(e.getMessage(), CoreMatchers.containsString("missing parameter of type KeyParameter"));
	}

	@Test
	public void testInitWithMissingKey() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () -> {
			cipher.init(true, new AsymmetricKeyParameter(true));
		});
		MatcherAssert.assertThat(e.getMessage(), CoreMatchers.containsString("missing parameter of type KeyParameter"));
	}

	@Test
	public void testInitWithInvalidKey() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () -> {
			cipher.init(true, new KeyParameter(new byte[7]));
		});
		MatcherAssert.assertThat(e.getMessage(), CoreMatchers.containsString("Invalid key"));
	}

	@Test
	public void testInitForEncryption() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		cipher.init(true, new KeyParameter(new byte[16]));
	}

	@Test
	public void testInitForEncryptionWithProvider() {
        JceAesBlockCipher cipher = new JceAesBlockCipher(getSunJceProvider());
		cipher.init(true, new KeyParameter(new byte[16]));
	}

	@Test
	public void testInitForDecryption() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		cipher.init(false, new KeyParameter(new byte[16]));
	}

	@Test
	public void testInitForDecryptionWithProvider() {
        JceAesBlockCipher cipher = new JceAesBlockCipher(getSunJceProvider());
		cipher.init(false, new KeyParameter(new byte[16]));
	}

    private Provider getSunJceProvider() {
        Provider provider = Security.getProvider("SunJCE");
        Assertions.assertNotNull(provider);
        return provider;
    }

    @Test
	public void testGetAlgorithmName() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		Assertions.assertEquals("AES", cipher.getAlgorithmName());
	}

	@Test
	public void testGetBlockSize() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		Assertions.assertEquals(16, cipher.getBlockSize());
	}

	@Test
	public void testProcessBlockWithUninitializedCipher() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		Assertions.assertThrows(IllegalStateException.class, () -> {
			cipher.processBlock(new byte[16], 0, new byte[16], 0);
		});
	}

	@Test
	public void testProcessBlockWithInsufficientInput() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		cipher.init(true, new KeyParameter(new byte[16]));
		DataLengthException e = Assertions.assertThrows(DataLengthException.class, () -> {
			cipher.processBlock(new byte[16], 1, new byte[16], 0);
		});
		MatcherAssert.assertThat(e.getMessage(), CoreMatchers.containsString("Insufficient data in 'in'"));
	}

	@Test
	public void testProcessBlockWithInsufficientOutput() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		cipher.init(true, new KeyParameter(new byte[16]));
		DataLengthException e = Assertions.assertThrows(DataLengthException.class, () -> {
			cipher.processBlock(new byte[16], 0, new byte[16], 1);
		});
		MatcherAssert.assertThat(e.getMessage(), CoreMatchers.containsString("Insufficient space in 'out'"));
	}

	@Test
	public void testProcessBlock() {
        testProcessBlock(new JceAesBlockCipher());
    }

    @Test
    public void testProcessBlockWithProvider() {
        testProcessBlock(new JceAesBlockCipher(getSunJceProvider()));
    }

    private void testProcessBlock(JceAesBlockCipher cipher) {
        cipher.init(true, new KeyParameter(new byte[16]));
        byte[] ciphertext = new byte[16];
        int encrypted = cipher.processBlock(new byte[20], 0, ciphertext, 0);
        Assertions.assertEquals(16, encrypted);

        cipher.init(false, new KeyParameter(new byte[16]));
        byte[] cleartext = new byte[16];
        int decrypted = cipher.processBlock(ciphertext, 0, cleartext, 0);
        Assertions.assertEquals(16, decrypted);
        Assertions.assertArrayEquals(new byte[16], cleartext);
    }

    @Test
	public void testResetBeforeInitDoesNotThrowExceptions() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		cipher.reset();
	}

	@Test
	public void testResetAfterInitDoesNotThrowExceptions() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		cipher.init(true, new KeyParameter(new byte[16]));
		cipher.reset();
	}

}
