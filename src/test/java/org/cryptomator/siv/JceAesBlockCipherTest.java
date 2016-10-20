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
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class JceAesBlockCipherTest {

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	@Test
	public void testInitWithNullParam() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		thrown.expect(IllegalArgumentException.class);
		thrown.expectMessage("missing parameter of type KeyParameter");
		cipher.init(true, null);
	}

	@Test
	public void testInitWithMissingKey() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		thrown.expect(IllegalArgumentException.class);
		thrown.expectMessage("missing parameter of type KeyParameter");
		cipher.init(true, new AsymmetricKeyParameter(true));
	}

	@Test
	public void testInitWithInvalidKey() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		thrown.expect(IllegalArgumentException.class);
		thrown.expectMessage("Invalid key");
		cipher.init(true, new KeyParameter(new byte[7]));
	}

	@Test
	public void testInitForEncryption() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		cipher.init(true, new KeyParameter(new byte[16]));
	}

	@Test
	public void testInitForDecryption() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		cipher.init(false, new KeyParameter(new byte[16]));
	}

	@Test
	public void testGetAlgorithmName() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		Assert.assertEquals("AES", cipher.getAlgorithmName());
	}

	@Test
	public void testGetBlockSize() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		Assert.assertEquals(16, cipher.getBlockSize());
	}

	@Test
	public void testProcessBlockWithUninitializedCipher() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		thrown.expect(IllegalStateException.class);
		cipher.processBlock(new byte[16], 0, new byte[16], 0);
	}

	@Test
	public void testProcessBlockWithUnsufficientInput() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		cipher.init(true, new KeyParameter(new byte[16]));
		thrown.expect(DataLengthException.class);
		thrown.expectMessage("Insufficient data in 'in'");
		cipher.processBlock(new byte[16], 1, new byte[16], 0);
	}

	@Test
	public void testProcessBlockWithUnsufficientOutput() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		cipher.init(true, new KeyParameter(new byte[16]));
		thrown.expect(DataLengthException.class);
		thrown.expectMessage("Insufficient space in 'out'");
		cipher.processBlock(new byte[16], 0, new byte[16], 1);
	}

	@Test
	public void testProcessBlock() {
		JceAesBlockCipher cipher = new JceAesBlockCipher();
		cipher.init(true, new KeyParameter(new byte[16]));
		byte[] ciphertext = new byte[16];
		int encrypted = cipher.processBlock(new byte[20], 0, ciphertext, 0);
		Assert.assertEquals(16, encrypted);

		cipher.init(false, new KeyParameter(new byte[16]));
		byte[] cleartext = new byte[16];
		int decrypted = cipher.processBlock(ciphertext, 0, cleartext, 0);
		Assert.assertEquals(16, decrypted);
		Assert.assertArrayEquals(new byte[16], cleartext);
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
