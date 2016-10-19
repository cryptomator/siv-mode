package org.cryptomator.siv;
/*******************************************************************************
 * Copyright (c) 2015 Sebastian Stenzel
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 * 
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 ******************************************************************************/

import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Implements the RFC 5297 SIV mode.
 */
public final class SivMode {

	private static final byte[] BYTES_ZERO = new byte[16];
	private static final byte DOUBLING_CONST = (byte) 0x87;

	private final BlockCipherFactory cipherFactory;

	/**
	 * Creates an AES-SIV instance using BouncyCastle's {@link AESFastEngine}, which should normally be the best choice.<br>
	 * 
	 * For embedded systems, you might want to consider using {@link #SivMode(BlockCipherFactory)} with {@link AESLightEngine} instead.
	 * 
	 * @see #SivMode(BlockCipherFactory)
	 */
	public SivMode() {
		this(new BlockCipherFactory() {

			@Override
			public BlockCipher create() {
				return new AESFastEngine();
			}

		});
	}

	/**
	 * Creates an instance using a specific BlockCipher. If you want to use AES, just use the default constructor.
	 * 
	 * @param cipherFactory A factory method creating a BlockCipher. Must use a block size of 128 bits (16 bytes).
	 */
	public SivMode(BlockCipherFactory cipherFactory) {
		// Try using cipherFactory to check that the block size is valid.
		// We assume here that the block size will not vary across calls to .create().
		if (cipherFactory.create().getBlockSize() != 16) {
			throw new IllegalArgumentException("cipherFactory must create BlockCipher objects with a 16-byte block size");
		}

		this.cipherFactory = cipherFactory;
	}

	/**
	 * Creates {@link BlockCipher}s.
	 */
	public static interface BlockCipherFactory {
		BlockCipher create();
	}

	/**
	 * Convenience method, if you are using the javax.crypto API. This is just a wrapper for {@link #encrypt(byte[], byte[], byte[], byte[]...)}.
	 * This method accesses key bytes directly and destroys these bytes when finished. However the two given keys will remain untouched.
	 * 
	 * @param ctrKey SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param macKey SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param plaintext Your plaintext, which shall be encrypted.
	 * @param additionalData Optional additional data, which gets authenticated but not encrypted.
	 * @return IV + Ciphertext as a concatenated byte array.
	 * @throws IllegalArgumentException if keys are invalid or {@link SecretKey#getEncoded()} is not supported.
	 */
	public byte[] encrypt(SecretKey ctrKey, SecretKey macKey, byte[] plaintext, byte[]... additionalData) {
		final byte[] ctrKeyBytes = ctrKey.getEncoded();
		final byte[] macKeyBytes = macKey.getEncoded();
		if (ctrKeyBytes == null || macKeyBytes == null) {
			throw new IllegalArgumentException("Can't get bytes of given key.");
		}
		try {
			return encrypt(ctrKeyBytes, macKeyBytes, plaintext, additionalData);
		} finally {
			Arrays.fill(ctrKeyBytes, (byte) 0);
			Arrays.fill(macKeyBytes, (byte) 0);
		}
	}

	/**
	 * Encrypts plaintext using SIV mode. A block cipher defined by the constructor is being used.<br>
	 * This method leaves the two given keys untouched, the calling function needs to makes sure, key bytes are destroyed when finished.
	 * 
	 * @param ctrKey SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param macKey SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param plaintext Your plaintext, which shall be encrypted.
	 * @param additionalData Optional additional data, which gets authenticated but not encrypted.
	 * @return IV + Ciphertext as a concatenated byte array.
	 * @throws IllegalArgumentException if the either of the two keys is of invalid length for the used {@link BlockCipher}.
	 */
	public byte[] encrypt(byte[] ctrKey, byte[] macKey, byte[] plaintext, byte[]... additionalData) {
		final byte[] iv = s2v(macKey, plaintext, additionalData);

		// Check if plaintext length will cause overflows
		if (plaintext.length > (Integer.MAX_VALUE - 16)) {
			throw new IllegalArgumentException("Plaintext is too long");
		}

		final int numBlocks = (plaintext.length + 15) / 16;

		// clear out the 31st and 63rd (rightmost) bit:
		final byte[] ctr = Arrays.copyOf(iv, 16);
		ctr[8] = (byte) (ctr[8] & 0x7F);
		ctr[12] = (byte) (ctr[12] & 0x7F);
		final ByteBuffer ctrBuf = ByteBuffer.wrap(ctr);
		final long initialCtrVal = ctrBuf.getLong(8);

		final byte[] x = new byte[numBlocks * 16];
		final BlockCipher cipher = cipherFactory.create();
		cipher.init(true, new KeyParameter(ctrKey));
		for (int i = 0; i < numBlocks; i++) {
			final long ctrVal = initialCtrVal + i;
			ctrBuf.putLong(8, ctrVal);
			cipher.processBlock(ctrBuf.array(), 0, x, i * 16);
			cipher.reset();
		}

		final byte[] ciphertext = xor(plaintext, x);

		// concat IV + ciphertext:
		final byte[] result = new byte[iv.length + ciphertext.length];
		System.arraycopy(iv, 0, result, 0, iv.length);
		System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
		return result;
	}

	/**
	 * Convenience method, if you are using the javax.crypto API. This is just a wrapper for {@link #decrypt(byte[], byte[], byte[], byte[]...)}.
	 * This method accesses key bytes directly and destroys these bytes when finished. However the two given keys will remain untouched.
	 * 
	 * @param ctrKey SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param macKey SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param ciphertext Your cipehrtext, which shall be decrypted.
	 * @param additionalData Optional additional data, which needs to be authenticated during decryption.
	 * @return Plaintext byte array.
	 * @throws IllegalArgumentException If keys are invalid or {@link SecretKey#getEncoded()} is not supported.
	 * @throws AEADBadTagException If the authentication failed, e.g. because ciphertext and/or additionalData are corrupted.
	 * @throws IllegalBlockSizeException If the provided ciphertext is of invalid length.
	 */
	public byte[] decrypt(SecretKey ctrKey, SecretKey macKey, byte[] ciphertext, byte[]... additionalData) throws AEADBadTagException, IllegalBlockSizeException {
		final byte[] ctrKeyBytes = ctrKey.getEncoded();
		final byte[] macKeyBytes = macKey.getEncoded();
		if (ctrKeyBytes == null || macKeyBytes == null) {
			throw new IllegalArgumentException("Can't get bytes of given key.");
		}
		try {
			return decrypt(ctrKeyBytes, macKeyBytes, ciphertext, additionalData);
		} finally {
			Arrays.fill(ctrKeyBytes, (byte) 0);
			Arrays.fill(macKeyBytes, (byte) 0);
		}
	}

	/**
	 * Decrypts ciphertext using SIV mode. A block cipher defined by the constructor is being used.<br>
	 * This method leaves the two given keys untouched, the calling function needs to makes sure, key bytes are destroyed when finished.
	 * 
	 * @param ctrKey SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param macKey SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param ciphertext Your ciphertext, which shall be encrypted.
	 * @param additionalData Optional additional data, which needs to be authenticated during decryption.
	 * @return Plaintext byte array.
	 * @throws IllegalArgumentException If the either of the two keys is of invalid length for the used {@link BlockCipher}.
	 * @throws AEADBadTagException If the authentication failed, e.g. because ciphertext and/or additionalData are corrupted.
	 * @throws IllegalBlockSizeException If the provided ciphertext is of invalid length.
	 */
	public byte[] decrypt(byte[] ctrKey, byte[] macKey, byte[] ciphertext, byte[]... additionalData) throws AEADBadTagException, IllegalBlockSizeException {
		if (ciphertext.length < 16) {
			throw new IllegalBlockSizeException("Input length must be greater than or equal 16.");
		}

		final byte[] iv = Arrays.copyOf(ciphertext, 16);
		final byte[] actualCiphertext = Arrays.copyOfRange(ciphertext, 16, ciphertext.length);

		// will not overflow because actualCiphertext.length == (ciphertext.length - 16)
		final int numBlocks = (actualCiphertext.length + 15) / 16;

		// clear out the 31st and 63rd (rightmost) bit:
		final byte[] ctr = Arrays.copyOf(iv, 16);
		ctr[8] = (byte) (ctr[8] & 0x7F);
		ctr[12] = (byte) (ctr[12] & 0x7F);
		final ByteBuffer ctrBuf = ByteBuffer.wrap(ctr);
		final long initialCtrVal = ctrBuf.getLong(8);

		final byte[] x = new byte[numBlocks * 16];
		final BlockCipher cipher = cipherFactory.create();
		cipher.init(true, new KeyParameter(ctrKey));
		for (int i = 0; i < numBlocks; i++) {
			final long ctrVal = initialCtrVal + i;
			ctrBuf.putLong(8, ctrVal);
			cipher.processBlock(ctrBuf.array(), 0, x, i * 16);
			cipher.reset();
		}

		final byte[] plaintext = xor(actualCiphertext, x);

		final byte[] control = s2v(macKey, plaintext, additionalData);

		// time-constant comparison (taken from MessageDigest.isEqual in JDK8)
		assert iv.length == control.length;
		int diff = 0;
		for (int i = 0; i < iv.length; i++) {
			diff |= iv[i] ^ control[i];
		}

		if (diff == 0) {
			return plaintext;
		} else {
			throw new AEADBadTagException("authentication in SIV decryption failed");
		}
	}

	// Visible for testing, throws IllegalArgumentException if key is not accepted by CMac#init(CipherParameters)
	byte[] s2v(byte[] macKey, byte[] plaintext, byte[]... additionalData) {
		// Maximum permitted AD length is the block size in bits - 2
		if (additionalData.length > 126) {
			// SIV mode cannot be used safely with this many AD fields
			throw new IllegalArgumentException("too many Additional Data fields");
		}

		final CipherParameters params = new KeyParameter(macKey);
		final BlockCipher cipher = cipherFactory.create();
		final CMac mac = new CMac(cipher);
		mac.init(params);

		byte[] d = mac(mac, BYTES_ZERO);

		for (byte[] s : additionalData) {
			d = xor(dbl(d), mac(mac, s));
		}

		final byte[] t;
		if (plaintext.length >= 16) {
			t = xorend(plaintext, d);
		} else {
			t = xor(dbl(d), pad(plaintext));
		}

		return mac(mac, t);
	}

	private static byte[] mac(Mac mac, byte[] in) {
		byte[] result = new byte[mac.getMacSize()];
		mac.update(in, 0, in.length);
		mac.doFinal(result, 0);
		return result;
	}

	// First bit 1, following bits 0.
	private static byte[] pad(byte[] in) {
		final byte[] result = Arrays.copyOf(in, 16);
		new ISO7816d4Padding().addPadding(result, in.length);
		return result;
	}

	// Code taken from {@link org.bouncycastle.crypto.macs.CMac}
	static int shiftLeft(byte[] block, byte[] output) {
		int i = block.length;
		int bit = 0;
		while (--i >= 0) {
			int b = block[i] & 0xff;
			output[i] = (byte) ((b << 1) | bit);
			bit = (b >>> 7) & 1;
		}
		return bit;
	}

	// Code taken from {@link org.bouncycastle.crypto.macs.CMac}
	static byte[] dbl(byte[] in) {
		byte[] ret = new byte[in.length];
		int carry = shiftLeft(in, ret);
		int xor = 0xff & DOUBLING_CONST;

		/*
		 * NOTE: This construction is an attempt at a constant-time implementation.
		 */
		int mask = (-carry) & 0xff;
		ret[in.length - 1] ^= xor & mask;

		return ret;
	}

	static byte[] xor(byte[] in1, byte[] in2) {
		assert in1.length <= in2.length : "Length of first input must be <= length of second input.";
		final byte[] result = new byte[in1.length];
		for (int i = 0; i < result.length; i++) {
			result[i] = (byte) (in1[i] ^ in2[i]);
		}
		return result;
	}

	static byte[] xorend(byte[] in1, byte[] in2) {
		assert in1.length >= in2.length : "Length of first input must be >= length of second input.";
		final byte[] result = Arrays.copyOf(in1, in1.length);
		final int diff = in1.length - in2.length;
		for (int i = 0; i < in2.length; i++) {
			result[i + diff] = (byte) (result[i + diff] ^ in2[i]);
		}
		return result;
	}

}
