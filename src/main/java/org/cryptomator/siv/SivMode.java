package org.cryptomator.siv;
/*******************************************************************************
 * Copyright (c) 2015 Sebastian Stenzel
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 ******************************************************************************/

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.Provider;
import java.util.Arrays;

/**
 * Implements the RFC 5297 SIV mode.
 */
public final class SivMode {

	private static final byte[] BYTES_ZERO = new byte[16];
	private static final byte DOUBLING_CONST = (byte) 0x87;

	private final ThreadLocal<BlockCipher> threadLocalCipher;
	private final CtrComputer ctrComputer;

	/**
	 * Creates an AES-SIV instance using JCE's cipher implementation, which should normally be the best choice.<br>
	 * <p>
	 * For embedded systems, you might want to consider using {@link #SivMode(BlockCipherFactory)} with BouncyCastle's {@code AESLightEngine} instead.
	 *
	 * @see #SivMode(BlockCipherFactory)
	 */
	public SivMode() {
		this((Provider) null);
	}

	/**
	 * Creates an AES-SIV instance using a custom JCE's security provider<br>
	 * <p>
	 * For embedded systems, you might want to consider using {@link #SivMode(BlockCipherFactory)} with BouncyCastle's {@code AESLightEngine} instead.
	 *
	 * @param jceSecurityProvider to use to create the internal {@link javax.crypto.Cipher} instance
	 * @see #SivMode(BlockCipherFactory)
	 */
	public SivMode(final Provider jceSecurityProvider) {
		this(ThreadLocal.withInitial(() -> new JceAesBlockCipher(jceSecurityProvider)), new JceAesCtrComputer(jceSecurityProvider));
	}

	/**
	 * Creates an instance using a specific Blockcipher.get(). If you want to use AES, just use the default constructor.
	 *
	 * @param cipherFactory A factory method creating a Blockcipher.get(). Must use a block size of 128 bits (16 bytes).
	 */
	public SivMode(final BlockCipherFactory cipherFactory) {
		this(ThreadLocal.withInitial(() -> cipherFactory.create()));
	}

	private SivMode(final ThreadLocal<BlockCipher> threadLocalCipher) {
		this(threadLocalCipher, new CustomCtrComputer(threadLocalCipher::get));
	}
	
	private SivMode(final ThreadLocal<BlockCipher> threadLocalCipher, final CtrComputer ctrComputer) {
		// Try using cipherFactory to check that the block size is valid.
		// We assume here that the block size will not vary across calls to .create().
		if (threadLocalCipher.get().getBlockSize() != 16) {
			throw new IllegalArgumentException("cipherFactory must create BlockCipher objects with a 16-byte block size");
		}

		this.threadLocalCipher = threadLocalCipher;
		this.ctrComputer = ctrComputer;
	}

	/**
	 * Creates {@link BlockCipher}s.
	 */
	@FunctionalInterface
	public interface BlockCipherFactory {
		BlockCipher create();
	}

	/**
	 * Performs CTR computations. 
	 */
	@FunctionalInterface
	interface CtrComputer {
		byte[] computeCtr(byte[] input, byte[] key, final byte[] iv);
	}

	/**
	 * Convenience method, if you are using the javax.crypto API. This is just a wrapper for {@link #encrypt(byte[], byte[], byte[], byte[]...)}.
	 *
	 * @param ctrKey         SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param macKey         SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param plaintext      Your plaintext, which shall be encrypted.
	 * @param associatedData Optional associated data, which gets authenticated but not encrypted.
	 * @return IV + Ciphertext as a concatenated byte array.
	 * @throws IllegalArgumentException if keys are invalid or {@link SecretKey#getEncoded()} is not supported.
	 */
	public byte[] encrypt(SecretKey ctrKey, SecretKey macKey, byte[] plaintext, byte[]... associatedData) {
		final byte[] ctrKeyBytes = ctrKey.getEncoded();
		final byte[] macKeyBytes = macKey.getEncoded();
		if (ctrKeyBytes == null || macKeyBytes == null) {
			throw new IllegalArgumentException("Can't get bytes of given key.");
		}
		try {
			return encrypt(ctrKeyBytes, macKeyBytes, plaintext, associatedData);
		} finally {
			Arrays.fill(ctrKeyBytes, (byte) 0);
			Arrays.fill(macKeyBytes, (byte) 0);
		}
	}

	/**
	 * Encrypts plaintext using SIV mode. A block cipher defined by the constructor is being used.<br>
	 *
	 * @param ctrKey         SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param macKey         SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param plaintext      Your plaintext, which shall be encrypted.
	 * @param associatedData Optional associated data, which gets authenticated but not encrypted.
	 * @return IV + Ciphertext as a concatenated byte array.
	 * @throws IllegalArgumentException if the either of the two keys is of invalid length for the used {@link BlockCipher}.
	 */
	public byte[] encrypt(byte[] ctrKey, byte[] macKey, byte[] plaintext, byte[]... associatedData) {
		// Check if plaintext length will cause overflows
		if (plaintext.length > (Integer.MAX_VALUE - 16)) {
			throw new IllegalArgumentException("Plaintext is too long");
		}

		assert plaintext.length + 15 < Integer.MAX_VALUE;
		final byte[] iv = s2v(macKey, plaintext, associatedData);
		final byte[] ciphertext = computeCtr(plaintext, ctrKey, iv);

		// concat IV + ciphertext:
		final byte[] result = new byte[iv.length + ciphertext.length];
		System.arraycopy(iv, 0, result, 0, iv.length);
		System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
		return result;
	}

	/**
	 * Convenience method, if you are using the javax.crypto API. This is just a wrapper for {@link #decrypt(byte[], byte[], byte[], byte[]...)}.
	 *
	 * @param ctrKey         SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param macKey         SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param ciphertext     Your cipehrtext, which shall be decrypted.
	 * @param associatedData Optional associated data, which needs to be authenticated during decryption.
	 * @return Plaintext byte array.
	 * @throws IllegalArgumentException       If keys are invalid or {@link SecretKey#getEncoded()} is not supported.
	 * @throws UnauthenticCiphertextException If the authentication failed, e.g. because ciphertext and/or associatedData are corrupted.
	 * @throws IllegalBlockSizeException      If the provided ciphertext is of invalid length.
	 */
	public byte[] decrypt(SecretKey ctrKey, SecretKey macKey, byte[] ciphertext, byte[]... associatedData) throws UnauthenticCiphertextException, IllegalBlockSizeException {
		final byte[] ctrKeyBytes = ctrKey.getEncoded();
		final byte[] macKeyBytes = macKey.getEncoded();
		if (ctrKeyBytes == null || macKeyBytes == null) {
			throw new IllegalArgumentException("Can't get bytes of given key.");
		}
		try {
			return decrypt(ctrKeyBytes, macKeyBytes, ciphertext, associatedData);
		} finally {
			Arrays.fill(ctrKeyBytes, (byte) 0);
			Arrays.fill(macKeyBytes, (byte) 0);
		}
	}

	/**
	 * Decrypts ciphertext using SIV mode. A block cipher defined by the constructor is being used.<br>
	 *
	 * @param ctrKey         SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param macKey         SIV mode requires two separate keys. You can use one long key, which is splitted in half. See https://tools.ietf.org/html/rfc5297#section-2.2
	 * @param ciphertext     Your ciphertext, which shall be encrypted.
	 * @param associatedData Optional associated data, which needs to be authenticated during decryption.
	 * @return Plaintext byte array.
	 * @throws IllegalArgumentException       If the either of the two keys is of invalid length for the used {@link BlockCipher}.
	 * @throws UnauthenticCiphertextException If the authentication failed, e.g. because ciphertext and/or associatedData are corrupted.
	 * @throws IllegalBlockSizeException      If the provided ciphertext is of invalid length.
	 */
	public byte[] decrypt(byte[] ctrKey, byte[] macKey, byte[] ciphertext, byte[]... associatedData) throws UnauthenticCiphertextException, IllegalBlockSizeException {
		if (ciphertext.length < 16) {
			throw new IllegalBlockSizeException("Input length must be greater than or equal 16.");
		}

		final byte[] iv = Arrays.copyOf(ciphertext, 16);
		final byte[] actualCiphertext = Arrays.copyOfRange(ciphertext, 16, ciphertext.length);

		assert actualCiphertext.length == ciphertext.length - 16;
		assert actualCiphertext.length + 15 < Integer.MAX_VALUE;
		final byte[] plaintext = computeCtr(actualCiphertext, ctrKey, iv);
		final byte[] control = s2v(macKey, plaintext, associatedData);

		// time-constant comparison (taken from MessageDigest.isEqual in JDK8)
		assert iv.length == control.length;
		int diff = 0;
		for (int i = 0; i < iv.length; i++) {
			diff |= iv[i] ^ control[i];
		}

		if (diff == 0) {
			return plaintext;
		} else {
			throw new UnauthenticCiphertextException("authentication in SIV decryption failed");
		}
	}
	
	byte[] computeCtr(byte[] input, byte[] key, final byte[] iv) {
		// clear out the 31st and 63rd (rightmost) bit:
		final byte[] adjustedIv = Arrays.copyOf(iv, 16);
		adjustedIv[8] = (byte) (adjustedIv[8] & 0x7F);
		adjustedIv[12] = (byte) (adjustedIv[12] & 0x7F);
		
		return ctrComputer.computeCtr(input, key, adjustedIv);
	}

	// Visible for testing, throws IllegalArgumentException if key is not accepted by CMac#init(CipherParameters)
	byte[] s2v(byte[] macKey, byte[] plaintext, byte[]... associatedData) {
		// Maximum permitted AD length is the block size in bits - 2
		if (associatedData.length > 126) {
			// SIV mode cannot be used safely with this many AD fields
			throw new IllegalArgumentException("too many Associated Data fields");
		}

		final CipherParameters params = new KeyParameter(macKey);
		final CMac mac = new CMac(threadLocalCipher.get());
		mac.init(params);
		
		// RFC 5297 defines a n == 0 case here. Where n is the length of the input vector:
		// S1 = associatedData1, S2 = associatedData2, ... Sn = plaintext
		// Since this method is invoked only by encrypt/decrypt, we always have a plaintext.
		// Thus n > 0

		byte[] d = mac(mac, BYTES_ZERO);

		for (byte[] s : associatedData) {
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
