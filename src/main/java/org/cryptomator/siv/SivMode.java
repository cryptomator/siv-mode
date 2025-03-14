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
import org.jetbrains.annotations.VisibleForTesting;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
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
		this(ThreadLocals.withInitial(() -> new JceAesBlockCipher(jceSecurityProvider)), new JceAesCtrComputer(jceSecurityProvider));
	}

	/**
	 * Creates an instance using a specific Blockcipher.get(). If you want to use AES, just use the default constructor.
	 *
	 * @param cipherFactory A factory method creating a Blockcipher.get(). Must use a block size of 128 bits (16 bytes).
	 */
	public SivMode(final BlockCipherFactory cipherFactory) {
		this(ThreadLocals.withInitial(cipherFactory::create));
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
		/**
		 * Creates a new {@link BlockCipher}.
		 *
		 * @return New {@link BlockCipher} instance
		 */
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
	 * Convenience method using a single 256, 384, or 512 bits key. This is just a wrapper for {@link #encrypt(byte[], byte[], byte[], byte[]...)}.
	 * @param key Combined key, which is split in half.
	 * @param plaintext Your plaintext, which shall be encrypted.
	 * @param associatedData Optional associated data, which gets authenticated but not encrypted.
	 * @return IV + Ciphertext as a concatenated byte array.
	 */
	public byte[] encrypt(SecretKey key, byte[] plaintext, byte[]... associatedData) {
		try {
			return deriveSubkeysAndThen(this::encrypt, key, plaintext, associatedData);
		} catch (UnauthenticCiphertextException | IllegalBlockSizeException e) {
			throw new IllegalStateException("Exceptions only expected during decryption", e);
		}
	}

	/**
	 * Convenience method, if you are using the javax.crypto API. This is just a wrapper for {@link #encrypt(byte[], byte[], byte[], byte[]...)}.
	 *
	 * @param ctrKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
	 * @param macKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
	 * @param plaintext      Your plaintext, which shall be encrypted.
	 * @param associatedData Optional associated data, which gets authenticated but not encrypted.
	 * @return IV + Ciphertext as a concatenated byte array.
	 * @throws IllegalArgumentException if keys are invalid or {@link SecretKey#getEncoded()} is not supported.
	 */
	public byte[] encrypt(SecretKey ctrKey, SecretKey macKey, byte[] plaintext, byte[]... associatedData) {
		try {
			return getEncodedAndThen(this::encrypt, ctrKey, macKey, plaintext, associatedData);
		} catch (UnauthenticCiphertextException | IllegalBlockSizeException e) {
			throw new IllegalStateException("Exceptions only expected during decryption", e);
		}
	}

	/**
	 * Encrypts plaintext using SIV mode. A block cipher defined by the constructor is being used.<br>
	 *
	 * @param ctrKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
	 * @param macKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
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

		final byte[] iv = s2v(macKey, plaintext, associatedData);
		final byte[] ciphertext = computeCtr(plaintext, ctrKey, iv);

		// concat IV + ciphertext:
		final byte[] result = new byte[iv.length + ciphertext.length];
		System.arraycopy(iv, 0, result, 0, iv.length);
		System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
		return result;
	}

	/**
	 * Convenience method using a single 256, 384, or 512 bits key. This is just a wrapper for {@link #decrypt(byte[], byte[], byte[], byte[]...)}.
	 * @param key Combined key, which is split in half.
	 * @param ciphertext Your cipehrtext, which shall be decrypted.
	 * @param associatedData Optional associated data, which gets authenticated but not encrypted.
	 * @return Plaintext byte array.
	 * @throws IllegalArgumentException       If keys are invalid.
	 * @throws UnauthenticCiphertextException If the authentication failed, e.g. because ciphertext and/or associatedData are corrupted.
	 * @throws IllegalBlockSizeException      If the provided ciphertext is of invalid length.
	 */
	public byte[] decrypt(SecretKey key, byte[] ciphertext, byte[]... associatedData) throws UnauthenticCiphertextException, IllegalBlockSizeException {
		return deriveSubkeysAndThen(this::decrypt, key, ciphertext, associatedData);
	}

	/**
	 * Convenience method, if you are using the javax.crypto API. This is just a wrapper for {@link #decrypt(byte[], byte[], byte[], byte[]...)}.
	 *
	 * @param ctrKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
	 * @param macKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
	 * @param ciphertext     Your cipehrtext, which shall be decrypted.
	 * @param associatedData Optional associated data, which needs to be authenticated during decryption.
	 * @return Plaintext byte array.
	 * @throws IllegalArgumentException       If keys are invalid or {@link SecretKey#getEncoded()} is not supported.
	 * @throws UnauthenticCiphertextException If the authentication failed, e.g. because ciphertext and/or associatedData are corrupted.
	 * @throws IllegalBlockSizeException      If the provided ciphertext is of invalid length.
	 */
	public byte[] decrypt(SecretKey ctrKey, SecretKey macKey, byte[] ciphertext, byte[]... associatedData) throws UnauthenticCiphertextException, IllegalBlockSizeException {
		return getEncodedAndThen(this::decrypt, ctrKey, macKey, ciphertext, associatedData);
	}

	/**
	 * Decrypts ciphertext using SIV mode. A block cipher defined by the constructor is being used.<br>
	 *
	 * @param ctrKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
	 * @param macKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
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


	/**
	 * Either {@link #encrypt(byte[], byte[], byte[], byte[]...)} or {@link #decrypt(byte[], byte[], byte[], byte[]...)}.
	 */
	@FunctionalInterface
	private interface EncryptOrDecrypt {
		byte[] compute(byte[] ctrKey, byte[] macKey, byte[] ciphertext, byte[]... associatedData) throws UnauthenticCiphertextException, IllegalBlockSizeException;
	}

	/**
	 * Splits the key into two subkeys and then encrypts or decrypts the data.
	 * @param encryptOrDecrypt Either {@link #encrypt(byte[], byte[], byte[], byte[]...)} or {@link #decrypt(byte[], byte[], byte[], byte[]...)}
	 * @param key The combined key, with the leftmost half being the S2V key and the rightmost half being the CTR key
	 * @param data The to-be-encrypted plaintext or the to-be-decrypted ciphertext
	 * @param associatedData Optional associated data
	 * @return result of the encryptOrDecrypt function
	 * @throws UnauthenticCiphertextException If the authentication failed, e.g. because ciphertext and/or associatedData are corrupted (only during decryption).
	 * @throws IllegalBlockSizeException      If the provided ciphertext is of invalid length (only during decryption).
	 */
	private byte[] deriveSubkeysAndThen(EncryptOrDecrypt encryptOrDecrypt, SecretKey key, byte[] data, byte[]... associatedData) throws UnauthenticCiphertextException, IllegalBlockSizeException {
		final byte[] keyBytes = key.getEncoded();
		if (keyBytes.length != 64 && keyBytes.length != 48 && keyBytes.length != 32) {
			throw new IllegalArgumentException("Key length must be 256, 384, or 512 bits.");
		}
		final int subkeyLen = keyBytes.length / 2;
		assert subkeyLen == 32 || subkeyLen == 24 || subkeyLen == 16;
		final byte[] macKey = new byte[subkeyLen];
		final byte[] ctrKey = new byte[subkeyLen];
		try {
			System.arraycopy(keyBytes, 0, macKey, 0, macKey.length); // K1 = leftmost(K, len(K)/2);
			System.arraycopy(keyBytes, macKey.length, ctrKey, 0, ctrKey.length); // K2 = rightmost(K, len(K)/2);
			return encryptOrDecrypt.compute(ctrKey, macKey, data, associatedData);
		} finally {
			Arrays.fill(macKey, (byte) 0);
			Arrays.fill(ctrKey, (byte) 0);
			Arrays.fill(keyBytes, (byte) 0);
		}
	}

	/**
	 * Encrypts or decrypts data using the given keys.
	 * @param encryptOrDecrypt Either {@link #encrypt(byte[], byte[], byte[], byte[]...)} or {@link #decrypt(byte[], byte[], byte[], byte[]...)}
	 * @param ctrKey The part of the key used for the CTR computation
	 * @param macKey The part of the key used for the S2V computation
	 * @param data The to-be-encrypted plaintext or the to-be-decrypted ciphertext
	 * @param associatedData Optional associated data
	 * @return result of the encryptOrDecrypt function
	 * @throws UnauthenticCiphertextException If the authentication failed, e.g. because ciphertext and/or associatedData are corrupted (only during decryption).
	 * @throws IllegalBlockSizeException      If the provided ciphertext is of invalid length (only during decryption).
	 */
	private byte[] getEncodedAndThen(EncryptOrDecrypt encryptOrDecrypt, SecretKey ctrKey, SecretKey macKey, byte[] data, byte[]... associatedData) throws UnauthenticCiphertextException, IllegalBlockSizeException {
		final byte[] ctrKeyBytes = ctrKey.getEncoded();
		final byte[] macKeyBytes = macKey.getEncoded();
		if (ctrKeyBytes == null || macKeyBytes == null) {
			throw new IllegalArgumentException("Can't get bytes of given key.");
		}
		try {
			return encryptOrDecrypt.compute(ctrKeyBytes, macKeyBytes, data, associatedData);
		} finally {
			Arrays.fill(ctrKeyBytes, (byte) 0);
			Arrays.fill(macKeyBytes, (byte) 0);
		}
	}

	@VisibleForTesting
	byte[] computeCtr(byte[] input, byte[] key, final byte[] iv) {
		// clear out the 31st and 63rd (rightmost) bit:
		final byte[] adjustedIv = Arrays.copyOf(iv, 16);
		adjustedIv[8] = (byte) (adjustedIv[8] & 0x7F);
		adjustedIv[12] = (byte) (adjustedIv[12] & 0x7F);
		
		return ctrComputer.computeCtr(input, key, adjustedIv);
	}

	@VisibleForTesting
	byte[] s2v(byte[] macKey, byte[] plaintext, byte[]... associatedData) throws IllegalArgumentException {
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
	@VisibleForTesting
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
	@VisibleForTesting
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

	@VisibleForTesting
	static byte[] xor(byte[] in1, byte[] in2) {
		assert in1.length <= in2.length : "Length of first input must be <= length of second input.";
		final byte[] result = new byte[in1.length];
		for (int i = 0; i < result.length; i++) {
			result[i] = (byte) (in1[i] ^ in2[i]);
		}
		return result;
	}

	@VisibleForTesting
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
