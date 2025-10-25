package org.cryptomator.siv;

import org.jetbrains.annotations.VisibleForTesting;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Implements the RFC 5297 SIV mode.
 */
public final class SivMode {

	private static final byte[] BYTES_ZERO = new byte[16];
	private static final byte DOUBLING_CONST = (byte) 0x87;

	private final SecretKey macKey;
	private final SecretKey ctrKey;

	private final CMac cmac;
	private final Cipher ctrCipher;

	/**
	 * Creates an AES-SIV instance using JCE's cipher implementation, which should normally be the best choice.
	 *
	 * @param key A 256, 384, or 512 bit key. The first half is used for nonce generation, the second half for encryption
	 */
	public SivMode(byte[] key) {
		if (key.length != 64 && key.length != 48 && key.length != 32) {
			throw new IllegalArgumentException("Key length must be 256, 384, or 512 bits.");
		}
		final int subkeyLen = key.length / 2;
		assert subkeyLen == 32 || subkeyLen == 24 || subkeyLen == 16;
		final byte[] macKey = new byte[subkeyLen];
		final byte[] ctrKey = new byte[subkeyLen];
		System.arraycopy(key, 0, macKey, 0, macKey.length); // K1 = leftmost(K, len(K)/2);
		System.arraycopy(key, macKey.length, ctrKey, 0, ctrKey.length); // K2 = rightmost(K, len(K)/2);
		this.macKey = new SecretKeySpec(macKey, "AES");
		this.ctrKey = new SecretKeySpec(ctrKey, "AES");
		this.cmac = new CMac();
		try {
			cmac.engineInit(this.macKey, null);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException(e);
		}

		try {
			this.ctrCipher = Cipher.getInstance("AES/CTR/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new IllegalStateException("AES/CTR/NoPadding not available on this platform.", e);
		}
	}

	/**
	 * Encrypts plaintext using SIV mode. A block cipher defined by the constructor is being used.<br>
	 *
	 * @param plaintext      Your plaintext, which shall be encrypted.
	 * @param associatedData Optional associated data, which gets authenticated but not encrypted.
	 * @return IV + Ciphertext as a concatenated byte array.
	 * @throws IllegalArgumentException if either of the two keys is of invalid length.
	 */
	public byte[] encrypt(byte[] plaintext, byte[]... associatedData) {
		// Check if plaintext length will cause overflows
		if (plaintext.length > (Integer.MAX_VALUE - 16)) {
			throw new IllegalArgumentException("Plaintext is too long");
		}

		final byte[] iv = s2v(plaintext, associatedData);
		final byte[] ciphertext = computeCtr(plaintext, iv);

		// concat IV + ciphertext:
		final byte[] result = new byte[iv.length + ciphertext.length];
		System.arraycopy(iv, 0, result, 0, iv.length);
		System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
		return result;
	}

	/**
	 * Decrypts ciphertext using SIV mode. A block cipher defined by the constructor is being used.<br>
	 *
	 * @param ciphertext     Your ciphertext, which shall be encrypted.
	 * @param associatedData Optional associated data, which needs to be authenticated during decryption.
	 * @return Plaintext byte array.
	 * @throws IllegalArgumentException       If the either of the two keys is of invalid length.
	 * @throws UnauthenticCiphertextException If the authentication failed, e.g. because ciphertext and/or associatedData are corrupted.
	 * @throws IllegalBlockSizeException      If the provided ciphertext is of invalid length.
	 */
	public byte[] decrypt(byte[] ciphertext, byte[]... associatedData) throws UnauthenticCiphertextException, IllegalBlockSizeException {
		if (ciphertext.length < 16) {
			throw new IllegalBlockSizeException("Input length must be greater than or equal 16.");
		}

		final byte[] iv = Arrays.copyOf(ciphertext, 16);
		final byte[] actualCiphertext = Arrays.copyOfRange(ciphertext, 16, ciphertext.length);
		final byte[] plaintext = computeCtr(actualCiphertext, iv);
		final byte[] control = s2v(plaintext, associatedData);

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

	@VisibleForTesting
	byte[] computeCtr(byte[] input, final byte[] iv) {
		// clear out the 31st and 63rd (rightmost) bit:
		final byte[] adjustedIv = Arrays.copyOf(iv, 16);
		adjustedIv[8] = (byte) (adjustedIv[8] & 0x7F);
		adjustedIv[12] = (byte) (adjustedIv[12] & 0x7F);

		try {
			ctrCipher.init(Cipher.ENCRYPT_MODE, ctrKey, new IvParameterSpec(adjustedIv));
			return ctrCipher.doFinal(input);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("Key or IV invalid.");
		} catch (BadPaddingException e) {
			throw new IllegalStateException("Cipher doesn't require padding.", e);
		} catch (IllegalBlockSizeException e) {
			throw new IllegalStateException("Block size irrelevant for stream ciphers.", e);
		}
	}

	@VisibleForTesting
	byte[] s2v(byte[] plaintext, byte[]... associatedData) throws IllegalArgumentException {
		// Maximum permitted AD length is the block size in bits - 2
		if (associatedData.length > 126) {
			// SIV mode cannot be used safely with this many AD fields
			throw new IllegalArgumentException("too many Associated Data fields");
		}

		// RFC 5297 defines a n == 0 case here. Where n is the length of the input vector:
		// S1 = associatedData1, S2 = associatedData2, ... Sn = plaintext
		// Since this method is invoked only by encrypt/decrypt, we always have a plaintext.
		// Thus n > 0

		byte[] d = mac(cmac, BYTES_ZERO);

		for (byte[] s : associatedData) {
			d = xor(dbl(d), mac(cmac, s));
		}

		final byte[] t;
		if (plaintext.length >= 16) {
			t = xorend(plaintext, d);
		} else {
			t = xor(dbl(d), pad(plaintext));
		}

		return mac(cmac, t);
	}

	private static byte[] mac(CMac mac, byte[] in) {
		mac.engineUpdate(in, 0, in.length);
		return mac.engineDoFinal();
	}

	// First bit 1, following bits 0.
	private static byte[] pad(byte[] in) {
		final byte[] result = Arrays.copyOf(in, 16);
		result[in.length] = (byte) 0x80;
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
		xor(in1, in2, result);
		return result;
	}

	static void xor(byte[] in1, byte[] in2, byte[] result) {
		assert result.length <= in1.length && result.length <= in2.length : "All inputs must have the same length.";
		for (int i = 0; i < result.length; i++) {
			result[i] = (byte) (in1[i] ^ in2[i]);
		}
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
