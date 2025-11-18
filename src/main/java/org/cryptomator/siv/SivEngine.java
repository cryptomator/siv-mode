package org.cryptomator.siv;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.cryptomator.siv.Utils.dbl;
import static org.cryptomator.siv.Utils.pad;
import static org.cryptomator.siv.Utils.xor;
import static org.cryptomator.siv.Utils.xorend;

/**
 * Implements the RFC 5297 SIV mode.
 */
public final class SivEngine {

	private static final int IV_LENGTH = CMac.BLOCK_SIZE;
	private static final byte[] BYTES_ZERO = new byte[16];

	private final SecretKey macKey;
	private final SecretKey ctrKey;

	private final Mac cmac;
	private final Cipher ctrCipher;

	/**
	 * Creates an AES-SIV instance using JCE's cipher implementation, which should normally be the best choice.
	 *
	 * @param key A 256, 384, or 512 bit key. The first half is used for nonce generation, the second half for encryption
	 */
	public SivEngine(byte[] key) {
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

		try {
			this.cmac = Mac.getInstance("CMAC", SivProvider.INSTANCE);
			cmac.init(this.macKey);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Failed to find CMAC in SivProvider.", e);
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
	 * @throws IllegalArgumentException if either param exceeds the limits for safe use.
	 */
	public byte[] encrypt(byte[] plaintext, byte[]... associatedData) {
		final byte[] ciphertext = new byte[16 + plaintext.length];
		try {
			int encrypted = encrypt(plaintext, ciphertext, 0, associatedData);
			assert encrypted == ciphertext.length;
		} catch (ShortBufferException e) {
			throw new IllegalStateException(e);
		}
		return ciphertext;
	}

	public int encrypt(byte[] input, byte[] output, int outputOffset, byte[]... associatedData) throws ShortBufferException {
		// Check if plaintext length will cause overflows
		if (input.length > (Integer.MAX_VALUE - IV_LENGTH)) {
			throw new IllegalArgumentException("Plaintext is too long");
		}

		if (output.length - outputOffset < IV_LENGTH + input.length) {
			throw new ShortBufferException();
		}
		byte[] iv = s2v(input, associatedData);
		assert iv.length == IV_LENGTH;
		System.arraycopy(iv, 0, output, 0, IV_LENGTH);
		return IV_LENGTH + computeCtr(input, iv, output, IV_LENGTH);
	}

	/**
	 * Decrypts ciphertext using SIV mode. A block cipher defined by the constructor is being used.<br>
	 *
	 * @param ciphertext     Your ciphertext, which shall be encrypted.
	 * @param associatedData Optional associated data, which needs to be authenticated during decryption.
	 * @return Plaintext byte array.
	 * @throws AEADBadTagException If the authentication failed, e.g. because ciphertext and/or associatedData are corrupted.
	 * @throws IllegalBlockSizeException      If the provided ciphertext is of invalid length.
	 */
	public byte[] decrypt(byte[] ciphertext, byte[]... associatedData) throws AEADBadTagException, IllegalBlockSizeException {
		if (ciphertext.length < IV_LENGTH) {
			throw new IllegalBlockSizeException("Input length must be greater than or equal 16.");
		}

		final byte[] iv = Arrays.copyOf(ciphertext, IV_LENGTH);
		final byte[] actualCiphertext = Arrays.copyOfRange(ciphertext, IV_LENGTH, ciphertext.length);
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
			throw new AEADBadTagException("authentication in SIV decryption failed");
		}
	}

	// visible for testing
	byte[] computeCtr(byte[] input, final byte[] iv) {
		byte[] output = new byte[input.length];
		try {
			int processed = computeCtr(input, iv, output, 0);
			assert processed == output.length;
		} catch (ShortBufferException e) {
			throw new IllegalStateException(e);
		}
		return output;
	}

	// visible for testing
	int computeCtr(byte[] input, final byte[] iv, byte[] output, int outputOffset) throws ShortBufferException {
		// clear out the 31st and 63rd (rightmost) bit:
		final byte[] adjustedIv = Arrays.copyOf(iv, 16);
		adjustedIv[8] = (byte) (adjustedIv[8] & 0x7F);
		adjustedIv[12] = (byte) (adjustedIv[12] & 0x7F);

		try {
			ctrCipher.init(Cipher.ENCRYPT_MODE, ctrKey, new IvParameterSpec(adjustedIv));
			return ctrCipher.doFinal(input, 0, input.length, output, outputOffset);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("Key or IV invalid.");
		} catch (BadPaddingException e) {
			throw new IllegalStateException("Cipher doesn't require padding.", e);
		} catch (IllegalBlockSizeException e) {
			throw new IllegalStateException("Block size irrelevant for stream ciphers.", e);
		}
	}

	// visible for testing
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

	private static byte[] mac(Mac mac, byte[] in) {
		return mac.doFinal(in);
	}
}
