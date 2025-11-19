package org.cryptomator.siv;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.util.Arrays;

/**
 * Implements the RFC 5297 SIV mode.
 */
@Deprecated
public final class SivMode {

	/**
	 * Creates an AES-SIV instance using JCE's cipher implementation, which should normally be the best choice.<br>
	 */
	public SivMode() {
	}

	/**
	 * Convenience method using a single 256, 384, or 512 bits key. This is just a wrapper for {@link #encrypt(byte[], byte[], byte[], byte[]...)}.
	 * @param key Combined key, which is split in half.
	 * @param plaintext Your plaintext, which shall be encrypted.
	 * @param associatedData Optional associated data, which gets authenticated but not encrypted.
	 * @return IV + Ciphertext as a concatenated byte array.
	 */
	public byte[] encrypt(SecretKey key, byte[] plaintext, byte[]... associatedData) {
		final byte[] keyBytes = key.getEncoded();
		if (keyBytes == null) {
			throw new IllegalArgumentException("Can't get bytes of given key.");
		}
		try {
			return new SivEngine(keyBytes).encrypt(plaintext, associatedData);
		} finally {
			Arrays.fill(keyBytes, (byte) 0);
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
	 * @param ctrKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
	 * @param macKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
	 * @param plaintext      Your plaintext, which shall be encrypted.
	 * @param associatedData Optional associated data, which gets authenticated but not encrypted.
	 * @return IV + Ciphertext as a concatenated byte array.
	 * @throws IllegalArgumentException if the either of the two keys is of invalid length.
	 */
	public byte[] encrypt(byte[] ctrKey, byte[] macKey, byte[] plaintext, byte[]... associatedData) {
		byte[] combinedKey = new byte[ctrKey.length + macKey.length];
		try {
			System.arraycopy(macKey, 0, combinedKey, 0, macKey.length);
			System.arraycopy(ctrKey, 0, combinedKey, macKey.length, ctrKey.length);
			return new SivEngine(combinedKey).encrypt(plaintext, associatedData);
		} finally {
			Arrays.fill(combinedKey, (byte) 0);
		}
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
		final byte[] keyBytes = key.getEncoded();
		if (keyBytes == null) {
			throw new IllegalArgumentException("Can't get bytes of given key.");
		}
		try {
			return new SivEngine(keyBytes).decrypt(ciphertext, associatedData);
		} catch (AEADBadTagException e) {
			throw new UnauthenticCiphertextException("authentication in SIV decryption failed");
		} finally {
			Arrays.fill(keyBytes, (byte) 0);
		}
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
	 * @param ctrKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
	 * @param macKey         SIV mode requires two separate keys. You can use one long key, which is split in half. See <a href="https://tools.ietf.org/html/rfc5297#section-2.2">RFC 5297 Section 2.2</a>
	 * @param ciphertext     Your ciphertext, which shall be encrypted.
	 * @param associatedData Optional associated data, which needs to be authenticated during decryption.
	 * @return Plaintext byte array.
	 * @throws IllegalArgumentException       If the either of the two keys is of invalid length.
	 * @throws UnauthenticCiphertextException If the authentication failed, e.g. because ciphertext and/or associatedData are corrupted.
	 * @throws IllegalBlockSizeException      If the provided ciphertext is of invalid length.
	 */
	public byte[] decrypt(byte[] ctrKey, byte[] macKey, byte[] ciphertext, byte[]... associatedData) throws UnauthenticCiphertextException, IllegalBlockSizeException {
		byte[] combinedKey = new byte[ctrKey.length + macKey.length];
		try {
			System.arraycopy(macKey, 0, combinedKey, 0, macKey.length);
			System.arraycopy(ctrKey, 0, combinedKey, macKey.length, ctrKey.length);
			return new SivEngine(combinedKey).decrypt(ciphertext, associatedData);
		} catch (AEADBadTagException e) {
			throw new UnauthenticCiphertextException("authentication in SIV decryption failed");
		} finally {
			Arrays.fill(combinedKey, (byte) 0);
		}
	}

}
