package org.cryptomator.siv;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Performs CTR Mode computations facilitating a cipher returned by JCE's <code>Cipher.getInstance("AES/CTR/NoPadding")</code>.
 */
final class JceAesCtrComputer implements SivMode.CtrComputer {

	private final ThreadLocal<Cipher> threadLocalCipher;
	
	public JceAesCtrComputer(final Provider jceSecurityProvider) {
		this.threadLocalCipher = new ThreadLocal<Cipher>(){
			@Override
			protected Cipher initialValue() {
				try {
					if (jceSecurityProvider == null) {
						return Cipher.getInstance("AES/CTR/NoPadding");
					} else {
						return Cipher.getInstance("AES/CTR/NoPadding", jceSecurityProvider);
					}
				} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
					throw new IllegalStateException("AES/CTR/NoPadding not available on this platform.", e);
				}
			}
		};
	}

	@Override
	public byte[] computeCtr(byte[] input, byte[] key, final byte[] iv) {
		try {
			Cipher cipher = threadLocalCipher.get();
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
			return cipher.doFinal(input);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("Key or IV invalid.");
		} catch (BadPaddingException e) {
			throw new IllegalStateException("Cipher doesn't require padding.", e);
		} catch (IllegalBlockSizeException e) {
			throw new IllegalStateException("Block size irrelevant for stream ciphers.", e);
		}
	}
}
