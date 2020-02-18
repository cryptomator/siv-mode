package org.cryptomator.siv;
/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 ******************************************************************************/

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Adapter class between BouncyCastle's {@link BlockCipher} and JCE's {@link Cipher} API.
 *
 * <p>
 * As per contract of {@link BlockCipher#processBlock(byte[], int, byte[], int)}, this class is designed to encrypt or decrypt just <b>one single block</b> at a time.
 * JCE doesn't allow us to retrieve the plain cipher without a mode, so we explicitly request {@value #SINGLE_BLOCK_PLAIN_AES_JCE_CIPHER_NAME}.
 * This is by design, because we want the plain cipher for a single 128 bit block without any mode. We're not actually using ECB mode.
 *
 * <p>
 * This is a package-private class only used to encrypt the 128 bit counter during SIV mode.
 */
final class JceAesBlockCipher implements BlockCipher {

	private static final String ALG_NAME = "AES";
	private static final String KEY_DESIGNATION = "AES";
	private static final String SINGLE_BLOCK_PLAIN_AES_JCE_CIPHER_NAME = "AES/ECB/NoPadding";

	private final Cipher cipher;
	private Key key;
	private int opmode;

	JceAesBlockCipher() {
        this(null);
    }

	JceAesBlockCipher(Provider provider) {
		try {
			if(provider != null) {
				this.cipher = Cipher.getInstance(SINGLE_BLOCK_PLAIN_AES_JCE_CIPHER_NAME, provider);
			} else {
				this.cipher = Cipher.getInstance(SINGLE_BLOCK_PLAIN_AES_JCE_CIPHER_NAME); // defaults to SunJCE
			}
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new IllegalStateException("Every implementation of the Java platform is required to support AES/ECB/NoPadding.");
		}
	}

	@Override
	public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
		if (params instanceof KeyParameter) {
			init(forEncryption, (KeyParameter) params);
		} else {
			throw new IllegalArgumentException("Invalid or missing parameter of type KeyParameter.");
		}
	}

	private void init(boolean forEncryption, KeyParameter keyParam) throws IllegalArgumentException {
		this.key = new SecretKeySpec(keyParam.getKey(), KEY_DESIGNATION);
		this.opmode = forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
		try {
			cipher.init(opmode, key);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid key.", e);
		}
	}

	@Override
	public String getAlgorithmName() {
		return ALG_NAME;
	}

	@Override
	public int getBlockSize() {
		return cipher.getBlockSize();
	}

	@Override
	public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
		if (in.length - inOff < getBlockSize()) {
			throw new DataLengthException("Insufficient data in 'in'.");
		}
		try {
			return cipher.update(in, inOff, getBlockSize(), out, outOff);
		} catch (ShortBufferException e) {
			throw new DataLengthException("Insufficient space in 'out'.");
		}
	}

	@Override
	public void reset() {
		if (key == null) {
			return; // no-op if init has not been called yet.
		}
		try {
			cipher.init(opmode, key);
		} catch (InvalidKeyException e) {
			throw new IllegalStateException("cipher.init(...) already invoked successfully earlier with same parameters.");
		}
	}

}
