package org.cryptomator.siv;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * JCE Cipher implementation for AES-SIV mode.
 * <p>
 * This cipher implements the Synthetic Initialization Vector (SIV) mode as specified in RFC 5297.
 */
public class SivCipher extends CipherSpi {

	private static final byte[] EMPTY = new byte[0];

	private int opmode;
	private byte[] key;
	private List<byte[]> aad;
	private byte[] inputBuffer;

	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
		if (!mode.equalsIgnoreCase("SIV")) {
			throw new NoSuchAlgorithmException("Mode must be SIV");
		}
	}

	@Override
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {
		if (!padding.equalsIgnoreCase("NoPadding")) {
			throw new NoSuchPaddingException("Padding must be NoPadding");
		}
	}

	@Override
	protected int engineGetBlockSize() {
		return 16;
	}

	@Override
	protected int engineGetOutputSize(int inputLen) {
		if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
			return 16 + inputLen;
		} else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
			return inputLen - 16;
		} else {
			throw new IllegalStateException("Invalid opmode " + this.opmode);
		}
	}

	@Override
	protected byte[] engineGetIV() {
		return null;
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {
		return null;
	}

	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
		byte[] keybytes = key.getEncoded();
		if (keybytes.length != 64 && keybytes.length != 48 && keybytes.length != 32) {
			throw new InvalidKeyException("Key length must be 256, 384, or 512 bits.");
		}
		this.opmode = opmode;
		this.key = keybytes;
		this.aad = new ArrayList<>();
		this.inputBuffer = EMPTY;
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
		engineInit(opmode, key, random);
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
		engineInit(opmode, key, random);
	}

	@Override
	protected void engineUpdateAAD(byte[] src, int offset, int len) {
		byte[] bytes = Arrays.copyOfRange(src, offset, offset + len);
		this.aad.add(bytes);
	}

	@Override
	protected void engineUpdateAAD(ByteBuffer src) {
		byte[] bytes = new byte[src.remaining()];
		src.get(bytes);
		this.aad.add(bytes);
	}

	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		int oldLen = inputBuffer.length;
		inputBuffer = Arrays.copyOf(inputBuffer, oldLen + inputLen);
		System.arraycopy(input, inputOffset, inputBuffer, oldLen, inputLen);
		return EMPTY;
	}

	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
		engineUpdate(input, inputOffset, inputLen);
		return 0;
	}

	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
		int outputSize = engineGetOutputSize(inputBuffer.length + inputLen);
		if (outputSize < 0) {
			throw new IllegalBlockSizeException("Ciphertext too short (must be at least 16 bytes including SIV tag)");
		}
		byte[] output = new byte[outputSize];
		try {
			engineDoFinal(input, inputOffset, inputLen, output, 0);
		} catch (ShortBufferException e) {
			// outputSize was calculated before, so this should never happen
			throw new IllegalStateException(e);
		}
		return output;
	}

	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		int outputSize = engineGetOutputSize(inputBuffer.length + inputLen);
		if (outputSize < 0) {
			throw new IllegalBlockSizeException("Ciphertext too short (must be at least 16 bytes including SIV tag)");
		}
		int availableSpace = output.length - outputOffset;
		if (availableSpace < outputSize) {
			throw new ShortBufferException();
		}
		engineUpdate(input, inputOffset, inputLen);

		int resultLength;
		SivEngine siv = new SivEngine(this.key);
		byte[][] aad = this.aad.toArray(new byte[this.aad.size()][]);
		if (this.opmode == Cipher.ENCRYPT_MODE || this.opmode == Cipher.WRAP_MODE) {
			resultLength = siv.encrypt(inputBuffer, output, outputOffset, aad);
		} else if (this.opmode == Cipher.DECRYPT_MODE || this.opmode == Cipher.UNWRAP_MODE) {
			// for security reasons we can't write into output directly before checking integrity:
			byte[] plaintext = new byte[0];
			try {
				plaintext = siv.decrypt(inputBuffer, aad);
				System.arraycopy(plaintext, 0, output, outputOffset, plaintext.length);
				resultLength = plaintext.length;
			} finally {
				Arrays.fill(plaintext, (byte) 0x00);
			}
		} else {
			throw new IllegalStateException("Invalid opmode " + this.opmode);
		}

		// reset internal state:
		this.inputBuffer = EMPTY;
		this.aad.clear();
		return resultLength;
	}
}
