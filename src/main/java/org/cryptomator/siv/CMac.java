package org.cryptomator.siv;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.MacSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import static org.cryptomator.siv.Utils.dbl;
import static org.cryptomator.siv.Utils.xor;

/**
 * AES-CMAC (Cipher-based Message Authentication Code).
 * Specs: <a href="https://www.rfc-editor.org/rfc/rfc4493.html">RFC 4493</a>.
 */
public class CMac extends MacSpi {

	static final int BLOCK_SIZE = 16; // 128 bits for AES
	private static final String AES_ALGORITHM = "AES";
	private static final String AES_ECB_NO_PADDING = "AES/ECB/NoPadding";

	// MAC keys:
	private Cipher cipher;
	private byte[] k1;
	private byte[] k2;

	// MAC state:
	private final byte[] buffer = new byte[BLOCK_SIZE];
	private int bufferPos = 0;
	private final byte[] x = new byte[BLOCK_SIZE]; // X := const_Zero;
	private final byte[] y = new byte[BLOCK_SIZE];
	private int msgLen = 0;

	@Override
	protected int engineGetMacLength() {
		return BLOCK_SIZE;
	}

	@Override
	protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException {
		try {
			this.cipher = Cipher.getInstance(AES_ECB_NO_PADDING);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new AssertionError("Every implementation of the Java platform is required to support [...] AES/ECB/NoPadding", e);
		}
		cipher.init(Cipher.ENCRYPT_MODE, key);

		// init subkeys K1 and K2
		// see https://www.rfc-editor.org/rfc/rfc4493.html#section-2.3
		byte[] L = new byte[BLOCK_SIZE];
		try {
			// L = AES_encrypt(K, const_Zero)
			encryptBlock(cipher, L, L);
			this.k1 = dbl(L.clone());
			this.k2 = dbl(k1.clone());
		} finally {
			Arrays.fill(L, (byte) 0);
		}

		// reset state
		engineReset();
	}

	@Override
	protected void engineUpdate(byte input) {
		if (bufferPos == BLOCK_SIZE) { // buffer is full
			processBlock();
		}
		assert bufferPos < BLOCK_SIZE;
		buffer[bufferPos++] = input;
		msgLen++;
	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		for (int i = offset; i < offset + len; ) {
			if (bufferPos == BLOCK_SIZE) { // buffer is full
				processBlock();
			}
			assert bufferPos < BLOCK_SIZE;
			int required = offset + len - i;
			int available = BLOCK_SIZE - bufferPos;
			int m = Math.min(required, available);
			System.arraycopy(input, i, buffer, bufferPos, m);
			bufferPos += m;
			i += m;
		}
		msgLen += len;
	}

	// https://www.rfc-editor.org/rfc/rfc4493.html#section-2.4 Step 6
	private void processBlock() {
		xor(x, buffer, y); // Y := X XOR M_i;
		encryptBlock(cipher, y, x); // X := AES-128(K,Y);
		bufferPos = 0;
	}

	// https://www.rfc-editor.org/rfc/rfc4493.html#section-2.4
	@Override
	protected byte[] engineDoFinal() {
		// Step 3:
		boolean flag = msgLen > 0 && bufferPos % BLOCK_SIZE == 0; // denoting if last block is complete or not

		// Step 4:
		byte[] m_last = new byte[BLOCK_SIZE];
		if (flag) {
			// M_last := M_n XOR K1;
			xor(buffer, k1, m_last);
		} else {
			// M_last := padding(M_n) XOR K2;
			//
			// [...] padding(x) is the concatenation of x and a single '1',
			// followed by the minimum number of '0's, so that the total length is
			// equal to 128 bits.
			buffer[bufferPos] = (byte) 0x80; // single '1' bit
			if (bufferPos + 1 < BLOCK_SIZE) {
				Arrays.fill(buffer, bufferPos + 1, BLOCK_SIZE, (byte) 0x00); // followed by '0' bits
			}
			xor(buffer, k2, m_last);
		}

		// Step 7:
		xor(x, m_last, y); // Y := M_last XOR X;
		try {
			byte[] t = new byte[BLOCK_SIZE];
			encryptBlock(cipher, y, t); // T := AES-128(K,Y);
			return t;
		} finally {
			engineReset();
		}
	}

	@Override
	protected void engineReset() {
		bufferPos = 0;
		msgLen = 0;
		Arrays.fill(buffer, (byte) 0);
		Arrays.fill(x, (byte) 0);
		Arrays.fill(y, (byte) 0);
	}

	private static void encryptBlock(Cipher cipher, byte[] block, byte[] output) {
		try {
			cipher.doFinal(block, 0, BLOCK_SIZE, output);
		} catch (IllegalBlockSizeException e) {
			throw new IllegalArgumentException(e);
		} catch (BadPaddingException e) {
			throw new AssertionError("Not in decrypt mode", e);
		} catch (ShortBufferException e) {
			throw new IllegalArgumentException("Output buffer too short", e);
		}
	}

	/**
	 * Create a new CMAC instance for incremental message processing
	 * @param key The AES key (16, 24, or 32 bytes)
	 * @return The CMAC instance
	 * @throws IllegalArgumentException if the key length is invalid
	 */
	public static CMac create(byte[] key) {
		if (key.length != 16 && key.length != 24 && key.length != 32) {
			throw new IllegalArgumentException("Invalid key length. Must be 16, 24, or 32 bytes");
		}
		try {
			SecretKeySpec keySpec = new SecretKeySpec(key, AES_ALGORITHM);

			CMac mac = new CMac();
			mac.engineInit(keySpec, null);
			return mac;
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid key", e);
		}
	}

	/**
	 * One-shot CMAC computation
	 * @param key The AES key (16, 24, or 32 bytes)
	 * @param message The message to authenticate
	 * @return The CMAC tag (always {@value BLOCK_SIZE} bytes)
	 * @throws IllegalArgumentException if the key length is invalid
	 */
	public static byte[] tag(byte[] key, byte[] message) {
		CMac cmac = create(key);
		cmac.engineUpdate(message, 0, message.length);
		return cmac.engineDoFinal();
	}
}
