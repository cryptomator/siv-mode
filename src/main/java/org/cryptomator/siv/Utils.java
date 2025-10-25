package org.cryptomator.siv;

import java.util.Arrays;

public class Utils {

	private static final byte DOUBLING_CONST = (byte) 0x87;

	// First bit 1, following bits 0.
	static byte[] pad(byte[] in) {
		final byte[] result = Arrays.copyOf(in, 16);
		result[in.length] = (byte) 0x80;
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
		xor(in1, in2, result);
		return result;
	}

	static void xor(byte[] in1, byte[] in2, byte[] result) {
		assert result.length <= in1.length && result.length <= in2.length : "All inputs must have the same length.";
		for (int i = 0; i < result.length; i++) {
			result[i] = (byte) (in1[i] ^ in2[i]);
		}
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
