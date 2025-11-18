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

	static int shiftLeft(byte[] block, byte[] output) {
		int carry = 0;

		// Left shift by 1 bit
		for (int i = block.length - 1; i >= 0; i--) {
			byte b = (byte) (block[i] & 0xff);
			output[i] = (byte) ((b << 1) | carry);
			carry = (b & 0x80) >>> 7;
		}

		return carry;
	}

	static byte[] dbl(byte[] data) {
		int carry = shiftLeft(data, data);
		int xor = 0xff & DOUBLING_CONST;

		/*
		 * NOTE: This construction is an attempt at a constant-time implementation.
		 */
		int mask = (-carry) & 0xff;
		data[data.length - 1] ^= xor & mask;

		return data;
	}

	static byte[] xor(byte[] in1, byte[] in2) {
		return xor(in1, in2, in1);
	}

	static byte[] xor(byte[] in1, byte[] in2, byte[] out) {
		assert in1.length <= in2.length : "Length of first input must be <= length of second input.";
		for (int i = 0; i < in1.length; i++) {
			out[i] = (byte) (in1[i] ^ in2[i]);
		}
		return out;
	}

	static byte[] xorend(byte[] in1, byte[] in2) {
		assert in1.length >= in2.length : "Length of first input must be >= length of second input.";
		final int diff = in1.length - in2.length;
		for (int i = 0; i < in2.length; i++) {
			in1[i + diff] = (byte) (in1[i + diff] ^ in2[i]);
		}
		return in1;
	}

}
