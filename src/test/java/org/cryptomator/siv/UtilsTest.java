package org.cryptomator.siv;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.cryptomator.siv.Utils.dbl;
import static org.cryptomator.siv.Utils.shiftLeft;
import static org.cryptomator.siv.Utils.xor;

class UtilsTest {

	@Test
	public void testShiftLeft() {
		final byte[] output = new byte[4];

		shiftLeft(new byte[]{(byte) 0x77, (byte) 0x3A, (byte) 0x87, (byte) 0x22}, output);
		Assertions.assertArrayEquals(new byte[]{(byte) 0xEE, (byte) 0x75, (byte) 0x0E, (byte) 0x44}, output);

		shiftLeft(new byte[]{(byte) 0x56, (byte) 0x12, (byte) 0x34, (byte) 0x99}, output);
		Assertions.assertArrayEquals(new byte[]{(byte) 0xAC, (byte) 0x24, (byte) 0x69, (byte) 0x32}, output);

		shiftLeft(new byte[]{(byte) 0xCF, (byte) 0xAB, (byte) 0xBA, (byte) 0x78}, output);
		Assertions.assertArrayEquals(new byte[]{(byte) 0x9F, (byte) 0x57, (byte) 0x74, (byte) 0xF0}, output);

		shiftLeft(new byte[]{(byte) 0x89, (byte) 0x65, (byte) 0x43, (byte) 0x21}, output);
		Assertions.assertArrayEquals(new byte[]{(byte) 0x12, (byte) 0xCA, (byte) 0x86, (byte) 0x42}, output);
	}

	@Test
	public void testDouble() {
		Assertions.assertArrayEquals(
				new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
						(byte) 0x00, (byte) 0x00,},
				dbl(new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
						(byte) 0x00, (byte) 0x00, (byte) 0x00,}));

		Assertions.assertArrayEquals(
				new byte[]{(byte) 0x22, (byte) 0x44, (byte) 0x66, (byte) 0x88, (byte) 0xAA, (byte) 0xCC, (byte) 0xEF, (byte) 0x10, (byte) 0x22, (byte) 0x44, (byte) 0x66, (byte) 0x88, (byte) 0x22, (byte) 0x44,
						(byte) 0x22, (byte) 0x44,},
				dbl(new byte[]{(byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x11,
						(byte) 0x22, (byte) 0x11, (byte) 0x22,}));

		Assertions.assertArrayEquals(
				new byte[]{(byte) 0x10, (byte) 0x88, (byte) 0x44, (byte) 0x23, (byte) 0x32, (byte) 0xEE, (byte) 0xAA, (byte) 0x66, (byte) 0x22, (byte) 0x66, (byte) 0xAA, (byte) 0xEE, (byte) 0x22, (byte) 0x44,
						(byte) 0x89, (byte) 0x97,},
				dbl(new byte[]{(byte) 0x88, (byte) 0x44, (byte) 0x22, (byte) 0x11, (byte) 0x99, (byte) 0x77, (byte) 0x55, (byte) 0x33, (byte) 0x11, (byte) 0x33, (byte) 0x55, (byte) 0x77, (byte) 0x11,
						(byte) 0x22, (byte) 0x44, (byte) 0x88,}));

		Assertions.assertArrayEquals(
				new byte[]{(byte) 0xF5, (byte) 0x79, (byte) 0xF5, (byte) 0x78, (byte) 0x02, (byte) 0x46, (byte) 0x02, (byte) 0x46, (byte) 0xAD, (byte) 0xB8, (byte) 0x24, (byte) 0x68, (byte) 0xAD, (byte) 0xB8,
						(byte) 0x24, (byte) 0xEF,},
				dbl(new byte[]{(byte) 0xFA, (byte) 0xBC, (byte) 0xFA, (byte) 0xBC, (byte) 0x01, (byte) 0x23, (byte) 0x01, (byte) 0x23, (byte) 0x56, (byte) 0xDC, (byte) 0x12, (byte) 0x34, (byte) 0x56,
						(byte) 0xDC, (byte) 0x12, (byte) 0x34,}));
	}

	@Test
	public void testXor() {
		Assertions.assertArrayEquals(new byte[]{}, xor(new byte[0], new byte[0]));
		Assertions.assertArrayEquals(new byte[3], xor(new byte[3], new byte[3]));
		Assertions.assertArrayEquals(new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03}, xor(new byte[]{(byte) 0xFF, (byte) 0x55, (byte) 0x81}, new byte[]{(byte) 0xFE, (byte) 0x57, (byte) 0x82}));
		Assertions.assertArrayEquals(new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03}, xor(new byte[]{(byte) 0xFF, (byte) 0x55, (byte) 0x81}, new byte[]{(byte) 0xFE, (byte) 0x57, (byte) 0x82}));
		Assertions.assertArrayEquals(new byte[]{(byte) 0xAB, (byte) 0x87, (byte) 0x34}, xor(new byte[]{(byte) 0xB9, (byte) 0xB3, (byte) 0x62}, new byte[]{(byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78}));
	}

}