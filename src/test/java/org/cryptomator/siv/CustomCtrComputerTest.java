package org.cryptomator.siv;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CustomCtrComputerTest {
	
	private BlockCipher supplyBlockCipher() {
		return new AESLightEngine();
	}

	// CTR-AES https://tools.ietf.org/html/rfc5297#appendix-A.1
	@Test
	public void testComputeCtr1() {
		byte[] ctrKey = {(byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, //
				(byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, //
				(byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, //
				(byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff};

		byte[] ctr = {(byte) 0x85, (byte) 0x63, (byte) 0x2d, (byte) 0x07, //
				(byte) 0xc6, (byte) 0xe8, (byte) 0xf3, (byte) 0x7f, //
				(byte) 0x15, (byte) 0x0a, (byte) 0xcd, (byte) 0x32, //
				(byte) 0x0a, (byte) 0x2e, (byte) 0xcc, (byte) 0x93};

		byte[] expected = {(byte) 0x51, (byte) 0xe2, (byte) 0x18, (byte) 0xd2, //
				(byte) 0xc5, (byte) 0xa2, (byte) 0xab, (byte) 0x8c, //
				(byte) 0x43, (byte) 0x45, (byte) 0xc4, (byte) 0xa6, //
				(byte) 0x23, (byte) 0xb2, (byte) 0xf0, (byte) 0x8f};

		byte[] result = new CustomCtrComputer(this::supplyBlockCipher).computeCtr(new byte[16], ctrKey, ctr);
		Assertions.assertArrayEquals(expected, result);
	}

	// CTR-AES https://tools.ietf.org/html/rfc5297#appendix-A.2
	@Test
	public void testComputeCtr2() {
		final byte[] ctrKey = {(byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, //
				(byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47, //
				(byte) 0x48, (byte) 0x49, (byte) 0x4a, (byte) 0x4b, //
				(byte) 0x4c, (byte) 0x4d, (byte) 0x4e, (byte) 0x4f};

		final byte[] ctr = {(byte) 0x7b, (byte) 0xdb, (byte) 0x6e, (byte) 0x3b, //
				(byte) 0x43, (byte) 0x26, (byte) 0x67, (byte) 0xeb, //
				(byte) 0x06, (byte) 0xf4, (byte) 0xd1, (byte) 0x4b, //
				(byte) 0x7f, (byte) 0x2f, (byte) 0xbd, (byte) 0x0f};

		final byte[] expected = {(byte) 0xbf, (byte) 0xf8, (byte) 0x66, (byte) 0x5c, //
				(byte) 0xfd, (byte) 0xd7, (byte) 0x33, (byte) 0x63, //
				(byte) 0x55, (byte) 0x0f, (byte) 0x74, (byte) 0x00, //
				(byte) 0xe8, (byte) 0xf9, (byte) 0xd3, (byte) 0x76, //
				(byte) 0xb2, (byte) 0xc9, (byte) 0x08, (byte) 0x8e, //
				(byte) 0x71, (byte) 0x3b, (byte) 0x86, (byte) 0x17, //
				(byte) 0xd8, (byte) 0x83, (byte) 0x92, (byte) 0x26, //
				(byte) 0xd9, (byte) 0xf8, (byte) 0x81, (byte) 0x59, //
				(byte) 0x9e, (byte) 0x44, (byte) 0xd8, (byte) 0x27, //
				(byte) 0x23, (byte) 0x49, (byte) 0x49, (byte) 0xbc, //
				(byte) 0x1b, (byte) 0x12, (byte) 0x34, (byte) 0x8e, //
				(byte) 0xbc, (byte) 0x19, (byte) 0x5e, (byte) 0xc7};

		byte[] result = new CustomCtrComputer(this::supplyBlockCipher).computeCtr(new byte[48], ctrKey, ctr);
		Assertions.assertArrayEquals(expected, result);
	}
	
}
