package org.cryptomator.siv;

import com.google.common.base.Splitter;
import com.google.common.io.BaseEncoding;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class EncryptionTestCase {

	private static int TESTCASE_CTR = 0;

	private final int testCaseNumber;
	private final byte[] ctrKey;
	private final byte[] macKey;
	private final byte[] plaintext;
	private final byte[][] additionalData;
	private final byte[] ciphertext;

	public EncryptionTestCase(int testCaseNumber, byte[] ctrKey, byte[] macKey, byte[] plaintext, byte[][] additionalData, byte[] ciphertext) {
		this.testCaseNumber = testCaseNumber;
		this.ctrKey = ctrKey;
		this.macKey = macKey;
		this.plaintext = plaintext;
		this.additionalData = additionalData;
		this.ciphertext = ciphertext;
	}

	public static EncryptionTestCase fromLine(String line) {
		List<String> fields = Splitter.on(';').splitToList(line);
		byte[] ctrKey = BaseEncoding.base16().decode(fields.get(0).toUpperCase());
		byte[] macKey = BaseEncoding.base16().decode(fields.get(1).toUpperCase());
		byte[] plaintext = BaseEncoding.base16().decode(fields.get(2).toUpperCase());
		int adCount = Integer.parseInt(fields.get(3));
		byte[][] ad = new byte[adCount][];
		for (int adIdx = 0; adIdx < adCount; adIdx++) {
			ad[adIdx] = BaseEncoding.base16().decode(fields.get(4+adIdx).toUpperCase());
		}
		byte[] ciphertext = BaseEncoding.base16().decode(fields.get(4+adCount).toUpperCase());
		return new EncryptionTestCase(TESTCASE_CTR++, ctrKey, macKey, plaintext, ad, ciphertext);
	}

	public int getTestCaseNumber() {
		return testCaseNumber;
	}

	public byte[] getCtrKey() {
		return Arrays.copyOf(ctrKey, ctrKey.length);
	}

	public byte[] getMacKey() {
		return Arrays.copyOf(macKey, macKey.length);
	}

	public byte[] getPlaintext() {
		return Arrays.copyOf(plaintext, plaintext.length);
	}

	public byte[][] getAssociatedData() {
		final byte[][] result = new byte[additionalData.length][];

		for (int i = 0; i < additionalData.length; i++) {
			result[i] = Arrays.copyOf(additionalData[i], additionalData[i].length);
		}

		return result;
	}

	public byte[] getCiphertext() {
		return Arrays.copyOf(ciphertext, ciphertext.length);
	}
}
