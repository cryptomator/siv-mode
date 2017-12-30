package org.cryptomator.siv;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.common.io.BaseEncoding;

public class EncryptionTestCase {
	private final byte[] ctrKey;
	private final byte[] macKey;
	private final byte[] plaintext;
	private final byte[][] additionalData;
	private final byte[] ciphertext;

	public EncryptionTestCase(byte[] ctrKey, byte[] macKey, byte[] plaintext, byte[][] additionalData, byte[] ciphertext) {
		this.ctrKey = ctrKey;
		this.macKey = macKey;
		this.plaintext = plaintext;
		this.additionalData = additionalData;
		this.ciphertext = ciphertext;
	}

	// Read and parse the test cases generated with `siv-test-vectors.go`
	public static EncryptionTestCase[] readTestCases() throws IOException {
		// testcases.txt should contain an output from `siv-test-vectors.go`
		BufferedReader reader = new BufferedReader(new InputStreamReader(EncryptionTestCase.class.getResourceAsStream("/testcases.txt"), StandardCharsets.US_ASCII));

		try {
			List<EncryptionTestCase> result = new ArrayList<EncryptionTestCase>();

			for (;;) {
				String ctrKeyStr = reader.readLine();
				if (ctrKeyStr == null) {
					// No more test cases
					break;
				}
				byte[] ctrKey = BaseEncoding.base16().decode(ctrKeyStr.toUpperCase());
				byte[] macKey = BaseEncoding.base16().decode(reader.readLine().toUpperCase());
				byte[] plaintext = BaseEncoding.base16().decode(reader.readLine().toUpperCase());
				int adCount = Integer.parseInt(reader.readLine());
				byte[][] ad = new byte[adCount][];
				for (int adIdx = 0; adIdx < adCount; adIdx++) {
					ad[adIdx] = BaseEncoding.base16().decode(reader.readLine().toUpperCase());
				}
				byte[] ciphertext = BaseEncoding.base16().decode(reader.readLine().toUpperCase());

				String divider = reader.readLine();
				if (!divider.equals("---")) {
					throw new IllegalStateException("expected test case divider but found: " + divider);
				}

				result.add(new EncryptionTestCase(ctrKey, macKey, plaintext, ad, ciphertext));
			}

			return result.toArray(new EncryptionTestCase[result.size()]);
		} finally {
			reader.close();
		}
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
