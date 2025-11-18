package org.cryptomator.siv;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Official RFC 5297 test vector taken from https://tools.ietf.org/html/rfc5297#appendix-A.1 and https://tools.ietf.org/html/rfc5297#appendix-A.2
 */
public class SivEngineTest {

	@Nested
	public class ParameterValidation {

		@ParameterizedTest
		@ValueSource(ints = {0, 31, 33, 47, 49, 63, 65})
		public void testCreateWithInvalidKeyLength(int keylen) {
			byte[] key = new byte[keylen];

			Assertions.assertThrows(IllegalArgumentException.class, () -> new SivEngine(key));
		}

		@Test
		public void testDecryptWithInvalidBlockSize() {
			final byte[] key = new byte[32];

			SivEngine siv = new SivEngine(key);
			Assertions.assertThrows(IllegalBlockSizeException.class, () -> {
				siv.decrypt(new byte[10]);
			});
		}

		@Test
		public void testEncryptAssociatedDataLimit() {
			final byte[] key = new byte[32];
			final byte[] plaintext = new byte[30];

			SivEngine siv = new SivEngine(key);
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				siv.encrypt(plaintext, new byte[127][0]);
			});
		}

		@Test
		public void testDecryptAssociatedDataLimit() {
			final byte[] key = new byte[32];
			final byte[] plaintext = new byte[80];

			SivEngine siv = new SivEngine(key);
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				siv.decrypt(plaintext, new byte[127][0]);
			});
		}
	}

	@ParameterizedTest
	@ValueSource(ints = {32, 48, 64})
	public void testEncryptionAndDecryption(int keylen) throws AEADBadTagException, IllegalBlockSizeException {
		final byte[] key = new byte[keylen];
		final SivEngine siv = new SivEngine(key);
		final byte[] cleartext = "hello world".getBytes();
		final byte[] ciphertext = siv.encrypt(cleartext);
		final byte[] decrypted = siv.decrypt(ciphertext);
		Assertions.assertArrayEquals(cleartext, decrypted);
	}

	// https://tools.ietf.org/html/rfc5297#appendix-A.1
	@Nested
	public class RfcTestVector1 {

		private final byte[] key = {(byte) 0xff, (byte) 0xfe, (byte) 0xfd, (byte) 0xfc, //
				(byte) 0xfb, (byte) 0xfa, (byte) 0xf9, (byte) 0xf8, //
				(byte) 0xf7, (byte) 0xf6, (byte) 0xf5, (byte) 0xf4, //
				(byte) 0xf3, (byte) 0xf2, (byte) 0xf1, (byte) 0xf0, //

				(byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, //
				(byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, //
				(byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, //
				(byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff};

		private final byte[] ad = {(byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, //
				(byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17, //
				(byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, //
				(byte) 0x1c, (byte) 0x1d, (byte) 0x1e, (byte) 0x1f, //
				(byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23, //
				(byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27};

		private final byte[] plaintext = {(byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, //
				(byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, //
				(byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, //
				(byte) 0xdd, (byte) 0xee};

		final byte[] ciphertext = {(byte) 0x85, (byte) 0x63, (byte) 0x2d, (byte) 0x07, //
				(byte) 0xc6, (byte) 0xe8, (byte) 0xf3, (byte) 0x7f, //
				(byte) 0x95, (byte) 0x0a, (byte) 0xcd, (byte) 0x32, //
				(byte) 0x0a, (byte) 0x2e, (byte) 0xcc, (byte) 0x93, //
				(byte) 0x40, (byte) 0xc0, (byte) 0x2b, (byte) 0x96, //
				(byte) 0x90, (byte) 0xc4, (byte) 0xdc, (byte) 0x04, //
				(byte) 0xda, (byte) 0xef, (byte) 0x7f, (byte) 0x6a, //
				(byte) 0xfe, (byte) 0x5c};

		// CTR-AES
		@Test
		public void testComputeCtr() {
			final byte[] ctr = {(byte) 0x85, (byte) 0x63, (byte) 0x2d, (byte) 0x07, //
					(byte) 0xc6, (byte) 0xe8, (byte) 0xf3, (byte) 0x7f, //
					(byte) 0x15, (byte) 0x0a, (byte) 0xcd, (byte) 0x32, //
					(byte) 0x0a, (byte) 0x2e, (byte) 0xcc, (byte) 0x93};

			final byte[] expected = {(byte) 0x51, (byte) 0xe2, (byte) 0x18, (byte) 0xd2, //
					(byte) 0xc5, (byte) 0xa2, (byte) 0xab, (byte) 0x8c, //
					(byte) 0x43, (byte) 0x45, (byte) 0xc4, (byte) 0xa6, //
					(byte) 0x23, (byte) 0xb2, (byte) 0xf0, (byte) 0x8f};

			final byte[] result = new SivEngine(key).computeCtr(new byte[16], ctr);
			Assertions.assertArrayEquals(expected, result);
		}

		@Test
		public void testS2v() {
			final byte[] expected = {(byte) 0x85, (byte) 0x63, (byte) 0x2d, (byte) 0x07, //
					(byte) 0xc6, (byte) 0xe8, (byte) 0xf3, (byte) 0x7f, //
					(byte) 0x95, (byte) 0x0a, (byte) 0xcd, (byte) 0x32, //
					(byte) 0x0a, (byte) 0x2e, (byte) 0xcc, (byte) 0x93};

			final byte[] result = new SivEngine(key).s2v(plaintext, ad);
			Assertions.assertArrayEquals(expected, result);
		}

		@Test
		public void testSivEncrypt() {
			final byte[] result = new SivEngine(key).encrypt(plaintext, ad);
			Assertions.assertArrayEquals(ciphertext, result);
		}

		@Test
		public void testSivDecrypt() throws AEADBadTagException, IllegalBlockSizeException {
			final byte[] result = new SivEngine(key).decrypt(ciphertext, ad);
			Assertions.assertArrayEquals(plaintext, result);
		}

		@Test
		public void testSivDecryptWithInvalidKey() {
			final byte[] invalidKey = Arrays.copyOf(key, key.length);
			invalidKey[invalidKey.length - 1] = 0x00;

			SivEngine siv = new SivEngine(invalidKey);
			Assertions.assertThrows(AEADBadTagException.class, () -> {
				siv.decrypt(ciphertext, ad);
			});
		}

		@Test
		public void testSivDecryptWithInvalidCiphertext() {
			final byte[] invalidCiphertext = Arrays.copyOf(ciphertext, ciphertext.length);
			invalidCiphertext[invalidCiphertext.length - 1] = 0x00;

			SivEngine siv = new SivEngine(key);
			Assertions.assertThrows(AEADBadTagException.class, () -> {
				siv.decrypt(invalidCiphertext);
			});
		}

		@Test
		public void testSivDecryptWithTruncatedCiphertext() {
			final byte[] invalidCiphertext = Arrays.copyOf(ciphertext, 15);

			SivEngine siv = new SivEngine(key);
			Assertions.assertThrows(IllegalBlockSizeException.class, () -> {
				siv.decrypt(invalidCiphertext);
			});
		}

	}

	// https://tools.ietf.org/html/rfc5297#appendix-A.2
	@Nested
	public class RfcTestVector2 {

		private final byte[] key = {
				(byte) 0x7f, (byte) 0x7e, (byte) 0x7d, (byte) 0x7c, //
				(byte) 0x7b, (byte) 0x7a, (byte) 0x79, (byte) 0x78, //
				(byte) 0x77, (byte) 0x76, (byte) 0x75, (byte) 0x74, //
				(byte) 0x73, (byte) 0x72, (byte) 0x71, (byte) 0x70, //

				(byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, //
				(byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47, //
				(byte) 0x48, (byte) 0x49, (byte) 0x4a, (byte) 0x4b, //
				(byte) 0x4c, (byte) 0x4d, (byte) 0x4e, (byte) 0x4f};

		final byte[] ad1 = {(byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, //
				(byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, //
				(byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, //
				(byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff, //
				(byte) 0xde, (byte) 0xad, (byte) 0xda, (byte) 0xda, //
				(byte) 0xde, (byte) 0xad, (byte) 0xda, (byte) 0xda, //
				(byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, //
				(byte) 0xbb, (byte) 0xaa, (byte) 0x99, (byte) 0x88, //
				(byte) 0x77, (byte) 0x66, (byte) 0x55, (byte) 0x44, //
				(byte) 0x33, (byte) 0x22, (byte) 0x11, (byte) 0x00};

		final byte[] ad2 = {(byte) 0x10, (byte) 0x20, (byte) 0x30, (byte) 0x40, //
				(byte) 0x50, (byte) 0x60, (byte) 0x70, (byte) 0x80, //
				(byte) 0x90, (byte) 0xa0};

		final byte[] nonce = {(byte) 0x09, (byte) 0xf9, (byte) 0x11, (byte) 0x02, //
				(byte) 0x9d, (byte) 0x74, (byte) 0xe3, (byte) 0x5b, //
				(byte) 0xd8, (byte) 0x41, (byte) 0x56, (byte) 0xc5, //
				(byte) 0x63, (byte) 0x56, (byte) 0x88, (byte) 0xc0};

		final byte[] plaintext = {(byte) 0x74, (byte) 0x68, (byte) 0x69, (byte) 0x73, //
				(byte) 0x20, (byte) 0x69, (byte) 0x73, (byte) 0x20, //
				(byte) 0x73, (byte) 0x6f, (byte) 0x6d, (byte) 0x65, //
				(byte) 0x20, (byte) 0x70, (byte) 0x6c, (byte) 0x61, //
				(byte) 0x69, (byte) 0x6e, (byte) 0x74, (byte) 0x65, //
				(byte) 0x78, (byte) 0x74, (byte) 0x20, (byte) 0x74, //
				(byte) 0x6f, (byte) 0x20, (byte) 0x65, (byte) 0x6e, //
				(byte) 0x63, (byte) 0x72, (byte) 0x79, (byte) 0x70, //
				(byte) 0x74, (byte) 0x20, (byte) 0x75, (byte) 0x73, //
				(byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x20, //
				(byte) 0x53, (byte) 0x49, (byte) 0x56, (byte) 0x2d, //
				(byte) 0x41, (byte) 0x45, (byte) 0x53};

		final byte[] ciphertext = {(byte) 0x7b, (byte) 0xdb, (byte) 0x6e, (byte) 0x3b, //
				(byte) 0x43, (byte) 0x26, (byte) 0x67, (byte) 0xeb, //
				(byte) 0x06, (byte) 0xf4, (byte) 0xd1, (byte) 0x4b, //
				(byte) 0xff, (byte) 0x2f, (byte) 0xbd, (byte) 0x0f, //
				(byte) 0xcb, (byte) 0x90, (byte) 0x0f, (byte) 0x2f, //
				(byte) 0xdd, (byte) 0xbe, (byte) 0x40, (byte) 0x43, //
				(byte) 0x26, (byte) 0x60, (byte) 0x19, (byte) 0x65, //
				(byte) 0xc8, (byte) 0x89, (byte) 0xbf, (byte) 0x17, //
				(byte) 0xdb, (byte) 0xa7, (byte) 0x7c, (byte) 0xeb, //
				(byte) 0x09, (byte) 0x4f, (byte) 0xa6, (byte) 0x63, //
				(byte) 0xb7, (byte) 0xa3, (byte) 0xf7, (byte) 0x48, //
				(byte) 0xba, (byte) 0x8a, (byte) 0xf8, (byte) 0x29, //
				(byte) 0xea, (byte) 0x64, (byte) 0xad, (byte) 0x54, //
				(byte) 0x4a, (byte) 0x27, (byte) 0x2e, (byte) 0x9c, //
				(byte) 0x48, (byte) 0x5b, (byte) 0x62, (byte) 0xa3, //
				(byte) 0xfd, (byte) 0x5c, (byte) 0x0d};

		@Test
		public void testComputeCtr() {
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

			final byte[] result = new SivEngine(key).computeCtr(new byte[48], ctr);
			Assertions.assertArrayEquals(expected, result);
		}

		@Test
		public void testSivEncrypt() {
			final byte[] result = new SivEngine(key).encrypt(plaintext, ad1, ad2, nonce);
			Assertions.assertArrayEquals(ciphertext, result);
		}

		@Test
		public void testSivDecrypt() throws AEADBadTagException, IllegalBlockSizeException {
			final byte[] result = new SivEngine(key).decrypt(ciphertext, ad1, ad2, nonce);
			Assertions.assertArrayEquals(plaintext, result);
		}

	}

	@TestFactory
	public Stream<DynamicContainer> testGeneratedTestCases() {
		InputStream in = EncryptionTestCase.class.getResourceAsStream("/testcases.txt");
		Reader reader = new InputStreamReader(in, StandardCharsets.US_ASCII);
		BufferedReader bufferedReader = new BufferedReader(reader);
		Stream<String> lines = bufferedReader.lines().onClose(() -> {
			try {
				bufferedReader.close();
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		});
		return lines.map(EncryptionTestCase::fromLine).map(testCase -> {
			int testIdx = testCase.getTestCaseNumber();
			SivEngine siv = new SivEngine(testCase.getKey());
			return DynamicContainer.dynamicContainer("test case " + testIdx, Arrays.asList(
					DynamicTest.dynamicTest("decrypt", () -> {
						byte[] actualPlaintext = siv.decrypt(testCase.getCiphertext(), testCase.getAssociatedData());
						Assertions.assertArrayEquals(testCase.getPlaintext(), actualPlaintext);
					}),
					DynamicTest.dynamicTest("encrypt", () -> {
						byte[] actualCiphertext = siv.encrypt(testCase.getPlaintext(), testCase.getAssociatedData());
						Assertions.assertArrayEquals(testCase.getCiphertext(), actualCiphertext);
					}),
					DynamicTest.dynamicTest("decrypt fails due to tampered mac key", () -> {
						byte[] key = testCase.getKey();

						// Pick some arbitrary byte from first half of key (i.e. the MAC key) to tamper with
						int halfKeyLen = key.length / 2;
						int tamperedByteIndex = testIdx % halfKeyLen;

						// Flip a single bit
						key[tamperedByteIndex] ^= 0x10;

						SivEngine sivWithTamperedKey = new SivEngine(key);

						Assertions.assertThrows(AEADBadTagException.class, () -> {
							sivWithTamperedKey.decrypt(testCase.getCiphertext(), testCase.getAssociatedData());
						});
					}),
					DynamicTest.dynamicTest("decrypt fails due to tampered ciphertext", () -> {
						byte[] ciphertext = testCase.getCiphertext();

						// Pick some arbitrary key byte to tamper with
						int tamperedByteIndex = testIdx % ciphertext.length;

						// Flip a single bit
						ciphertext[tamperedByteIndex] ^= 0x10;

						Assertions.assertThrows(AEADBadTagException.class, () -> {
							siv.decrypt(ciphertext, testCase.getAssociatedData());
						});
					}),
					DynamicTest.dynamicTest("decrypt fails due to tampered associated data", () -> {
						byte[][] ad = testCase.getAssociatedData();

						// Try flipping bits in the associated data elements
						for (int adIdx = 0; adIdx < ad.length; adIdx++) {
							// Skip if this ad element is empty
							if (ad[adIdx].length == 0) {
								continue;
							}

							// Pick some arbitrary byte to tamper with
							int tamperedByteIndex = testIdx % ad[adIdx].length;

							// Flip a single bit
							ad[adIdx][tamperedByteIndex] ^= 0x04;

							Assertions.assertThrows(AEADBadTagException.class, () -> {
								siv.decrypt(testCase.getCiphertext(), ad);
							});

							// Restore ad to original value
							ad[adIdx][tamperedByteIndex] ^= 0x04;
						}
					}),
					DynamicTest.dynamicTest("decrypt fails due to prepended associated data", () -> {
						// Skip if there is no more room for additional AD
						if (testCase.getAssociatedData().length > 125) {
							return;
						}

						byte[][] ad = testCase.getAssociatedData();
						byte[][] prependedAd = new byte[ad.length + 1][];
						prependedAd[0] = new byte[testIdx % 16];
						System.arraycopy(ad, 0, prependedAd, 1, ad.length);

						Assertions.assertThrows(AEADBadTagException.class, () -> {
							siv.decrypt(testCase.getCiphertext(), prependedAd);
						});
					}),
					DynamicTest.dynamicTest("decrypt fails due to appended associated data", () -> {
						// Skip if there is no more room for additional AD
						if (testCase.getAssociatedData().length > 125) {
							return;
						}

						byte[][] ad = testCase.getAssociatedData();
						byte[][] appendedAd = new byte[ad.length + 1][];
						appendedAd[ad.length] = new byte[testIdx % 16];
						System.arraycopy(ad, 0, appendedAd, 0, ad.length);

						Assertions.assertThrows(AEADBadTagException.class, () -> {
							siv.decrypt(testCase.getCiphertext(), appendedAd);
						});
					})
			));
		});
	}

}
