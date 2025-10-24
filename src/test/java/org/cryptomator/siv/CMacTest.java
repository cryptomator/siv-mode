package org.cryptomator.siv;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.SimpleArgumentConverter;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CMacTest {

	/**
	 * Convert hex string to byte array
	 */
	static class HexConverter extends SimpleArgumentConverter {
		@Override
		protected Object convert(Object source, Class<?> targetType) throws ArgumentConversionException {
			if (source == null) {
				return new byte[0];
			} else if (!(source instanceof String)) {
				throw new ArgumentConversionException("Source must be a String");
			}
			String hex = (String) source;
			if (hex.isEmpty()) {
				return new byte[0];
			}
			int len = hex.length();
			byte[] data = new byte[len / 2];
			for (int i = 0; i < len; i += 2) {
				data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
						+ Character.digit(hex.charAt(i + 1), 16));
			}
			return data;
		}
	}

	/**
	 * Convert byte array to hex string
	 */
	private static String bytesToHex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		for (byte b : bytes) {
			result.append(String.format("%02x", b));
		}
		return result.toString();
	}

	@ParameterizedTest(name = "{0}")
	@CsvSource(delimiterString = "|", value = {
			"Test Case 1: Empty message   | 2b7e151628aed2a6abf7158809cf4f3c |                                                                                                                                  | bb1d6929e95937287fa37d129b756746",
			"Test Case 2: 16-byte message | 2b7e151628aed2a6abf7158809cf4f3c | 6bc1bee22e409f96e93d7e117393172a                                                                                                 | 070a16b46b4d4144f79bdd9dd04a287c",
			"Test Case 3: 40-byte message | 2b7e151628aed2a6abf7158809cf4f3c | 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411                                                 | dfa66747de9ae63030ca32611497c827",
			"Test Case 4: 64-byte message | 2b7e151628aed2a6abf7158809cf4f3c | 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710 | 51f0bebf7e3b9d92fc49741779363cfe"
	})
	void testRfc4493Vectors(String testName,
							@ConvertWith(HexConverter.class) byte[] key,
							@ConvertWith(HexConverter.class) byte[] message,
							String expectedHex) {
		byte[] result = CMac.tag(key, message);
		assertEquals(expectedHex, bytesToHex(result), testName + " failed");
	}

	@ParameterizedTest(name = "{0}")
	@CsvSource(delimiterString = "|", value = {
			"AES-128 Example 1 | 2B7E151628AED2A6ABF7158809CF4F3C                                 |                                                                                                                                  | bb1d6929e95937287fa37d129b756746",
			"AES-128 Example 2 | 2B7E151628AED2A6ABF7158809CF4F3C                                 | 6BC1BEE22E409F96E93D7E117393172A                                                                                                 | 070a16b46b4d4144f79bdd9dd04a287c",
			"AES-128 Example 3 | 2B7E151628AED2A6ABF7158809CF4F3C                                 | 6BC1BEE22E409F96E93D7E117393172AAE2D8A57                                                                                         | 7d85449ea6ea19c823a7bf78837dfade",
			"AES-128 Example 4 | 2B7E151628AED2A6ABF7158809CF4F3C                                 | 6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710 | 51f0bebf7e3b9d92fc49741779363cfe",
			"AES-192 Example 1 | 8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B                 |                                                                                                                                  | d17ddf46adaacde531cac483de7a9367",
			"AES-192 Example 2 | 8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B                 | 6BC1BEE22E409F96E93D7E117393172A                                                                                                 | 9e99a7bf31e710900662f65e617c5184",
			"AES-192 Example 3 | 8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B                 | 6BC1BEE22E409F96E93D7E117393172AAE2D8A57                                                                                         | 3d75c194ed96070444a9fa7ec740ecf8",
			"AES-192 Example 4 | 8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B                 | 6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710 | a1d5df0eed790f794d77589659f39a11",
			"AES-256 Example 1 | 603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4 |                                                                                                                                  | 028962f61b7bf89efc6b551f4667d983",
			"AES-256 Example 2 | 603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4 | 6BC1BEE22E409F96E93D7E117393172A                                                                                                 | 28a7023f452e8f82bd4bf28d8c37c35c",
			"AES-256 Example 3 | 603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4 | 6BC1BEE22E409F96E93D7E117393172AAE2D8A57                                                                                         | 156727dc0878944a023c1fe03bad6d93",
			"AES-256 Example 4 | 603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4 | 6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710 | e1992190549f6ed5696a2c056c315410"
	})
	void testNistVectors(String testName,
						 @ConvertWith(HexConverter.class) byte[] key,
						 @ConvertWith(HexConverter.class) byte[] message,
						 String expectedHex) {
		byte[] result = CMac.tag(key, message);
		assertEquals(expectedHex, bytesToHex(result), testName + " failed");
	}

}