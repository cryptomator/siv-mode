package org.cryptomator.siv;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import java.security.Security;

class SivProviderTest {

	@Test
	public void getMac() {
		Security.addProvider(SivProvider.INSTANCE);

		Assertions.assertDoesNotThrow(() -> Mac.getInstance("CMAC", SivProvider.INSTANCE));
		Assertions.assertDoesNotThrow(() -> Mac.getInstance("CMAC", "SIV"));
		Assertions.assertDoesNotThrow(() -> Mac.getInstance("CMAC"));
	}

}