package org.cryptomator.siv;

import java.security.Provider;
import java.util.HashMap;

/**
 * JCE Security Provider for AES-SIV mode.
 * <p>
 * Provides implementations for:
 * <ul>
 *   <li>CMAC (Cipher-based Message Authentication Code)</li>
 *   <li>AES/SIV/NoPadding cipher</li>
 * </ul>
 */
public class SivProvider extends Provider {

	/**
	 * Singleton instance of the SIV provider.
	 */
	public static final SivProvider INSTANCE = new SivProvider();

	/**
	 * Constructs a new SIV provider and registers the available algorithms.
	 */
	public SivProvider() {
		super("SIV", 2.0, "AES-SIV mode provider for authenticated encryption");
		putService(new Service(this, "Mac", "CMAC", CMac.class.getName(), null, new HashMap<>()));
		putService(new Service(this, "Cipher", "AES/SIV/NoPadding", SivCipher.class.getName(), null, new HashMap<>()));
	}

}
