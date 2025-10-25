package org.cryptomator.siv;

import java.security.Provider;
import java.util.HashMap;

public class SivProvider extends Provider {

	public static final SivProvider INSTANCE = new SivProvider();

	public SivProvider() {
		super("SIV", 2.0, "");
		putService(new Service(this, "Mac", "CMAC", CMac.class.getName(), null, new HashMap<>()));
	}

}
