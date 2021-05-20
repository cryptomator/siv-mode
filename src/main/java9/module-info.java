module org.cryptomator.siv {
	requires static org.bouncycastle.provider;

	exports org.cryptomator.siv;
	exports org.cryptomator.siv.org.bouncycastle.crypto;
	exports org.cryptomator.siv.org.bouncycastle.crypto.macs;
	exports org.cryptomator.siv.org.bouncycastle.crypto.modes;
	exports org.cryptomator.siv.org.bouncycastle.crypto.paddings;
	exports org.cryptomator.siv.org.bouncycastle.crypto.params;
	exports org.cryptomator.siv.org.bouncycastle.util;
}