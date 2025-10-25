import java.security.Provider;

module org.cryptomator.siv {
	exports org.cryptomator.siv;

	provides Provider with org.cryptomator.siv.SivProvider;
}