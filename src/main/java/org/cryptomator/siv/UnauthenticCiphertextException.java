package org.cryptomator.siv;

import javax.crypto.BadPaddingException;

/**
 * Drop-in replacement for {@link javax.crypto.AEADBadTagException}, which is not available on some older Android systems.
 */
public class UnauthenticCiphertextException extends BadPaddingException {

	public UnauthenticCiphertextException(String message) {
		super(message);
	}

}
