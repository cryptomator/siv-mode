package org.cryptomator.siv;

import javax.crypto.BadPaddingException;

/**
 * Drop-in replacement for {@link javax.crypto.AEADBadTagException}, which is not available on some older Android systems.
 */
public class UnauthenticCiphertextException extends BadPaddingException {

	/**
	 * Constructs a UnauthenticCiphertextException with the specified
	 * detail message.
	 *
	 * @param message the detail message.
	 */
	public UnauthenticCiphertextException(String message) {
		super(message);
	}

}
