package org.cryptomator.siv;

import java.util.function.Supplier;

/**
 * Shim for Android 7.x
 * @see <a href="https://github.com/cryptomator/siv-mode/issues/17">Issue 17</a>
 */
class ThreadLocals {

	private ThreadLocals() {
	}

	static <S> ThreadLocal<S> withInitial(Supplier<S> supplier) {
		// ThreadLocal.withInitial is unavailable on Android 7.x
		return new ThreadLocal<S>() {
			@Override
			protected S initialValue() {
				return supplier.get();
			}
		};
	}

}
