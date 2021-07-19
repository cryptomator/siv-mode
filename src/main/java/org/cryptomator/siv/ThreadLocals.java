package org.cryptomator.siv;

import java.util.function.Supplier;

class ThreadLocals {

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
