package org.cryptomator.siv;

import java.util.function.Supplier;

class ThreadLocals {

	static <S> ThreadLocal<S> withInitial(Supplier<S> supplier) {
		return ThreadLocal.withInitial(supplier);
	}

}
