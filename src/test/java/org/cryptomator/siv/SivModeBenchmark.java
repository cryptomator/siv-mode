/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 * 
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 ******************************************************************************/
package org.cryptomator.siv;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.cryptomator.siv.SivMode.BlockCipherFactory;
import org.junit.jupiter.api.Assertions;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import javax.crypto.IllegalBlockSizeException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * Needs to be compiled via maven as the JMH annotation processor needs to do stuff...
 */
@SuppressWarnings("deprecation")
@State(Scope.Thread)
@Warmup(iterations = 3, time = 300, timeUnit = TimeUnit.MILLISECONDS)
@Measurement(iterations = 2, time = 500, timeUnit = TimeUnit.MILLISECONDS)
@BenchmarkMode(value = {Mode.AverageTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class SivModeBenchmark {

	private int run;
	private final byte[] encKey = new byte[16];
	private final byte[] macKey = new byte[16];
	private final byte[] cleartextData = new byte[1000];
	private final byte[] associatedData = new byte[100];

	private final SivMode jceSivMode = new SivMode();
	private final SivMode bcFastSivMode = new SivMode(new BlockCipherFactory() {

		@Override
		public BlockCipher create() {
			return new AESFastEngine();
		}

	});
	private final SivMode bcLightSivMode = new SivMode(new BlockCipherFactory() {

		@Override
		public BlockCipher create() {
			return new AESLightEngine();
		}

	});

	@Setup(Level.Trial)
	public void shuffleData() {
		run++;
		Arrays.fill(encKey, (byte) (run & 0xFF));
		Arrays.fill(macKey, (byte) (run & 0xFF));
		Arrays.fill(cleartextData, (byte) (run & 0xFF));
		Arrays.fill(associatedData, (byte) (run & 0xFF));
	}

	@Benchmark
	public void benchmarkJce(Blackhole bh) throws UnauthenticCiphertextException, IllegalBlockSizeException {
		byte[] encrypted = jceSivMode.encrypt(encKey, macKey, cleartextData, associatedData);
		byte[] decrypted = jceSivMode.decrypt(encKey, macKey, encrypted, associatedData);
		Assertions.assertArrayEquals(cleartextData, decrypted);
		bh.consume(encrypted);
		bh.consume(decrypted);
	}

	@Benchmark
	public void benchmarkBcFast(Blackhole bh) throws UnauthenticCiphertextException, IllegalBlockSizeException {
		byte[] encrypted = bcFastSivMode.encrypt(encKey, macKey, cleartextData, associatedData);
		byte[] decrypted = bcFastSivMode.decrypt(encKey, macKey, encrypted, associatedData);
		Assertions.assertArrayEquals(cleartextData, decrypted);
		bh.consume(encrypted);
		bh.consume(decrypted);
	}

	@Benchmark
	public void benchmarkBcLight(Blackhole bh) throws UnauthenticCiphertextException, IllegalBlockSizeException {
		byte[] encrypted = bcLightSivMode.encrypt(encKey, macKey, cleartextData, associatedData);
		byte[] decrypted = bcLightSivMode.decrypt(encKey, macKey, encrypted, associatedData);
		Assertions.assertArrayEquals(cleartextData, decrypted);
		bh.consume(encrypted);
		bh.consume(decrypted);
	}

}
