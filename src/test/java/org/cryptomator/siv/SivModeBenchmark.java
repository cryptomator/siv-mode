/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 * 
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 ******************************************************************************/
package org.cryptomator.siv;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.cryptomator.siv.SivMode.BlockCipherFactory;
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

/**
 * Needs to be compiled via maven as the JMH annotation processor needs to do stuff...
 */
@State(Scope.Thread)
@Warmup(iterations = 2, time = 500, timeUnit = TimeUnit.MILLISECONDS)
@Measurement(iterations = 2, time = 500, timeUnit = TimeUnit.MILLISECONDS)
@BenchmarkMode(value = {Mode.AverageTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class SivModeBenchmark {

	private int run;
	private final byte[] encKeyBuf = new byte[16];
	private final byte[] macKeyBuf = new byte[16];
	private final byte[] testData = new byte[8 * 1024];
	private final byte[] adData = new byte[1024];

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
		Arrays.fill(encKeyBuf, (byte) (run & 0xFF));
		Arrays.fill(macKeyBuf, (byte) (run & 0xFF));
		Arrays.fill(testData, (byte) (run & 0xFF));
		Arrays.fill(adData, (byte) (run & 0xFF));
	}

	@Benchmark
	public void benchmarkJce() {
		jceSivMode.encrypt(encKeyBuf, macKeyBuf, testData, adData);
	}

	@Benchmark
	public void benchmarkBcFast() {
		bcFastSivMode.encrypt(encKeyBuf, macKeyBuf, testData, adData);
	}

	@Benchmark
	public void benchmarkBcLight() {
		bcLightSivMode.encrypt(encKeyBuf, macKeyBuf, testData, adData);
	}

}
