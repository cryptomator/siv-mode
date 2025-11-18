package org.cryptomator.siv;

import org.junit.jupiter.api.Assertions;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * Needs to be compiled via maven as the JMH annotation processor needs to do stuff...
 */
@State(Scope.Thread)
@Warmup(iterations = 3, time = 300, timeUnit = TimeUnit.MILLISECONDS)
@Measurement(iterations = 2, time = 500, timeUnit = TimeUnit.MILLISECONDS)
@BenchmarkMode(value = {Mode.AverageTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class SivModeBenchmark {

	private int run;
	private final byte[] key = new byte[32];
	@Param({"1024", "1048576", "10485760"})
	private int cleartextDataSize;
	private byte[] cleartextData;
	private final byte[] associatedData = new byte[100];

	private SivEngine siv;

	@Setup(Level.Trial)
	public void shuffleData() {
		run++;
		Arrays.fill(key, (byte) (run & 0xFF));
		siv = new SivEngine(key);
		cleartextData = new byte[cleartextDataSize];
		Arrays.fill(cleartextData, (byte) (run & 0xFF));
		Arrays.fill(associatedData, (byte) (run & 0xFF));
	}

	@Benchmark
	public void benchmarkJce(Blackhole bh) throws AEADBadTagException, IllegalBlockSizeException {
		byte[] encrypted = siv.encrypt(cleartextData, associatedData);
		byte[] decrypted = siv.decrypt(encrypted, associatedData);
		Assertions.assertArrayEquals(cleartextData, decrypted);
		bh.consume(encrypted);
		bh.consume(decrypted);
	}

}
