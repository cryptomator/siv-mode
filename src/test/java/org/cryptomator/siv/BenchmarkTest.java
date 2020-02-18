/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 * 
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 ******************************************************************************/
package org.cryptomator.siv;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnJre;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

public class BenchmarkTest {

	@Test
	public void runBenchmarks() throws RunnerException {
		// Taken from http://stackoverflow.com/a/30486197/4014509:
		Options opt = new OptionsBuilder()
				// Specify which benchmarks to run
				.include(getClass().getPackage().getName() + ".*Benchmark.*")
				// Set the following options as needed
				.threads(2).forks(2) //
				.shouldFailOnError(true).shouldDoGC(true)
				// .jvmArgs("-XX:+UnlockDiagnosticVMOptions", "-XX:+PrintInlining")
				// .addProfiler(WinPerfAsmProfiler.class)
				.build();
		new Runner(opt).run();
	}

}
