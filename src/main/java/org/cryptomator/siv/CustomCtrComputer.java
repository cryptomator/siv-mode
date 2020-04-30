package org.cryptomator.siv;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.function.Supplier;

/**
 * Performs CTR Mode computations facilitating BouncyCastle's {@link SICBlockCipher}.
 */
class CustomCtrComputer implements SivMode.CtrComputer {

	private final Supplier<BlockCipher> blockCipherSupplier;

	public CustomCtrComputer(Supplier<BlockCipher> blockCipherSupplier) {
		this.blockCipherSupplier = blockCipherSupplier;
	}
	
	@Override
	public byte[] computeCtr(byte[] input, byte[] key, byte[] iv) {
		SICBlockCipher cipher = new SICBlockCipher(blockCipherSupplier.get());
		CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
		cipher.init(true, params);
		try {
			byte[] output = new byte[input.length];
			cipher.processBytes(input, 0, input.length, output, 0);
			return output;
		} catch (OutputLengthException e) {
			throw new IllegalStateException("In CTR mode output length must be equal to input length", e);
		}
	}
}
