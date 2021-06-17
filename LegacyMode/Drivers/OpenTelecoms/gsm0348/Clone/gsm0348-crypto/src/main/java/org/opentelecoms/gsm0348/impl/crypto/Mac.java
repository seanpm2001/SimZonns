package org.opentelecoms.gsm0348.impl.crypto;

public interface Mac
{
	void init(CipherParameters cipherParameters) throws IllegalArgumentException;

	String getAlgorithmName();

	int getMacSize();

	void update(byte input) throws IllegalStateException;

	void update(byte[] input, int offset, int length) throws IllegalStateException;

	int doFinal(byte[] output, int offset) throws IllegalStateException;

	void reset();
}
