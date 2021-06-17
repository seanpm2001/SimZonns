package org.opentelecoms.gsm0348.impl.crypto.params;

import org.opentelecoms.gsm0348.impl.crypto.CipherParameters;

public class KeyParameter implements CipherParameters {

  private byte[] key;

  public KeyParameter(byte[] input) {
    this(input, 0, input.length);
  }

  public KeyParameter(byte[] input, int inputOffset, int inputLen) {
    this.key = new byte[inputLen];
    System.arraycopy(input, inputOffset, this.key, 0, inputLen);
  }

  public byte[] getKey() {
    return this.key;
  }
}
