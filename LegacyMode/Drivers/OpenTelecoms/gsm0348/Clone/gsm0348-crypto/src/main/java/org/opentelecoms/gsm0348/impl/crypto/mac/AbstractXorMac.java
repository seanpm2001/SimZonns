package org.opentelecoms.gsm0348.impl.crypto.mac;

import org.opentelecoms.gsm0348.impl.crypto.CipherParameters;
import org.opentelecoms.gsm0348.impl.crypto.Mac;


public abstract class AbstractXorMac implements Mac {

  protected final int width;
  private final String algorithmName;
  protected int position;
  private long result;

  public AbstractXorMac(final String algorithmName, final int width) {
    this.algorithmName = algorithmName;
    this.width = width;
  }

  @Override
  public void init(final CipherParameters paramCipherParameters) throws IllegalArgumentException {
    position = 0;
    result = 0;
  }

  @Override
  public String getAlgorithmName() {
    return algorithmName;
  }

  @Override
  public int getMacSize() {
    return width;
  }

  @Override
  public void update(final byte input) throws IllegalStateException {
    result ^= getXor(input);
  }

  @Override
  public void update(final byte[] input, final int offset, final int length) throws IllegalStateException {
    for (int i = offset; i < offset + length; i++) {
      result ^= getXor(input[i]);
    }
  }

  @Override
  public int doFinal(final byte[] output, final int offset) throws IllegalStateException {
    byte[] xor = longToByteArray(result);
    System.arraycopy(xor, 8 - width, output, offset, width);
    return width;
  }

  @Override
  public void reset() {
    position = 0;
    result = 0;
  }

  private byte[] longToByteArray(long value) {
    return new byte[]{
        (byte) (value >>> 56),
        (byte) (value >>> 48),
        (byte) (value >>> 40),
        (byte) (value >>> 32),
        (byte) (value >>> 24),
        (byte) (value >>> 16),
        (byte) (value >>> 8),
        (byte) value };
  }

  private long getXor(byte input) {
    switch (width - 1 - (position++ % width)) {
      case 7:
        return ((long) (input & 0xff)) << 56;
      case 6:
        return ((long) (input & 0xff)) << 48;
      case 5:
        return ((long) (input & 0xff)) << 40;
      case 4:
        return ((long) (input & 0xff)) << 32;
      case 3:
        return ((long) (input & 0xff)) << 24;
      case 2:
        return ((long) (input & 0xff)) << 16;
      case 1:
        return ((long) (input & 0xff)) << 8;
      case 0:
        return (input & 0xff);
      default:
        throw new IllegalStateException("Should never happen");
    }
  }
}
