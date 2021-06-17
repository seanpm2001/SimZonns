package org.opentelecoms.gsm0348.impl.crypto.mac;

import org.opentelecoms.gsm0348.impl.crypto.CipherParameters;
import org.opentelecoms.gsm0348.impl.crypto.Mac;

import com.github.snksoft.crc.CRC;

/*
 * See also http://www.sunshine2k.de/coding/javascript/crc/crc_js.html for testing
 */

public abstract class AbstractCrcMac implements Mac {

  private final String algorithmName;
  private final CRC.Parameters crcParameters;
  private final int width;
  private CRC crc;
  private long value;

  AbstractCrcMac(String algorithmName, CRC.Parameters crcParameters) {
    this.algorithmName = algorithmName;
    this.crcParameters = crcParameters;
    this.width = crcParameters.getWidth() / 8;
  }

  public void init(CipherParameters cipheringParams) throws IllegalArgumentException {
    crc = new CRC(crcParameters);
    value = crcParameters.getInit();
  }

  public String getAlgorithmName() {
    return algorithmName;
  }

  public int getMacSize() {
    return width;
  }

  public void update(byte input) throws IllegalStateException {
    value = crc.update(value, new byte[]{ input });
  }

  public void update(byte[] input, int inputOffset, int inputLen) throws IllegalStateException {
    value = crc.update(value, input, inputOffset, inputLen);
  }

  public int doFinal(byte[] output, int outputOffset) throws IllegalStateException {
    long finalValue = crc.finalCRC(value);
    byte[] result = valueAsBytes(finalValue, width);
    System.arraycopy(result, 0, output, outputOffset, width);
    return width;
  }

  public void reset() {
    value = crc.init();
  }

  private byte[] valueAsBytes(long value, int width) {
    byte[] result = new byte[width];
    for (int i = width; i > 0; i--) {
      result[i - 1] = (byte) (value & 0xff);
      value >>= 8;
    }
    return result;
  }
}
