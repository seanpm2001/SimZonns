package org.opentelecoms.gsm0348.impl.crypto.mac;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class CRC16X25Test {

  // ETSI 102 225
  // If an input message is '01 02 03 04 05' where '01' is the first byte and '05' the last byte used for the
  // computation, then the result of CRC 16 computation applied to the input message is '22 EC', where
  // '22' would represent the first byte and 'EC' the last byte of the RC/CC/DS field.

  @Test
  public void test_crc16_x25() throws Exception {
    CRC16X25 crc16X25 = new CRC16X25();
    crc16X25.init(null);
    final byte[] data = new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05 };
    crc16X25.update(data, 0, data.length);
    final byte[] crc = new byte[2];
    final int bytesCopied = crc16X25.doFinal(crc, 0);
    assertEquals(2, bytesCopied);
    assertArrayEquals(new byte[]{ (byte) 0x22, (byte) 0xEC }, crc);
  }
}