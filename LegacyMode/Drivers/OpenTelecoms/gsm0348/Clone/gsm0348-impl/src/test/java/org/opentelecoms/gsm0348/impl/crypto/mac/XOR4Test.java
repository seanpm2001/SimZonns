package org.opentelecoms.gsm0348.impl.crypto.mac;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

public class XOR4Test {

  private XOR4 xor4 = new XOR4();

  @Before
  public void setUp() throws Exception {
    xor4.init(null);
  }

  @Test
  public void test_xor4_single_byte() throws Exception {
    xor4.update((byte) 0xab);
    final byte[] output = new byte[4];
    final int bytesCopied = xor4.doFinal(output, 0);
    assertEquals(4, bytesCopied);
    assertArrayEquals(new byte[]{ (byte) 0xab, (byte) 0x00, (byte) 0x00, (byte) 0x00 }, output);
  }

  @Test
  public void test_xor4_4_bytes() throws Exception {
    final byte[] data = new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04 };
    xor4.update(data, 0, data.length);
    final byte[] output = new byte[4];
    final int bytesCopied = xor4.doFinal(output, 0);
    assertEquals(4, bytesCopied);
    assertArrayEquals(new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04 }, output);
  }

  @Test
  public void test_xor4_8_bytes() throws Exception {
    final byte[] data = new byte[]{
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
        (byte) 0x50, (byte) 0x60, (byte) 0x70, (byte) 0x80 };
    xor4.update(data, 0, data.length);
    final byte[] output = new byte[4];
    final int bytesCopied = xor4.doFinal(output, 0);
    assertEquals(4, bytesCopied);
    assertArrayEquals(new byte[]{ (byte) 0x51, (byte) 0x62, (byte) 0x73, (byte) 0x84 }, output);
  }
}