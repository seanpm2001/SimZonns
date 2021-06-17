package org.opentelecoms.gsm0348.impl.crypto.mac;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

public class XOR8Test {
  private XOR8 xor8 = new XOR8();

  @Before
  public void setUp() throws Exception {
    xor8.init(null);
  }

  @Test
  public void test_xor8_1_byte() throws Exception {
    xor8.update((byte) 0xab);
    final byte[] output = new byte[8];
    final int bytesCopied = xor8.doFinal(output, 0);
    assertEquals(8, bytesCopied);
    assertArrayEquals(new byte[]{ (byte) 0xab, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }, output);
  }

  @Test
  public void test_xor8_8_bytes() throws Exception {
    final byte[] data = new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08 };
    xor8.update(data, 0, data.length);
    final byte[] output = new byte[8];
    final int bytesCopied = xor8.doFinal(output, 0);
    assertEquals(8, bytesCopied);
    assertArrayEquals(new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08 }, output);
  }

  @Test
  public void test_xor8_16_bytes() throws Exception {
    final byte[] data = new byte[]{
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
        (byte) 0x80, (byte) 0x90, (byte) 0xa0, (byte) 0xb0, (byte) 0xc0, (byte) 0xd0, (byte) 0xe0, (byte) 0xf0 };
    xor8.update(data, 0, data.length);
    final byte[] output = new byte[8];
    final int bytesCopied = xor8.doFinal(output, 0);
    assertEquals(8, bytesCopied);
    assertArrayEquals(new byte[]{ (byte) 0x81, (byte) 0x92, (byte) 0xa3, (byte) 0xb4, (byte) 0xc5, (byte) 0xd6, (byte) 0xe7, (byte) 0xf8 }, output);
  }

}