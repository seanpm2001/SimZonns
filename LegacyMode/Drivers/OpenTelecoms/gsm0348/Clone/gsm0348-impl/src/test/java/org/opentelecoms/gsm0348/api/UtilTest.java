package org.opentelecoms.gsm0348.api;

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;

import org.junit.Assert;
import org.junit.Test;

public class UtilTest {

  @Test
  public void test_to_hex() {
    assertEquals("0xAB", Util.toHex((byte) 0xab));
  }

  @Test
  public void test_to_hex_string() {
    assertEquals("ABCD", Util.toHexString(new byte[]{ (byte) 0xab, (byte) 0xcd }));
    assertEquals("null", Util.toHexString(null));
  }

  @Test
  public void test_to_hex_array() {
    assertEquals("0xAB 0xCD", Util.toHexArray(new byte[]{ (byte) 0xab, (byte) 0xcd }));
  }

  @Test
  public void test_encoded_length_decode() {
    // ETSI TS 101 220
    assertEncodedLength(0, new byte[]{ (byte) 0x00 });
    assertEncodedLength(1, new byte[]{ (byte) 0x01 });
    assertEncodedLength(127, new byte[]{ (byte) 0x7f });
    assertEncodedLength(128, new byte[]{ (byte) 0x81, (byte) 0x80 });
    assertEncodedLength(255, new byte[]{ (byte) 0x81, (byte) 0xff });
    assertEncodedLength(256, new byte[]{ (byte) 0x82, (byte) 0x01, (byte) 0x00 });
    assertEncodedLength(65535, new byte[]{ (byte) 0x82, (byte) 0xff, (byte) 0xff });
    assertEncodedLength(65536, new byte[]{ (byte) 0x83, (byte) 0x01, (byte) 0x00, (byte) 0x00 });
    assertEncodedLength(16777215, new byte[]{ (byte) 0x83, (byte) 0xff, (byte) 0xff, (byte) 0xff });
  }

  @Test(expected = IllegalArgumentException.class)
  public void test_encoded_length_decode_exception() {
    // ETSI TS 101 220
    Util.getEncodedLength(ByteBuffer.wrap(new byte[]{ (byte) 0x84, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00 }));
  }

  @Test
  public void test_encoded_length_bytes_decode() {
    // ETSI TS 101 220
    assertEncodedLengthBytes(new byte[]{ (byte) 0x00 }, new byte[]{ (byte) 0x00, (byte) 0xff });
    assertEncodedLengthBytes(new byte[]{ (byte) 0x01 }, new byte[]{ (byte) 0x01, (byte) 0xff });
    assertEncodedLengthBytes(new byte[]{ (byte) 0x7f }, new byte[]{ (byte) 0x7f, (byte) 0xff });
    assertEncodedLengthBytes(new byte[]{ (byte) 0x81, (byte) 0x80 }, new byte[]{ (byte) 0x81, (byte) 0x80, (byte) 0xff });
    assertEncodedLengthBytes(new byte[]{ (byte) 0x81, (byte) 0xff }, new byte[]{ (byte) 0x81, (byte) 0xff, (byte) 0xff });
    assertEncodedLengthBytes(new byte[]{ (byte) 0x82, (byte) 0x01, (byte) 0x00 }, new byte[]{ (byte) 0x82, (byte) 0x01, (byte) 0x00, (byte) 0xff });
    assertEncodedLengthBytes(new byte[]{ (byte) 0x82, (byte) 0xff, (byte) 0xff }, new byte[]{ (byte) 0x82, (byte) 0xff, (byte) 0xff, (byte) 0xff });
    assertEncodedLengthBytes(new byte[]{ (byte) 0x83, (byte) 0x01, (byte) 0x00, (byte) 0x00 },
        new byte[]{ (byte) 0x83, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0xff });
    assertEncodedLengthBytes(new byte[]{ (byte) 0x83, (byte) 0xff, (byte) 0xff, (byte) 0xff },
        new byte[]{ (byte) 0x83, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff });
  }

  private void assertEncodedLength(final int expected, final byte[] bytes) {
    Assert.assertEquals(expected, Util.getEncodedLength(ByteBuffer.wrap(bytes)));
  }

  private void assertEncodedLengthBytes(final byte[] expected, final byte[] bytes) {
    byte[] lengthBytes = Util.getEncodedLengthBytes(ByteBuffer.wrap(bytes));
    Assert.assertArrayEquals(expected, lengthBytes);
  }

  @Test
  public void test_ber_length_decode() {
    // ETSI TS 101 220
    assertEncodedLength(0, new byte[]{ (byte) 0x00 });
    assertEncodedLength(1, new byte[]{ (byte) 0x01 });
    assertEncodedLength(127, new byte[]{ (byte) 0x7f });
    assertEncodedLength(128, new byte[]{ (byte) 0x81, (byte) 0x80, });
    assertEncodedLength(255, new byte[]{ (byte) 0x81, (byte) 0xff, });
    assertEncodedLength(256, new byte[]{ (byte) 0x82, (byte) 0x01, (byte) 0x00 });
    assertEncodedLength(65535, new byte[]{ (byte) 0x82, (byte) 0xff, (byte) 0xff });
    assertEncodedLength(65536, new byte[]{ (byte) 0x83, (byte) 0x01, (byte) 0x00, (byte) 0x00 });
    assertEncodedLength(16777215, new byte[]{ (byte) 0x83, (byte) 0xff, (byte) 0xff, (byte) 0xff });
  }

  @Test
  public void test_length_decode() {
    // ETSI TS 101 220
    assertEquals(0, Util.decodeLength(new byte[]{ (byte) 0x00 }));
    assertEquals(1, Util.decodeLength(new byte[]{ (byte) 0x01 }));
    assertEquals(127, Util.decodeLength(new byte[]{ (byte) 0x7f }));
    assertEquals(128, Util.decodeLength(new byte[]{ (byte) 0x81, (byte) 0x80 }));
    assertEquals(129, Util.decodeLength(new byte[]{ (byte) 0x81, (byte) 0x81 }));
    assertEquals(255, Util.decodeLength(new byte[]{ (byte) 0x81, (byte) 0xff, }));
    assertEquals(256, Util.decodeLength(new byte[]{ (byte) 0x82, (byte) 0x01, (byte) 0x00 }));
    assertEquals(65535, Util.decodeLength(new byte[]{ (byte) 0x82, (byte) 0xff, (byte) 0xff }));
    assertEquals(65536, Util.decodeLength(new byte[]{ (byte) 0x83, (byte) 0x01, (byte) 0x00, (byte) 0x00 }));
    assertEquals(16777215, Util.decodeLength(new byte[]{ (byte) 0x83, (byte) 0xff, (byte) 0xff, (byte) 0xff }));
  }

  @Test(expected = IllegalArgumentException.class)
  public void test_length_decode_invalid() {
    // ETSI TS 101 220
    assertEquals(0, Util.decodeLength(new byte[]{ (byte) 0x85 }));
  }

}
