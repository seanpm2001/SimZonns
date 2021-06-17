package org.opentelecoms.gsm0348.impl;

import org.junit.Assert;
import org.junit.Test;

public class ICCIDKeyGeneratorTest {

  private byte[] masterKey = new byte[]{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

  @Test
  public void test_get_key_without_luhn() throws Exception {

    final String iccid = "8900000000000000001";

    final byte[] key = ICCIDKeyGenerator.getKey(masterKey, iccid);

    Assert.assertArrayEquals(new byte[]{ (byte) 0x76, (byte) 0x07, (byte) 0xeb, (byte) 0x06, (byte) 0x2d, (byte) 0x25, (byte) 0x04, (byte) 0x31 }, key);
  }

  @Test
  public void test_get_key_with_luhn() throws Exception {

    final String iccid = "89000000000000000012";

    final byte[] key = ICCIDKeyGenerator.getKey(masterKey, iccid);

    Assert.assertArrayEquals(new byte[]{ (byte) 0x76, (byte) 0x07, (byte) 0xeb, (byte) 0x06, (byte) 0x2d, (byte) 0x25, (byte) 0x04, (byte) 0x31 }, key);
  }

}