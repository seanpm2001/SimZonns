package org.opentelecoms.gsm0348.impl.crypto;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opentelecoms.gsm0348.api.Util;

public class SignatureManagerTest {

  @Before
  public void setUp() throws Exception {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  /*
   * See: https://csrc.nist.rip/publications/fips/fips113/fips113.html
   *
   * The text is the ASCII code for "7654321 Now is the time for "
   * https://csrc.nist.rip/publications/fips/fips113/fips113.html text string in Appendix 2 is incorrect!
   */
  @Test
  public void test_fips_113() throws Exception {
    byte[] keyBytes = Hex.decode("0123456789abcdef");
    byte[] input = "7654321 Now is the time for ".getBytes(StandardCharsets.US_ASCII);

    byte[] mac1 = SignatureManager.sign("DES_MAC8_ISO9797_M1", keyBytes, input);

    Assert.assertEquals("f1d30f6849312ca4", Hex.toHexString(mac1));
  }

  @Test
  public void test_fips_113_aligned_on_block() throws Exception {
    byte[] keyBytes = Hex.decode("0123456789abcdef");
    byte[] input = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f722000000000");

    byte[] mac = SignatureManager.sign("DES_MAC8_ISO9797_M1", keyBytes, input);

    Assert.assertEquals("f1d30f6849312ca4", Hex.toHexString(mac));
  }

  @Test
  public void test_bc_des_mac() throws Exception {
    byte[] keyBytes = Hex.decode("0123456789abcdef");
    byte[] input = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f722000000000");

    SecretKey key = new SecretKeySpec(keyBytes, "DES");
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("DESMac", "BC");

    mac.init(key);
    mac.update(input, 0, input.length);
    byte[] out = mac.doFinal();

    Assert.assertEquals("f1d30f68", Hex.toHexString(out));
  }

  @Test
  public void test_bc_des_mac_64() throws Exception {
    byte[] keyBytes = Hex.decode("0123456789abcdef");
    byte[] input = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f722000000000");

    SecretKey key = new SecretKeySpec(keyBytes, "DES");
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("DESMAC64", "BC");

    mac.init(key);
    mac.update(input, 0, input.length);
    byte[] out = mac.doFinal();

    Assert.assertEquals("f1d30f6849312ca4", Hex.toHexString(out));
  }

  @Test
  public void test_bc_des_ede_mac_64() throws Exception {
    byte[] keyBytes = Hex.decode("0123456789abcdef0123456789abcdef");
    byte[] input = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f722000000000");

    SecretKey key = new SecretKeySpec(keyBytes, "DES");
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("DESedeMac64", "BC");

    mac.init(key);
    mac.update(input, 0, input.length);
    byte[] out = mac.doFinal();

    Assert.assertEquals("f1d30f6849312ca4", Hex.toHexString(out));
  }

  @Test
  public void test_gsm0348_des_mac8_iso9797_m1_vs_bc_des_mac_64() throws Exception {
    Random random = new Random();
    byte[] keyBytes = Hex.decode("0123456789abcdef");
    for (int i = 0; i < 512; i++) {
      byte[] input = new byte[i];
      random.nextBytes(input);
      Assert.assertArrayEquals(
          SignatureManager.sign("DESMAC64", keyBytes, input),
          SignatureManager.sign("DES_MAC8_ISO9797_M1", keyBytes, input));
    }
  }

  @Test
  public void test_des_mac_64() throws Exception {
    byte[] keyBytes = Hex.decode("0123456789abcdef");
    byte[] input = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f722000000000");
    Assert.assertEquals("F1D30F6849312CA4",
        Util.toHexString(SignatureManager.sign("DES_MAC8_ISO9797_M1", keyBytes, input)));
  }

  @Test
  public void test_des_ede_2_keys_mac_64() throws Exception {
    byte[] keyBytes = Hex.decode("0123456789abcdef0123456789abcdef");
    byte[] input = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f722000000000");
    Assert.assertEquals("F1D30F6849312CA4",
        Util.toHexString(SignatureManager.sign("DESEDEMAC64", keyBytes, input)));
  }

  @Test
  public void test_des_ede_3_keys_mac_64() throws Exception {
    byte[] keyBytes = Hex.decode("0123456789abcdef0123456789abcdef0123456789abcdef");
    byte[] input = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f722000000000");
    Assert.assertEquals("F1D30F6849312CA4",
        Util.toHexString(SignatureManager.sign("DESEDEMAC64", keyBytes, input)));
  }

  @Test
  public void test_crc16() throws Exception {
    byte[] keyBytes = new byte[]{};
    byte[] input = Hex.decode("0102030405060708");
    Assert.assertEquals("6DD4", Util.toHexString(SignatureManager.sign("CRC16", keyBytes, input)));
  }

  @Test
  public void test_crc32() throws Exception {
    byte[] keyBytes = new byte[]{};
    byte[] input = Hex.decode("0102030405060708");
    Assert.assertEquals("3FCA88C5", Util.toHexString(SignatureManager.sign("CRC32", keyBytes, input)));
  }

  @Test
  public void test_aes_cmac_empty_string() throws Exception {
    byte[] keyBytes = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
    byte[] input = Hex.decode("");
    Assert.assertEquals("BB1D6929", Util.toHexString(SignatureManager.sign("AES_CMAC_32", keyBytes, input)));
    Assert.assertEquals("BB1D6929E9593728", Util.toHexString(SignatureManager.sign("AES_CMAC_64", keyBytes, input)));
  }

  @Test
  public void test_aes_cmac_example_1() throws Exception {
    // https://tools.ietf.org/html/rfc4493
    byte[] keyBytes = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
    byte[] input = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
    Assert.assertEquals("070A16B4", Util.toHexString(SignatureManager.sign("AES_CMAC_32", keyBytes, input)));
    Assert.assertEquals("070A16B46B4D4144", Util.toHexString(SignatureManager.sign("AES_CMAC_64", keyBytes, input)));
  }

  @Test
  public void test_aes_cmac_example_2() throws Exception {
    // https://tools.ietf.org/html/rfc4493
    byte[] keyBytes = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
    byte[] input = Hex.decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
    Assert.assertEquals("DFA66747", Util.toHexString(SignatureManager.sign("AES_CMAC_32", keyBytes, input)));
    Assert.assertEquals("DFA66747DE9AE630", Util.toHexString(SignatureManager.sign("AES_CMAC_64", keyBytes, input)));
  }

  @Test
  public void test_aes_cmac_example_3() throws Exception {
    // https://tools.ietf.org/html/rfc4493
    byte[] keyBytes = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
    byte[] input = Hex.decode("6bc1bee2 2e409f96 e93d7e11 7393172a" +
        "ae2d8a57 1e03ac9c 9eb76fac 45af8e51" +
        "30c81c46 a35ce411 e5fbc119 1a0a52ef" +
        " f69f2445 df4f9b17 ad2b417b e66c3710");
    Assert.assertEquals("51F0BEBF", Util.toHexString(SignatureManager.sign("AES_CMAC_32", keyBytes, input)));
    Assert.assertEquals("51F0BEBF7E3B9D92", Util.toHexString(SignatureManager.sign("AES_CMAC_64", keyBytes, input)));
  }

  @Test
  public void test_xor4() throws Exception {
    byte[] keyBytes = new byte[]{};
    byte[] input = Hex.decode("0102030405060708");
    Assert.assertEquals("0404040C", Util.toHexString(SignatureManager.sign("XOR4", keyBytes, input)));
  }

  @Test
  public void test_xor8() throws Exception {
    byte[] keyBytes = new byte[]{};
    byte[] input = Hex.decode("0102030405060708");
    Assert.assertEquals("0102030405060708", Util.toHexString(SignatureManager.sign("XOR8", keyBytes, input)));
  }

}