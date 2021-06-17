package org.opentelecoms.gsm0348.impl.coders;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;
import org.opentelecoms.gsm0348.api.model.AlgorithmImplementation;
import org.opentelecoms.gsm0348.api.model.CertificationAlgorithmMode;
import org.opentelecoms.gsm0348.api.model.CertificationMode;
import org.opentelecoms.gsm0348.api.model.KID;

public class KIDCoderTest {

  @Test
  public void test_kid_no_security() throws Exception {
    for (int i = 0; i < 256; i++) {
      final KID kid = KIDCoder.encode(CertificationMode.NO_SECURITY, (byte) (i & 0xff));
      assertNull(kid.getAlgorithmImplementation());
      assertNull(kid.getCertificationAlgorithmMode());
      assertEquals((byte) ((i & 0xf0) >>> 4), kid.getKeysetID());
    }
  }

  @Test
  public void test_kid_cc_00() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x00);
    assertEquals(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES, kid.getAlgorithmImplementation());
    assertNull(kid.getCertificationAlgorithmMode());
    assertEquals((byte) 0, kid.getKeysetID());
    assertEquals((byte) 0x00, KIDCoder.decode(kid));
  }

  @Test
  public void test_kid_cc_01() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x01);
    assertEquals(AlgorithmImplementation.DES, kid.getAlgorithmImplementation());
    assertEquals(CertificationAlgorithmMode.DES_CBC, kid.getCertificationAlgorithmMode());
    assertEquals(0, kid.getKeysetID());
    assertEquals((byte) 0x01, KIDCoder.decode(kid));
  }

  @Test
  public void test_kid_cc_02() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x02);
    assertEquals(AlgorithmImplementation.AES, kid.getAlgorithmImplementation());
    assertEquals(CertificationAlgorithmMode.AES_CMAC, kid.getCertificationAlgorithmMode());
    assertEquals(0, kid.getKeysetID());
    assertEquals((byte) 0x02, KIDCoder.decode(kid));
  }

  @Test
  public void test_kid_cc_03() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x03);
    assertEquals(AlgorithmImplementation.PROPRIETARY_IMPLEMENTATIONS, kid.getAlgorithmImplementation());
    assertNull(kid.getCertificationAlgorithmMode());
    assertEquals(0, kid.getKeysetID());
    assertEquals((byte) 0x03, KIDCoder.decode(kid));
  }

  @Test
  public void test_kid_cc_05() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x05);
    assertEquals(AlgorithmImplementation.DES, kid.getAlgorithmImplementation());
    assertEquals(CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS, kid.getCertificationAlgorithmMode());
    assertEquals(0, kid.getKeysetID());
    assertEquals((byte) 0x05, KIDCoder.decode(kid));
  }

  @Test
  public void test_kid_cc_32() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.CC, (byte) 0x32);
    assertEquals(AlgorithmImplementation.AES, kid.getAlgorithmImplementation());
    assertEquals(CertificationAlgorithmMode.AES_CMAC, kid.getCertificationAlgorithmMode());
    assertEquals(3, kid.getKeysetID());
    assertEquals((byte) 0x32, KIDCoder.decode(kid));
  }

  @Test
  public void test_kid_no_security_32() throws Exception {
    final KID kid = KIDCoder.encode(CertificationMode.NO_SECURITY, (byte) 0x32);
    assertNull(kid.getAlgorithmImplementation());
    assertNull(kid.getCertificationAlgorithmMode());
    assertEquals(3, kid.getKeysetID());
    assertEquals((byte) 0x30, KIDCoder.decode(kid));
  }
}