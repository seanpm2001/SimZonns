package org.opentelecoms.gsm0348.impl.coders;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;
import org.opentelecoms.gsm0348.api.model.AlgorithmImplementation;
import org.opentelecoms.gsm0348.api.model.CipheringAlgorithmMode;
import org.opentelecoms.gsm0348.api.model.KIC;

public class KICCoderTest {

  @Test
  public void test_kic_00() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x00);
    assertEquals(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES, kic.getAlgorithmImplementation());
    assertNull(kic.getCipheringAlgorithmMode());
    assertEquals(0, kic.getKeysetID());
    assertEquals((byte)0x00, KICCoder.decode(kic));
  }

  @Test
  public void test_kic_10() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x10);
    assertEquals(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES, kic.getAlgorithmImplementation());
    assertNull(kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
    assertEquals((byte)0x10, KICCoder.decode(kic));
  }

  @Test
  public void test_kic_11() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x11);
    assertEquals(AlgorithmImplementation.DES, kic.getAlgorithmImplementation());
    assertEquals(CipheringAlgorithmMode.DES_CBC, kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
    assertEquals((byte)0x11, KICCoder.decode(kic));
  }

  @Test
  public void test_kic_12() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x12);
    assertEquals(AlgorithmImplementation.AES, kic.getAlgorithmImplementation());
    assertEquals(CipheringAlgorithmMode.AES_CBC, kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
    assertEquals((byte)0x12, KICCoder.decode(kic));
  }

  @Test
  public void test_kic_13() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x13);
    assertEquals(AlgorithmImplementation.PROPRIETARY_IMPLEMENTATIONS, kic.getAlgorithmImplementation());
    assertNull(kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
    assertEquals((byte)0x13, KICCoder.decode(kic));
  }

  @Test
  public void test_kic_15() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x15);
    assertEquals(AlgorithmImplementation.DES, kic.getAlgorithmImplementation());
    assertEquals(CipheringAlgorithmMode.TRIPLE_DES_CBC_2_KEYS, kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
    assertEquals((byte)0x15, KICCoder.decode(kic));
  }

  @Test
  public void test_kic_18() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x18);
    assertEquals(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES, kic.getAlgorithmImplementation());
    assertNull(kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
    assertEquals((byte)0x10, KICCoder.decode(kic));
  }

  @Test
  public void test_kic_19() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x19);
    assertEquals(AlgorithmImplementation.DES, kic.getAlgorithmImplementation());
    assertEquals(CipheringAlgorithmMode.TRIPLE_DES_CBC_3_KEYS, kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
    assertEquals((byte)0x19, KICCoder.decode(kic));
  }

  @Test
  public void test_kic_1d() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x1d);
    assertEquals(AlgorithmImplementation.DES, kic.getAlgorithmImplementation());
    assertEquals(CipheringAlgorithmMode.DES_ECB, kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
    assertEquals((byte)0x1d, KICCoder.decode(kic));
  }

  @Test
  public void test_kic_32() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x32);
    assertEquals(AlgorithmImplementation.AES, kic.getAlgorithmImplementation());
    assertEquals(CipheringAlgorithmMode.AES_CBC, kic.getCipheringAlgorithmMode());
    assertEquals(3, kic.getKeysetID());
    assertEquals((byte)0x32, KICCoder.decode(kic));
  }

  @Test
  public void test_kic_33() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x33);
    assertEquals(AlgorithmImplementation.PROPRIETARY_IMPLEMENTATIONS, kic.getAlgorithmImplementation());
    assertNull(kic.getCipheringAlgorithmMode());
    assertEquals(3, kic.getKeysetID());
    assertEquals((byte)0x33, KICCoder.decode(kic));
  }

  @Test
  public void test_kic_ff() throws Exception {
    KIC kic = KICCoder.encode((byte) 0xff);
    assertEquals(AlgorithmImplementation.PROPRIETARY_IMPLEMENTATIONS, kic.getAlgorithmImplementation());
    assertNull(kic.getCipheringAlgorithmMode());
    assertEquals(15, kic.getKeysetID());
    assertEquals((byte)0xf3, KICCoder.decode(kic));
  }
}