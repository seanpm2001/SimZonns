package org.opentelecoms.gsm0348.impl.crypto;

import org.junit.Assert;
import org.junit.Test;

public class CipheringManagerTest {

  @Test
  public void check_block_alignment() {
    Assert.assertEquals(0, CipheringManager.aligned(0, 8));
    Assert.assertEquals(8, CipheringManager.aligned(1, 8));
    Assert.assertEquals(8, CipheringManager.aligned(2, 8));
    Assert.assertEquals(8, CipheringManager.aligned(3, 8));
    Assert.assertEquals(8, CipheringManager.aligned(4, 8));
    Assert.assertEquals(8, CipheringManager.aligned(5, 8));
    Assert.assertEquals(8, CipheringManager.aligned(6, 8));
    Assert.assertEquals(8, CipheringManager.aligned(7, 8));
    Assert.assertEquals(8, CipheringManager.aligned(8, 8));
    Assert.assertEquals(16, CipheringManager.aligned(9, 8));
    Assert.assertEquals(16, CipheringManager.aligned(10, 8));
    Assert.assertEquals(16, CipheringManager.aligned(14, 8));
    Assert.assertEquals(16, CipheringManager.aligned(15, 8));
    Assert.assertEquals(16, CipheringManager.aligned(16, 8));
    Assert.assertEquals(24, CipheringManager.aligned(17, 8));
    Assert.assertEquals(24, CipheringManager.aligned(23, 8));
    Assert.assertEquals(24, CipheringManager.aligned(24, 8));
  }

}