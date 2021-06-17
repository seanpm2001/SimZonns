package org.opentelecoms.gsm0348.impl.crypto.mac;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Ignore;
import org.junit.Test;

import com.github.snksoft.crc.CRC;

public class CRC32Test {

  // ETSI 102 225
  // If an input message is '01 02 03 04 05' where '01' is the first byte and '05' the last byte used for the
  // computation, then the result of CRC 32 computation applied to the input message is
  // '47 0B 99 F4', where '47' would represent the first byte and 'F4' the last byte of the RC/CC/DS field.

  @Test
  public void test_crc32() throws Exception {
    CRC32 crc32 = new CRC32();
    crc32.init(null);
    final byte[] data = new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05 };
    crc32.update(data, 0, data.length);
    final byte[] crc = new byte[4];
    final int bytesCopied = crc32.doFinal(crc, 0);
    assertEquals(4, bytesCopied);
    assertArrayEquals(new byte[]{ (byte) 0x47, (byte) 0x0b, (byte) 0x99, (byte) 0xf4 }, crc);
  }

  @Test
  public void test_crc32_c() throws Exception {
    CRC crc = new CRC(CRC.Parameters.CRC32);
    final byte[] data = new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05 };
    final long l = crc.calculateCRC(data);
    // CRC is 0x470B99F4"
    assertEquals(1191942644, l);
  }

  @Test
  public void test_crc32_table() throws Exception {
    final byte[] data = new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05 };
    final long l = CRC.calculateCRC(CRC.Parameters.CRC32, data);
    // CRC is 0x470B99F4"
    assertEquals(1191942644, l);
  }

  @Test
  public void create_table() throws Exception {
    final MyCRC.Parameters crcParams = new MyCRC.Parameters(16, 4129L, 65535L, true, true, 0xFFFFFFFFL);

    long initValue = (crcParams.isReflectIn()) ? MyCRC.reflect(crcParams.getInit(), crcParams.getWidth()) : crcParams.getInit();
    long mask = ((crcParams.getWidth() >= 64) ? 0 : (1L << crcParams.getWidth())) - 1;
    long[] crctable = new long[256];

    byte[] tmp = new byte[1];

    MyCRC.Parameters tableParams = new MyCRC.Parameters(crcParams);

    tableParams.setInit(0);
    tableParams.setReflectOut(tableParams.isReflectIn());
    tableParams.setFinalXor(0);
    for (int i = 0; i < 256; i++) {
      tmp[0] = (byte) i;
      crctable[i] = MyCRC.calculateCRC(tableParams, tmp);
    }
    System.out.println("private final static int[] TABLE = {");
    for (int i = 0; i < 256; i++) {
      System.out.print(String.format("0x%04x", crctable[i]));
      if (i < 255) {
        System.out.print(", ");
      } else {
        System.out.print(" }");
      }
      if (i % 8 == 7) {
        System.out.println("");
      }
    }
  }

  @Ignore
  @Test
  public void create_table_2() throws Exception {
    final CRC.Parameters crcParams = new CRC.Parameters(16, 4129L, 0, true, true, 0);

    long initValue = (crcParams.isReflectIn()) ? MyCRC.reflect(crcParams.getInit(), crcParams.getWidth()) : crcParams.getInit();
    long mask = ((crcParams.getWidth() >= 64) ? 0 : (1L << crcParams.getWidth())) - 1;
    long[] crctable = new long[256];

    byte[] tmp = new byte[1];

    // CRC.Parameters tableParams = new CRC.Parameters(crcParams);
    CRC.Parameters tableParams = crcParams;

//    tableParams.setInit(0);
//    tableParams.setReflectOut(tableParams.isReflectIn());
//    tableParams.setFinalXor(0);
    for (int i = 0; i < 256; i++) {
      tmp[0] = (byte) i;
      crctable[i] = CRC.calculateCRC(tableParams, tmp);
    }
    System.out.println("private final static int[] TABLE = {");
    for (int i = 0; i < 256; i++) {
      System.out.print(String.format("0x%04x", crctable[i]));
      if (i < 255) {
        System.out.print(", ");
      } else {
        System.out.print(" }");
      }
      if (i % 8 == 7) {
        System.out.println("");
      }
    }
  }
}