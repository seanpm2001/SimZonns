package org.opentelecoms.gsm0348.impl.crypto.mac;

import com.github.snksoft.crc.CRC;

public class CRC32 extends AbstractCrcMac {

  // CRC algorithm is specified in ISO 13239.
  // The generator polynomial used for CRC 32 shall be X^32 + X^26 + X^23 + X^22 + X^16 + X^12 + X^11 + X^10 + X^8 + X^7 + X^5 + X^4 + X^2 + X + 1.
  // The least significant bit of the first byte to be included in the checksum shall represent the most significant term of the input polynomial.
  // The initial value of the register shall be 'FFFFFFFF' for CRC 32.
  // The CRC result is obtained after an XOR operation of the final register value with 'FFFFFFFF' for CRC 32.
  //
  // See http://www.sunshine2k.de/coding/javascript/crc/crc_js.html

  // public CRC32() {
  //  super("CRC32", new CRC.Parameters(32, 0x4C11DB7, 0xFFFFFFFFL, true, true, 0xFFFFFFFFL));
  //}
  public CRC32() {
    super("CRC32", CRC.Parameters.CRC32);
  }

}