package org.opentelecoms.gsm0348.impl.crypto.mac;

import com.github.snksoft.crc.CRC;

public class CRC16X25 extends AbstractCrcMac {

  // CRC algorithm is specified in ISO 13239.
  // The generator polynomial used for CRC 16 shall be X^16 + X^12 + X^5 + 1.
  // The least significant bit of the first byte to be included in the checksum shall represent the most significant term of the input polynomial.
  // The initial value of the register shall be 'FFFF' for CRC 16.
  // The CRC result is obtained after an XOR operation of the final register value with 'FFFF' for CRC 16.
  //
  // See http://www.sunshine2k.de/coding/javascript/crc/crc_js.html

  public CRC16X25() {
    super("CRC16-X25", new CRC.Parameters(16, 4129L, 65535L, true, true, 0xFFFFFFFFL));
  }

}