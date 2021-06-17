package org.opentelecoms.gsm0348.impl;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.opentelecoms.gsm0348.api.Util;
import org.opentelecoms.gsm0348.impl.crypto.CipheringManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ICCIDKeyGenerator {

  private static final Logger LOGGER = LoggerFactory.getLogger(ICCIDKeyGenerator.class);

  private static final int ICCID_LENGTH = 20;
  private static final int ICCID_LENGTH_WITHOUT_LUHN = 19;
  private static final String TRANSFORMATION = "DES/ECB/NoPadding";

  /**
   * Generates ciphering key from master key and ICCID. It is computed by using DES ECB with key=master key and data=last 8 bytes of ICCID. If ICCID provided
   * without Luhn (19 chars) then Luhn is computed and added. ICCID`s checksum is checked.
   *
   * @param masterKey - master key. Must be 8 bytes length.
   * @param iccid     - ICCID with (20 chars) or without LUHN (19 chars).
   * @return 8-bytes length key
   * @throws IllegalArgumentException if ICCID is null or empty
   * @throws IllegalArgumentException if ICCID length not equals 19 or 20
   * @throws IllegalArgumentException if ICCID has bad checksum (Luhn digit)
   * @throws GeneralSecurityException in case of unexpected cryptographic problems
   */
  public static byte[] getKey(byte[] masterKey, String iccid) throws GeneralSecurityException {
    if (iccid == null || iccid.isEmpty()) {
      throw new IllegalArgumentException("ICCID cannot be null or empty");
    }
    if (iccid.length() != ICCID_LENGTH && iccid.length() != ICCID_LENGTH_WITHOUT_LUHN) {
      throw new IllegalArgumentException("ICCID length must be ether " + ICCID_LENGTH + " or " + ICCID_LENGTH_WITHOUT_LUHN
          + ". ICCID=" + iccid + " length=" + iccid.length());
    }

    LOGGER.debug("Generating ciphering key. Master key = {}, ICCID = {}", Util.toHexArray(masterKey), iccid);
    if (iccid.length() == ICCID_LENGTH_WITHOUT_LUHN) {
      iccid = addLuhn(iccid);
      LOGGER.debug("New ICCID with Luhn number: {}", iccid);
    }
    if (!verifyLuhnChecksum(iccid)) {
      throw new IllegalArgumentException("ICCID does not pass Luhn check");
    }

    byte[] byteIccid = new byte[iccid.length() / 2];

    for (int i = 0; i < iccid.length(); i += 2) {
      byteIccid[i / 2] = (byte) Integer.parseInt(iccid.substring(i, i + 2), 0x10);
    }
    return getKey(masterKey, byteIccid);
  }

  /**
   * Generates ciphering key from master key and ICCID. It is computed by using DES ECB with key=master key and data=last 8 bytes of ICCID.
   *
   * @param masterKey - master key. Must be 8 bytes length.
   * @param iccid     - ICCID. Must be &gt;= 8 length.
   * @return byte[]
   * @throws IllegalArgumentException if ICCID is null or iccid.length &lt; 8
   * @throws IllegalArgumentException if master key is null or masterKey.length != 8
   * @throws GeneralSecurityException in case of unexpected cryptographic problems
   */
  public static byte[] getKey(byte[] masterKey, byte[] iccid) throws GeneralSecurityException {
    if (masterKey == null || masterKey.length != 8) {
      throw new IllegalArgumentException("Master key cannot be null or not 8-bytes length. MasterKey="
          + Util.toHexArray(masterKey));
    }
    if (iccid == null || iccid.length < 8) {
      throw new IllegalArgumentException("ICCID cannot be null or less than 8-bytes length. ICCID="
          + Util.toHexArray(iccid));
    }

    if (iccid.length > 8) {
      iccid = Arrays.copyOfRange(iccid, iccid.length - 8, iccid.length);
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("ICCID length > 8 - using last 8 bytes: {}", iccid);
      }
    }
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Generating key. Master key: {}, ICCID= {}", Util.toHexArray(masterKey), Util.toHexArray(iccid));
    }

    byte[] result = CipheringManager.encipher(TRANSFORMATION, masterKey, iccid);

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Generated key: {}", Util.toHexArray(result));
    }

    return result;
  }

  /**
   * Verify Luhn checksum for string provided. String must be sequence of decimal digits(ex. "1236340012").
   *
   * @param input - sequence of decimal digits(ex. "1236340012")
   * @return boolean
   */
  public static boolean verifyLuhnChecksum(String input) {
    final int[][] sumTable = { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 } };
    int sum = 0, flip = 0;

    for (int i = input.length() - 1; i >= 0; i--) {
      sum += sumTable[flip++ & 0x1][Character.digit(input.charAt(i), 10)];
    }

    final boolean result = sum % 10 == 0;

    if (result && LOGGER.isDebugEnabled()) {
      LOGGER.debug("Checksum check for {} is: PASSED", input);
    }
    if (!result) {
      LOGGER.error("Checksum check for {} is: FAILED", input);
    }
    return result;
  }

  private static String addLuhn(String input) {
    byte[] byteIccid = new byte[input.length() + 1];
    for (int i = 0; i < input.length(); i++) {
      byteIccid[i] = (byte) (Character.digit(input.charAt(i), 10));
    }
    return input + getLuhn(byteIccid);
  }

  private static byte getLuhn(byte[] input) {
    int result = 0;
    int tmp = 0;
    for (int i = 0; i < input.length; i++) {
      tmp = input[input.length - i - 1];
      if (i % 2 != 0) {
        tmp *= 2;
        if (tmp > 9) {
          tmp -= 9;
        }
      }
      result += tmp;
    }
    result = 10 - (result % 10);
    if (result == 10) {
      result = 0; // Strange workaround since this algo never adds "0"
    }
    return (byte) result;
  }
}
