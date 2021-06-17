package org.opentelecoms.gsm0348.api;

import java.nio.ByteBuffer;

public class Util {

  private static final char HEX_CHARS[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

  public static String toHex(final byte b) {
    return new String(new char[]{ '0', 'x', HEX_CHARS[(b & 0xf0) >> 4], HEX_CHARS[b & 0x0f] });
  }

  private static void appendHex(byte b, StringBuilder hexString) {
    final char highNibble = HEX_CHARS[(b & 0xf0) >> 4];
    final char lowNibble = HEX_CHARS[b & 0x0f];
    hexString.append(highNibble);
    hexString.append(lowNibble);
  }

  private static void appendHexPair(final byte b, final StringBuilder hexString) {
    hexString.append("0x");
    appendHex(b, hexString);
  }

  public static String toHexString(final byte[] array) {
    if (array == null) {
      return "null";
    }
    final StringBuilder sb = new StringBuilder();
    for (byte b : array) {
      appendHex(b, sb);
    }
    return sb.toString();
  }

  public static String toHexArray(final byte[] array) {
    if (array == null) {
      return "null";
    }
    final StringBuilder sb = new StringBuilder();
    for (byte b : array) {
      appendHexPair(b, sb);
      sb.append(' ');
    }
    if (sb.length() > 0) {
      sb.deleteCharAt(sb.length() - 1);
    }
    return sb.toString();
  }

  public static byte[] encodeTwoBytesLength(final int length) {
    return new byte[]{ (byte)((length >> 8) & 0xff) , (byte)(length & 0xff)};
  }

  public static byte[] encodeLength(final int length) {
    if (length >= 0 && length <= 127) {
      return new byte[]{ (byte) length };
    }
    if (length >= 128 && length <= 255) {
      return new byte[]{ (byte) 0x81, (byte) length };
    }
    if (length >= 256 && length <= 65535) {
      return new byte[]{ (byte) 0x82, (byte) ((length >> 8) & (byte) 0xff), (byte) (length & (byte) 0xff) };
    }
    if (length >= 65536 && length <= 16777215) {
      return new byte[]{ (byte) 0x83, (byte) ((length >> 16) & (byte) 0xff), (byte) ((length >> 8) & (byte) 0xff), (byte) (length & (byte) 0xff) };
    }
    throw new IllegalArgumentException("ETSI 102 220 encoded length is invalid");
  }

  public static int decodeLengthOne(final byte[] bytes) {
    return (bytes[0] & 0xff);
  }

  public static int decodeLength(final byte[] bytes) {
    byte first = bytes[0];
    if ((first & 0x80) == 0x00) {
      return first & 0xff;
    }
    int octets = (first ^ (byte) 0x80);
    if (octets > 3) {
      throw new IllegalArgumentException("ETSI 102 220 encoded length has too many octets");
    }
    int result = 0;
    for (int i = 1; i <= octets; i++) {
      byte next = bytes[i];
      result |= (next & 0xff) << ((octets - i) * 8);
    }
    return result;
    // return ((bytes[1] & 0xff) << 8) + (first & 0xff);
  }

  public static int decodeLengthTwo(final byte[] bytes) {
    return (((bytes[0] & 0xff) << 8) + (bytes[1] & 0xff));
  }

  public static byte[] getOneBytesLengthBytes(final ByteBuffer byteBuffer) {
    return new byte[]{ byteBuffer.get() };
  }

  public static byte[] getTwoBytesLengthBytes(final ByteBuffer byteBuffer) {
    byte[] bytes = new byte[2];
    byteBuffer.get(bytes);
    return bytes;
  }

  public static byte[] getEncodedLengthBytes(final ByteBuffer byteBuffer) {
    byte first = byteBuffer.get();
    if ((first & 0x80) == 0x00) {
      return new byte[]{ first };
    }
    int octets = (first ^ (byte) 0x80);
    if (octets > 3) {
      throw new IllegalArgumentException("Encoded length has too many octets");
    }
    byte[] bytes = new byte[1 + octets];
    bytes[0] = first;
    byteBuffer.get(bytes, 1, octets);
    return bytes;
  }

  public static int getEncodedLength(final ByteBuffer byteBuffer) {
    byte first = byteBuffer.get();
    if ((first & 0x80) == 0x00) {
      return first;
    }
    int octets = (first ^ (byte) 0x80);
    if (octets > 3) {
      throw new IllegalArgumentException("Encoded length has too many octets");
    }
    int result = 0;
    for (int i = 1; i <= octets; i++) {
      byte next = byteBuffer.get();
      result |= (next & 0xff) << ((octets - i) * 8);
    }
    return result;
  }

}