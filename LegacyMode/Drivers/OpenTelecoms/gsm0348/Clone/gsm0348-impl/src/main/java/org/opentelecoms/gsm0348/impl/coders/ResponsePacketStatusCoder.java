package org.opentelecoms.gsm0348.impl.coders;

import org.opentelecoms.gsm0348.api.Util;
import org.opentelecoms.gsm0348.api.model.ResponsePacketStatus;
import org.opentelecoms.gsm0348.impl.CodingException;

public class ResponsePacketStatusCoder {
  public static byte decode(ResponsePacketStatus respStatus) throws CodingException {
    switch (respStatus) {
      case POR_OK:
        return 0x00;
      case RC_CC_DS_FAILED:
        return 0x01;
      case CNTR_LOW:
        return 0x02;
      case CNTR_HIGH:
        return 0x03;
      case CNTR_BLOCKED:
        return 0x04;
      case CIPHERING_ERROR:
        return 0x05;
      case UNIDENTIFIED_SECURITY_ERROR:
        return 0x06;
      case INSUFFICIENT_MEMORY:
        return 0x07;
      case MORE_TIME:
        return 0x08;
      case TAR_UNKNOWN:
        return 0x09;
      case INSUFFICIENT_SECURITY_LEVEL:
        return 0x0a;
      case TO_BE_SENT_VIA_SMS_SUBMIT:
        return 0x0b;
      case TO_BE_SENT_VIA_PROCESSUNSTRUCTUREDSS_REQUEST:
        return 0x0c;

      default:
        throw new CodingException("Cannot code " + respStatus);
    }
  }

  public static ResponsePacketStatus encode(byte respStatus) throws CodingException {
    switch (respStatus) {
      case 0x00:
        return ResponsePacketStatus.POR_OK;
      case 0x01:
        return ResponsePacketStatus.RC_CC_DS_FAILED;
      case 0x02:
        return ResponsePacketStatus.CNTR_LOW;
      case 0x03:
        return ResponsePacketStatus.CNTR_HIGH;
      case 0x04:
        return ResponsePacketStatus.CNTR_BLOCKED;
      case 0x05:
        return ResponsePacketStatus.CIPHERING_ERROR;
      case 0x06:
        return ResponsePacketStatus.UNIDENTIFIED_SECURITY_ERROR;
      case 0x07:
        return ResponsePacketStatus.INSUFFICIENT_MEMORY;
      case 0x08:
        return ResponsePacketStatus.MORE_TIME;
      case 0x09:
        return ResponsePacketStatus.TAR_UNKNOWN;
      case 0x0a:
        return ResponsePacketStatus.INSUFFICIENT_SECURITY_LEVEL;
      case 0x0b:
        return ResponsePacketStatus.TO_BE_SENT_VIA_SMS_SUBMIT;
      case 0x0c:
        return ResponsePacketStatus.TO_BE_SENT_VIA_PROCESSUNSTRUCTUREDSS_REQUEST;
      default:
        throw new CodingException("Cannot decode response packet status with id=" + Util.toHex(respStatus));
    }
  }
}
