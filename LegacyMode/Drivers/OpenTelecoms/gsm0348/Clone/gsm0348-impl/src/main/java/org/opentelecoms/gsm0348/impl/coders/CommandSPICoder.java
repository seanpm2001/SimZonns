package org.opentelecoms.gsm0348.impl.coders;

import org.opentelecoms.gsm0348.api.Util;
import org.opentelecoms.gsm0348.api.model.CertificationMode;
import org.opentelecoms.gsm0348.api.model.CommandSPI;
import org.opentelecoms.gsm0348.api.model.SynchroCounterMode;
import org.opentelecoms.gsm0348.impl.CodingException;

public class CommandSPICoder {
  public static byte decode(CommandSPI commandSPI) throws CodingException {
    int certMode = 0;
    int counterMode = 0;
    boolean isCiphered = commandSPI.isCiphered();

    switch (commandSPI.getCertificationMode()) {
      case NO_SECURITY:
        certMode = 0;
        break;
      case RC:
        certMode = 1;
        break;
      case CC:
        certMode = 2;
        break;
      case DS:
        certMode = 3;
        break;
    }

    switch (commandSPI.getSynchroCounterMode()) {
      case NO_COUNTER:
        counterMode = 0;
        break;
      case COUNTER_NO_REPLAY_NO_CHECK:
        counterMode = 1;
        break;
      case COUNTER_REPLAY_OR_CHECK:
        counterMode = 2;
        break;
      case COUNTER_REPLAY_OR_CHECK_INCREMENT:
        counterMode = 3;
        break;
    }

    byte result = (byte) (certMode + (counterMode << 3));
    if (isCiphered) {
      result = (byte) (result | (1 << 2));
    }

    return result;
  }

  public static CommandSPI encode(byte commandSPI) throws CodingException {
    CommandSPI result = new CommandSPI();

    final int certMode = commandSPI & 0x3;
    final int counterMode = (commandSPI & 0x18) >> 3;
    boolean isCiphered = (commandSPI & 0x4) != 0;

    CertificationMode resultCertMode;
    switch (certMode) {
      case 0:
        resultCertMode = CertificationMode.NO_SECURITY;
        break;
      case 1:
        resultCertMode = CertificationMode.RC;
        break;
      case 2:
        resultCertMode = CertificationMode.CC;
        break;
      case 3:
        resultCertMode = CertificationMode.DS;
        break;

      default:
        throw new CodingException("Cannot encode CommandSPI(raw=" + Util.toHex(commandSPI) + "). No such certification mode(raw="
            + Integer.toHexString(certMode));
    }

    SynchroCounterMode resultCounterMode;
    switch (counterMode) {
      case 0:
        resultCounterMode = SynchroCounterMode.NO_COUNTER;
        break;
      case 1:
        resultCounterMode = SynchroCounterMode.COUNTER_NO_REPLAY_NO_CHECK;
        break;
      case 2:
        resultCounterMode = SynchroCounterMode.COUNTER_REPLAY_OR_CHECK;
        break;
      case 3:
        resultCounterMode = SynchroCounterMode.COUNTER_REPLAY_OR_CHECK_INCREMENT;
        break;

      default:
        throw new CodingException("Cannot encode CommandSPI(raw=" + Util.toHex(commandSPI) + "). No such counter mode(raw="
            + Integer.toHexString(counterMode));
    }

    result.setCertificationMode(resultCertMode);
    result.setCiphered(isCiphered);
    result.setSynchroCounterMode(resultCounterMode);

    return result;
  }
}
