package org.opentelecoms.gsm0348.impl.coders;

import java.nio.ByteBuffer;

import org.opentelecoms.gsm0348.api.Util;
import org.opentelecoms.gsm0348.api.model.CardProfile;
import org.opentelecoms.gsm0348.api.model.CertificationMode;
import org.opentelecoms.gsm0348.api.model.KIC;
import org.opentelecoms.gsm0348.api.model.KID;
import org.opentelecoms.gsm0348.api.model.SPI;
import org.opentelecoms.gsm0348.impl.CodingException;
import org.opentelecoms.gsm0348.impl.crypto.SignatureManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class provides methods for converting row bytes array to {@linkplain CardProfile} and backside.
 *
 * @author Vasily Avilov
 */
public class CardProfileCoder {

  private static final Logger LOGGER = LoggerFactory.getLogger(CardProfileCoder.class);

  private static final int TAR_SIZE = 3;

  /**
   * Build {@linkplain CardProfile} from row byte array
   *
   * @param datarow - the message header {@linkplain byte[]} row.
   * @return CardProfile
   * @throws NullPointerException if <strong>datarow</strong> parameter is null.
   * @throws CodingException      if configuration is in inconsistent state.
   */
  public static CardProfile encode(byte[] datarow) throws CodingException {

    if (datarow == null) {
      throw new NullPointerException();
    }

    if (datarow.length < 7) {
      throw new CodingException("Incorrect header size");
    }

    CardProfile newCardProfile = new CardProfile();

    ByteBuffer data = ByteBuffer.wrap(datarow);

    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode(data.get()));
    spi.setResponseSPI(ResponseSPICoder.encode(data.get()));
    LOGGER.debug("SPI: {}", spi.toString());

    KIC kic = KICCoder.encode(data.get());
    LOGGER.debug("KIC: {}", kic);
    KID kid = KIDCoder.encode(spi.getCommandSPI().getCertificationMode(), data.get());
    LOGGER.debug("KID: {}", kid);

    byte[] tar = new byte[TAR_SIZE];
    data.get(tar);
    newCardProfile.setTAR(tar);

    LOGGER.debug("TAR: {}", Util.toHexArray(tar));

    newCardProfile.setSPI(spi);
    newCardProfile.setKIC(kic);
    newCardProfile.setKID(kid);

    // The initial chaining value for CBC modes shall be zero.

    switch (kic.getAlgorithmImplementation()) {
      case PROPRIETARY_IMPLEMENTATIONS:
      case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
        break;
      case DES:
        switch (kic.getCipheringAlgorithmMode()) {
          case DES_CBC:
            newCardProfile.setCipheringAlgorithm("DES/CBC/NoPadding");
            break;

          case DES_ECB:
            newCardProfile.setCipheringAlgorithm("DES/ECB/NoPadding");
            break;

          case TRIPLE_DES_CBC_2_KEYS:
          case TRIPLE_DES_CBC_3_KEYS:
            newCardProfile.setCipheringAlgorithm("DESede/CBC/NoPadding");
            break;

          default:
        }
        break;

      case AES:
        // AES shall be used together with counter settings (b5 and b4 of the first octet of SPI) 10 or 11.
        switch (kic.getCipheringAlgorithmMode()) {
          case AES_CBC:
            newCardProfile.setCipheringAlgorithm("AES/CBC/NoPadding");
            break;
          default:
        }
        break;

      default:
    }

    if (!spi.getCommandSPI().getCertificationMode().equals(CertificationMode.NO_SECURITY)) {
      switch (kid.getAlgorithmImplementation()) {
        case CRC:
          switch (kid.getCertificationAlgorithmMode()) {
            case CRC_16:
              newCardProfile.setSignatureAlgorithm(SignatureManager.CRC_16);
              break;
            case CRC_32:
              newCardProfile.setSignatureAlgorithm(SignatureManager.CRC_32);
              break;
          }
        case PROPRIETARY_IMPLEMENTATIONS:
        case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
          break;
        case DES:
          switch (kid.getCertificationAlgorithmMode()) {
            case DES_CBC:
              newCardProfile.setSignatureAlgorithm(SignatureManager.DES_MAC8_ISO9797_M1);
              break;

            case RESERVED:
              break;

            case TRIPLE_DES_CBC_2_KEYS:
            case TRIPLE_DES_CBC_3_KEYS:
              newCardProfile.setSignatureAlgorithm(SignatureManager.DES_EDE_MAC64);
              break;

            default:
          }
          break;
        case AES:
          // For AES CMAC, use AES_CMAC_32 or AES_CMAC_64, default is SignatureManager.AES_CMAC_64
          // Otherwise set the value explicit.
          newCardProfile.setSignatureAlgorithm(SignatureManager.AES_CMAC_64);
          break;
      }
    }
    return newCardProfile;
  }

  /**
   * Build {@linkplain byte[]} from {@linkplain CardProfile}
   *
   * @param profile - a card profile {@linkplain CardProfile}.
   * @return byte[]
   * @throws NullPointerException if <strong>profile</strong> parameter is null.
   * @throws CodingException      if configuration is in inconsistent state.
   */
  public static byte[] decode(CardProfile profile) throws CodingException {

    if (profile == null) {
      throw new IllegalArgumentException("The profile argument cannot be null");
    }

    ByteBuffer header = ByteBuffer.allocate(7);

    byte commandSpi = CommandSPICoder.decode(profile.getSPI().getCommandSPI());
    header.put(commandSpi);
    byte responseSpi = ResponseSPICoder.decode(profile.getSPI().getResponseSPI());
    header.put(ResponseSPICoder.decode(profile.getSPI().getResponseSPI()));
    LOGGER.debug("SPI: {}", String.format("%1$#x %2$#x", commandSpi, responseSpi));

    byte kic = KICCoder.decode(profile.getKIC());
    header.put(kic);
    LOGGER.debug("KIC: {}", Util.toHex(kic));

    byte kid = KIDCoder.decode(profile.getKID());
    header.put(kid);
    LOGGER.debug("KID: {}", Util.toHex(kid));

    byte[] tar = profile.getTAR();
    header.put(tar);
    LOGGER.debug("TAR: {}", Util.toHexArray(tar));

    return header.array();
  }
}
