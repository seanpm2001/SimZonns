package org.opentelecoms.gsm0348.impl;

import org.opentelecoms.gsm0348.api.PacketBuilder;
import org.opentelecoms.gsm0348.api.PacketBuilderConfigurationException;
import org.opentelecoms.gsm0348.api.model.AlgorithmImplementation;
import org.opentelecoms.gsm0348.api.model.CardProfile;
import org.opentelecoms.gsm0348.api.model.CertificationAlgorithmMode;
import org.opentelecoms.gsm0348.api.model.CertificationMode;
import org.opentelecoms.gsm0348.api.model.CipheringAlgorithmMode;
import org.opentelecoms.gsm0348.api.model.CommandSPI;
import org.opentelecoms.gsm0348.api.model.KIC;
import org.opentelecoms.gsm0348.api.model.KID;
import org.opentelecoms.gsm0348.api.model.PoRMode;
import org.opentelecoms.gsm0348.api.model.PoRProtocol;
import org.opentelecoms.gsm0348.api.model.ResponseSPI;
import org.opentelecoms.gsm0348.api.model.SPI;
import org.opentelecoms.gsm0348.api.model.SynchroCounterMode;
import org.opentelecoms.gsm0348.api.model.TransportProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Trivial {@linkplain PacketBuilder} factory. It creates new
 * {@linkplain PacketBuilder} for each {@linkplain CardProfile}.
 *
 * @author Victor Platov
 */
public class PacketBuilderFactory {
  private static final Logger LOGGER = LoggerFactory.getLogger(PacketBuilderFactory.class);

  private PacketBuilderFactory() {
  }

  public static PacketBuilder getInstance(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    LOGGER.trace("Creating new packet builder for profile {}", cardProfile);
    return new PacketBuilderImpl(cardProfile);
  }

  /**
   * Creates a default instance for SMS_PP with no security applied.
   *
   * Useful for recovering packets with {@link PacketBuilder#recoverCommandPacket(byte[], byte[], byte[])}.
   *
   * @return the created packet builder.
   */
  public static PacketBuilder getInstance() {
    CardProfile cardProfile = new CardProfile();
    cardProfile.setTransportProtocol(TransportProtocol.SMS_PP);
    cardProfile.setTAR(new byte[]{ 0, 0, 0 });

    KIC kic = new KIC();
    kic.setAlgorithmImplementation(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES);
    kic.setCipheringAlgorithmMode(CipheringAlgorithmMode.DES_CBC);
    kic.setKeysetID((byte) 0);
    cardProfile.setKIC(kic);

    KID kid = new KID();
    kid.setAlgorithmImplementation(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES);
    kid.setCertificationAlgorithmMode(CertificationAlgorithmMode.DES_CBC);
    kid.setKeysetID((byte) 0);
    cardProfile.setKID(kid);

    SPI spi = new SPI();
    CommandSPI commandSPI = new CommandSPI();
    commandSPI.setCertificationMode(CertificationMode.NO_SECURITY);
    commandSPI.setCiphered(false);
    commandSPI.setSynchroCounterMode(SynchroCounterMode.COUNTER_NO_REPLAY_NO_CHECK);
    spi.setCommandSPI(commandSPI);

    ResponseSPI responseSPI = new ResponseSPI();
    responseSPI.setCiphered(false);
    responseSPI.setPoRCertificateMode(CertificationMode.NO_SECURITY);
    responseSPI.setPoRMode(PoRMode.NO_REPLY);
    responseSPI.setPoRProtocol(PoRProtocol.SMS_SUBMIT);
    spi.setResponseSPI(responseSPI);
    cardProfile.setSPI(spi);
    try {
      return getInstance(cardProfile);
    } catch (PacketBuilderConfigurationException e) {
      throw new RuntimeException("Could not instance a packet builder", e);
    }
  }

}
