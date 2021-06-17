package org.opentelecoms.gsm0348.impl;

import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.opentelecoms.gsm0348.api.PacketBuilder;
import org.opentelecoms.gsm0348.api.model.AlgorithmImplementation;
import org.opentelecoms.gsm0348.api.model.CardProfile;
import org.opentelecoms.gsm0348.api.model.CertificationAlgorithmMode;
import org.opentelecoms.gsm0348.api.model.CertificationMode;
import org.opentelecoms.gsm0348.api.model.CipheringAlgorithmMode;
import org.opentelecoms.gsm0348.api.model.CommandPacket;
import org.opentelecoms.gsm0348.api.model.CommandSPI;
import org.opentelecoms.gsm0348.api.model.KIC;
import org.opentelecoms.gsm0348.api.model.KID;
import org.opentelecoms.gsm0348.api.model.PoRMode;
import org.opentelecoms.gsm0348.api.model.PoRProtocol;
import org.opentelecoms.gsm0348.api.model.ResponsePacket;
import org.opentelecoms.gsm0348.api.model.ResponsePacketStatus;
import org.opentelecoms.gsm0348.api.model.ResponseSPI;
import org.opentelecoms.gsm0348.api.model.SPI;
import org.opentelecoms.gsm0348.api.model.SynchroCounterMode;
import org.opentelecoms.gsm0348.api.model.TransportProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.impl.SimpleLogger;

@RunWith(Parameterized.class)
public class PacketBuilderImplTest {

  private static final Logger log = LoggerFactory.getLogger(PacketBuilderImplTest.class);

  private Random random = new Random();

  private PacketType packetType;
  private CardProfile cardProfile;
  private int cipheringKeyLength;
  private int signatureKeyLength;

  public PacketBuilderImplTest(PacketType packetType, CardProfile cardProfile, int cipheringKeyLength, int signatureKeyLength) {
    this.packetType = packetType;
    this.cardProfile = cardProfile;
    this.cipheringKeyLength = cipheringKeyLength;
    this.signatureKeyLength = signatureKeyLength;
  }

  @Parameters
  public static Collection<Object[]> data() {
    ArrayList<Object[]> parameters = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      for (TransportProtocol tp : TransportProtocol.values()) {
        for (PacketType packetType : PacketType.values()) {
          if (tp == TransportProtocol.SMS_CB && packetType == PacketType.RESPONSE) {
            // For SMS_CB, no response is defined
            continue;
          }

          // NO SECURITY DES
          parameters.add(new Object[]{ packetType, createNoSecurityProfile(tp, false), 8, 8 });
          //parameters.add(new Object[]{ packetType, createDesNoSecurityProfile(tp, true), 8, 8 });

          // CC DES_CBC DES_CBC
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_CBC, CertificationAlgorithmMode.DES_CBC, false), 8, 8 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_CBC, CertificationAlgorithmMode.DES_CBC, true), 8, 8 });

          // CC DES_CBC TRIPLE_DES_CBC_2_KEYS
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_CBC, CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS,
              false), 8, 16 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_CBC, CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS,
              true), 8, 16 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_CBC, CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS,
              false), 8, 24 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_CBC, CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS,
              true), 8, 24 });

          // CC DES_CBC TRIPLE_DES_CBC_3_KEYS
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_CBC, CertificationAlgorithmMode.TRIPLE_DES_CBC_3_KEYS,
              false), 8, 16 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_CBC, CertificationAlgorithmMode.TRIPLE_DES_CBC_3_KEYS,
              true), 8, 16 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_CBC, CertificationAlgorithmMode.TRIPLE_DES_CBC_3_KEYS,
              false), 8, 24 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_CBC, CertificationAlgorithmMode.TRIPLE_DES_CBC_3_KEYS,
              true), 8, 24 });

          // CC DES_EBC DES_CBC
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_ECB, CertificationAlgorithmMode.DES_CBC, false), 8, 8 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_ECB, CertificationAlgorithmMode.DES_CBC, true), 8, 8 });

          // CC DES_EBC TRIPLE_DES_CBC_2_KEYS
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_ECB, CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS,
              false), 8, 16 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_ECB, CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS,
              true), 8, 16 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_ECB, CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS,
              false), 8, 24 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_ECB, CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS,
              true), 8, 24 });

          // CC DES_EBC TRIPLE_DES_CBC_3_KEYS
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_ECB, CertificationAlgorithmMode.TRIPLE_DES_CBC_3_KEYS,
              false), 8, 16 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_ECB, CertificationAlgorithmMode.TRIPLE_DES_CBC_3_KEYS,
              true), 8, 16 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_ECB, CertificationAlgorithmMode.TRIPLE_DES_CBC_3_KEYS,
              false), 8, 24 });
          parameters.add(new Object[]{ packetType, createDesProfile(tp, CipheringAlgorithmMode.DES_ECB, CertificationAlgorithmMode.TRIPLE_DES_CBC_3_KEYS,
              true), 8, 24 });

          // CC AES AES_CMAC_32
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_32", false), 16, 16 });
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_32", true), 16, 16 });
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_32", false), 24, 24 });
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_32", true), 24, 24 });
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_32", false), 32, 32 });
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_32", true), 32, 32 });

          // CC AES AES_CMAC_32
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_64", false), 16, 16 });
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_64", true), 16, 16 });
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_64", false), 24, 24 });
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_64", true), 24, 24 });
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_64", false), 32, 32 });
          parameters.add(new Object[]{ packetType, createAesProfile(tp, "AES_CMAC_64", true), 32, 32 });

          // RC
          parameters.add(new Object[]{ packetType, createRcProfile(tp, false, "CRC16"), 8, 8 });
          parameters.add(new Object[]{ packetType, createRcProfile(tp, false, "CRC32"), 8, 8 });
          parameters.add(new Object[]{ packetType, createRcProfile(tp, false, "XOR4"), 8, 8 });
          parameters.add(new Object[]{ packetType, createRcProfile(tp, false, "XOR8"), 8, 8 });
          parameters.add(new Object[]{ packetType, createRcProfile(tp, true, "CRC16"), 8, 8 });
          parameters.add(new Object[]{ packetType, createRcProfile(tp, true, "CRC32"), 8, 8 });
          parameters.add(new Object[]{ packetType, createRcProfile(tp, true, "XOR4"), 8, 8 });
          parameters.add(new Object[]{ packetType, createRcProfile(tp, true, "XOR8"), 8, 8 });
        }
      }
    }

    return parameters;
  }

  @BeforeClass
  public static void beforeClass() throws Exception {
    System.setProperty(SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "debug");
    System.setProperty("java.util.logging.ConsoleHandler.level", "FINEST");
    /*
     * Adding security provider - it will do all security job
     */
    Security.addProvider(new BouncyCastleProvider());

    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static CardProfile createNoSecurityProfile(final TransportProtocol transportProtocol, final boolean cipher) {
    CardProfile cardProfile = new CardProfile();
    cardProfile.setName(transportProtocol.value() + " NO SECURITY " + (cipher ? "ciphered" : "plain"));
    cardProfile.setTransportProtocol(transportProtocol);
    cardProfile.setCipheringAlgorithm(null);
    cardProfile.setSignatureAlgorithm(null);
    cardProfile.setTAR(new byte[]{ (byte) 0xb0, 0x00, 0x10 });

    KIC kic = new KIC();
    kic.setAlgorithmImplementation(null);
    kic.setCipheringAlgorithmMode(null);
    kic.setKeysetID((byte) 1);
    cardProfile.setKIC(kic);

    KID kid = new KID();
    kid.setAlgorithmImplementation(null);
    kid.setCertificationAlgorithmMode(null);
    kid.setKeysetID((byte) 1);
    cardProfile.setKID(kid);

    SPI spi = new SPI();
    CommandSPI commandSPI = new CommandSPI();
    commandSPI.setCertificationMode(CertificationMode.NO_SECURITY);
    commandSPI.setCiphered(cipher);
    commandSPI.setSynchroCounterMode(SynchroCounterMode.NO_COUNTER);
    spi.setCommandSPI(commandSPI);

    ResponseSPI responseSPI = new ResponseSPI();
    responseSPI.setCiphered(cipher);
    responseSPI.setPoRCertificateMode(CertificationMode.NO_SECURITY);
    responseSPI.setPoRMode(PoRMode.REPLY_WHEN_ERROR);
    responseSPI.setPoRProtocol(PoRProtocol.SMS_SUBMIT);
    spi.setResponseSPI(responseSPI);

    cardProfile.setSPI(spi);

    return cardProfile;
  }

  private static CardProfile createDesProfile(final TransportProtocol transportProtocol,
                                              final CipheringAlgorithmMode cipheringAlgorithmMode,
                                              final CertificationAlgorithmMode certificationAlgorithmMode,
                                              final boolean cipher) {
    CardProfile cardProfile = new CardProfile();
    cardProfile.setName(transportProtocol.value() + " " +
        cipheringAlgorithmMode + " " +
        certificationAlgorithmMode + " " +
        (cipher ? "ciphered" : "plain"));
    cardProfile.setTransportProtocol(transportProtocol);
    cardProfile.setCipheringAlgorithm(null);
    cardProfile.setSignatureAlgorithm(null);
    cardProfile.setTAR(new byte[]{ (byte) 0xb0, 0x00, 0x10 });

    KIC kic = new KIC();
    kic.setAlgorithmImplementation(AlgorithmImplementation.DES);
    kic.setCipheringAlgorithmMode(cipheringAlgorithmMode);
    kic.setKeysetID((byte) 1);
    cardProfile.setKIC(kic);

    KID kid = new KID();
    kid.setAlgorithmImplementation(AlgorithmImplementation.DES);
    kid.setCertificationAlgorithmMode(certificationAlgorithmMode);
    kid.setKeysetID((byte) 1);
    cardProfile.setKID(kid);

    SPI spi = new SPI();
    CommandSPI commandSPI = new CommandSPI();
    commandSPI.setCertificationMode(CertificationMode.CC);
    commandSPI.setCiphered(cipher);
    commandSPI.setSynchroCounterMode(SynchroCounterMode.COUNTER_REPLAY_OR_CHECK_INCREMENT);
    spi.setCommandSPI(commandSPI);

    ResponseSPI responseSPI = new ResponseSPI();
    responseSPI.setCiphered(cipher);
    responseSPI.setPoRCertificateMode(CertificationMode.CC);
    responseSPI.setPoRMode(PoRMode.REPLY_ALWAYS);
    responseSPI.setPoRProtocol(PoRProtocol.SMS_DELIVER_REPORT);
    spi.setResponseSPI(responseSPI);

    cardProfile.setSPI(spi);

    return cardProfile;
  }

  private static CardProfile createAesProfile(final TransportProtocol transportProtocol, final String signatureAlgorithm, final boolean cipher) {
    CardProfile cardProfile = new CardProfile();
    cardProfile.setName(transportProtocol.value() + " AES " + (cipher ? "ciphered" : "plain"));
    cardProfile.setTransportProtocol(transportProtocol);
    cardProfile.setCipheringAlgorithm("");
    cardProfile.setSignatureAlgorithm(signatureAlgorithm);
    cardProfile.setTAR(new byte[]{ (byte) 0x00, 0x00, 0x01 });

    KIC kic = new KIC();
    kic.setAlgorithmImplementation(AlgorithmImplementation.AES);
    kic.setCipheringAlgorithmMode(CipheringAlgorithmMode.AES_CBC);
    kic.setKeysetID((byte) 1);
    cardProfile.setKIC(kic);

    KID kid = new KID();
    kid.setAlgorithmImplementation(AlgorithmImplementation.AES);
    kid.setCertificationAlgorithmMode(CertificationAlgorithmMode.AES_CMAC);
    kid.setKeysetID((byte) 1);
    cardProfile.setKID(kid);

    SPI spi = new SPI();
    CommandSPI commandSPI = new CommandSPI();
    commandSPI.setCertificationMode(CertificationMode.CC);
    commandSPI.setCiphered(cipher);
    commandSPI.setSynchroCounterMode(SynchroCounterMode.COUNTER_REPLAY_OR_CHECK);
    spi.setCommandSPI(commandSPI);

    ResponseSPI responseSPI = new ResponseSPI();
    responseSPI.setCiphered(cipher);
    responseSPI.setPoRCertificateMode(CertificationMode.CC);
    responseSPI.setPoRMode(PoRMode.REPLY_ALWAYS);
    responseSPI.setPoRProtocol(PoRProtocol.SMS_SUBMIT);
    spi.setResponseSPI(responseSPI);

    cardProfile.setSPI(spi);

    return cardProfile;
  }

  private static CardProfile createRcProfile(final TransportProtocol transportProtocol, final boolean cipher, final String signatureAlgorithm) {
    CardProfile cardProfile = new CardProfile();
    cardProfile.setName(transportProtocol.value() + " DES/CBC RC " + signatureAlgorithm + " " + (cipher ? "ciphered" : "plain"));
    cardProfile.setTransportProtocol(transportProtocol);
    cardProfile.setCipheringAlgorithm("");
    cardProfile.setSignatureAlgorithm(signatureAlgorithm);
    cardProfile.setTAR(new byte[]{ (byte) 0x00, 0x00, 0x01 });

    KIC kic = new KIC();
    kic.setAlgorithmImplementation(AlgorithmImplementation.DES);
    kic.setCipheringAlgorithmMode(CipheringAlgorithmMode.DES_CBC);
    kic.setKeysetID((byte) 1);
    cardProfile.setKIC(kic);

    KID kid = new KID();
    switch (signatureAlgorithm) {
      case "CRC16":
        kid.setAlgorithmImplementation(AlgorithmImplementation.CRC);
        kid.setCertificationAlgorithmMode(CertificationAlgorithmMode.CRC_16);
        break;
      case "CRC32":
        kid.setAlgorithmImplementation(AlgorithmImplementation.CRC);
        kid.setCertificationAlgorithmMode(CertificationAlgorithmMode.CRC_32);
        break;
      case "XOR4":
        kid.setAlgorithmImplementation(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES);
        kid.setCertificationAlgorithmMode(CertificationAlgorithmMode.XOR_4);
        break;
      case "XOR8":
        kid.setAlgorithmImplementation(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES);
        kid.setCertificationAlgorithmMode(CertificationAlgorithmMode.XOR_8);
        break;
      default:
        throw new IllegalArgumentException("Signature algorithm " + signatureAlgorithm + " is invalid");
    }
    kid.setKeysetID((byte) 1);
    cardProfile.setKID(kid);

    SPI spi = new SPI();
    CommandSPI commandSPI = new CommandSPI();
    commandSPI.setCertificationMode(CertificationMode.RC);
    commandSPI.setCiphered(cipher);
    commandSPI.setSynchroCounterMode(SynchroCounterMode.COUNTER_REPLAY_OR_CHECK);
    spi.setCommandSPI(commandSPI);

    ResponseSPI responseSPI = new ResponseSPI();
    responseSPI.setCiphered(cipher);
    responseSPI.setPoRCertificateMode(CertificationMode.RC);
    responseSPI.setPoRMode(PoRMode.REPLY_ALWAYS);
    responseSPI.setPoRProtocol(PoRProtocol.SMS_DELIVER_REPORT);
    spi.setResponseSPI(responseSPI);

    cardProfile.setSPI(spi);

    return cardProfile;
  }

  @Test
  public void should_create_and_recover_packet() throws Exception {
    log.info("*** START {} {} ***", packetType, cardProfile.getName());
    switch (packetType) {
      case COMMAND:
        should_create_and_recover_command_packet();
        break;
      case RESPONSE:
        should_create_and_recover_response_packet();
        break;
    }
    log.info("*** END {} {} ***", packetType, cardProfile.getName());
  }

  private void should_create_and_recover_command_packet() throws Exception {
    log.info("Test command: {} cipherKeyLen:{} signKeyLen:{}", cardProfile.getName(), cipheringKeyLength, signatureKeyLength);

    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    /*
     * Data to be sent to applet. Commonly it is an APDU command for Remote File Management Applet.
     * Or RAM Applet.
     */
    byte[] data = new byte[random.nextInt(64)];
    random.nextBytes(data);
    byte[] counter = new byte[]{ 0, 0, 0, (byte) (random.nextInt(256)), (byte) (random.nextInt(254) + 1) };

    /*
     * Use random security keys
     */
    byte[] cipheringKey = new byte[cipheringKeyLength];
    random.nextBytes(cipheringKey);
    byte[] signatureKey = new byte[signatureKeyLength];
    random.nextBytes(signatureKey);

    byte[] packet = packetBuilder.buildCommandPacket(data, counter, cipheringKey, signatureKey);

    CommandPacket recoveredPacket = packetBuilder.recoverCommandPacket(packet, cipheringKey, signatureKey);

    // KIC
    switch (cardProfile.getSPI().getCommandSPI().getCertificationMode()) {
      case RC:
      case CC:
      case DS:
        Assert.assertEquals(cardProfile.getKIC().getAlgorithmImplementation(), recoveredPacket.getHeader().getKIC().getAlgorithmImplementation());
        Assert.assertEquals(cardProfile.getKIC().getCipheringAlgorithmMode(), recoveredPacket.getHeader().getKIC().getCipheringAlgorithmMode());
    }
    Assert.assertEquals(cardProfile.getKIC().getKeysetID(), recoveredPacket.getHeader().getKIC().getKeysetID());

    // KID
    switch (cardProfile.getSPI().getResponseSPI().getPoRCertificateMode()) {
      case RC:
      case CC:
      case DS:
        if (recoveredPacket.getHeader().getKID().getAlgorithmImplementation() != null) {
          Assert.assertEquals(cardProfile.getKID().getAlgorithmImplementation(), recoveredPacket.getHeader().getKID().getAlgorithmImplementation());
        }
        if (recoveredPacket.getHeader().getKID().getCertificationAlgorithmMode() != null) {
          Assert.assertEquals(cardProfile.getKID().getCertificationAlgorithmMode(), recoveredPacket.getHeader().getKID().getCertificationAlgorithmMode());
        }
    }
    Assert.assertEquals(cardProfile.getKID().getKeysetID(), recoveredPacket.getHeader().getKID().getKeysetID());
    Assert.assertArrayEquals(cardProfile.getTAR(), recoveredPacket.getHeader().getTAR());
    if (cardProfile.getSPI().getCommandSPI().getSynchroCounterMode() == SynchroCounterMode.NO_COUNTER) {
      Assert.assertArrayEquals(new byte[]{ 0, 0, 0, 0, 0 }, recoveredPacket.getHeader().getCounter());
    } else {
      Assert.assertArrayEquals(counter, recoveredPacket.getHeader().getCounter());
    }
    Assert.assertArrayEquals(data, recoveredPacket.getData());
  }

  private void should_create_and_recover_response_packet() throws Exception {
    log.info("Test response: profile:{} cipherKeyLen:{} signKeyLen:{}", cardProfile.getName(), cipheringKeyLength, signatureKeyLength);

    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    /*
     * Data sent by applet as response.
     */
    byte[] data = new byte[random.nextInt(32)];
    random.nextBytes(data);
    byte[] counter = new byte[]{ 0, 0, 0, (byte) (random.nextInt(256)), (byte) (random.nextInt(254) + 1) };

    /*
     * Use random security keys
     */
    byte[] cipheringKey = new byte[cipheringKeyLength];
    random.nextBytes(cipheringKey);
    byte[] signatureKey = new byte[signatureKeyLength];
    random.nextBytes(signatureKey);

    ResponsePacketStatus responsePacketStatus = ResponsePacketStatus.CNTR_LOW;

    byte[] packet = packetBuilder.buildResponsePacket(data, counter, cipheringKey, signatureKey, responsePacketStatus);

    ResponsePacket recoveredPacket = packetBuilder.recoverResponsePacket(packet, cipheringKey, signatureKey);

    Assert.assertArrayEquals(cardProfile.getTAR(), recoveredPacket.getHeader().getTAR());
    if (cardProfile.getSPI().getCommandSPI().getSynchroCounterMode() == SynchroCounterMode.NO_COUNTER) {
      Assert.assertArrayEquals(new byte[]{ 0, 0, 0, 0, 0 }, recoveredPacket.getHeader().getCounter());
    } else {
      Assert.assertArrayEquals(counter, recoveredPacket.getHeader().getCounter());
    }
    Assert.assertEquals(ResponsePacketStatus.CNTR_LOW, recoveredPacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(data, recoveredPacket.getData());
  }

  private enum PacketType {
    COMMAND,
    RESPONSE
  }
}