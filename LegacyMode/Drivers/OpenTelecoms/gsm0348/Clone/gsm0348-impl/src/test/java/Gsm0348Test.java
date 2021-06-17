import static org.opentelecoms.gsm0348.api.model.ResponsePacketStatus.POR_OK;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.opentelecoms.gsm0348.api.PacketBuilder;
import org.opentelecoms.gsm0348.api.Util;
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
import org.opentelecoms.gsm0348.impl.PacketBuilderFactory;
import org.opentelecoms.gsm0348.impl.coders.CardProfileCoder;
import org.opentelecoms.gsm0348.impl.coders.CommandSPICoder;
import org.opentelecoms.gsm0348.impl.coders.KICCoder;
import org.opentelecoms.gsm0348.impl.coders.KIDCoder;
import org.opentelecoms.gsm0348.impl.coders.ResponseSPICoder;
import org.opentelecoms.gsm0348.impl.crypto.SignatureManager;
import org.slf4j.impl.SimpleLogger;

public class Gsm0348Test {

  private PacketBuilder packetBuilder;
  private byte[] cipheringKey;
  private byte[] signatureKey;

  private static CardProfile createProfile() {
    CardProfile cardProfile = new CardProfile();
    cardProfile.setTransportProtocol(TransportProtocol.SMS_PP);
    cardProfile.setCipheringAlgorithm(null);
    cardProfile.setSignatureAlgorithm(null);
    cardProfile.setTAR(new byte[]{ (byte) 0xb0, 0x00, 0x10 });

    KIC kic = new KIC();
    kic.setAlgorithmImplementation(AlgorithmImplementation.DES);
    kic.setCipheringAlgorithmMode(CipheringAlgorithmMode.DES_CBC);
    kic.setKeysetID((byte) 1);
    cardProfile.setKIC(kic);

    KID kid = new KID();
    kid.setAlgorithmImplementation(AlgorithmImplementation.DES);
    kid.setCertificationAlgorithmMode(CertificationAlgorithmMode.DES_CBC);
    kid.setKeysetID((byte) 1);
    cardProfile.setKID(kid);

    SPI spi = new SPI();
    CommandSPI commandSPI = new CommandSPI();
    commandSPI.setCertificationMode(CertificationMode.CC);
    commandSPI.setCiphered(true);
    commandSPI.setSynchroCounterMode(SynchroCounterMode.NO_COUNTER);
    spi.setCommandSPI(commandSPI);

    ResponseSPI responseSPI = new ResponseSPI();
    responseSPI.setCiphered(false);
    responseSPI.setPoRCertificateMode(CertificationMode.NO_SECURITY);
    responseSPI.setPoRMode(PoRMode.REPLY_ALWAYS);
    responseSPI.setPoRProtocol(PoRProtocol.SMS_DELIVER_REPORT);
    spi.setResponseSPI(responseSPI);

    cardProfile.setSPI(spi);

    return cardProfile;
  }

  private static CardProfile createProfileAes(final TransportProtocol transportProtocol, final boolean cipher,
                                              final SynchroCounterMode synchroCounterMode) {
    CardProfile cardProfile = new CardProfile();
    cardProfile.setTransportProtocol(transportProtocol);
    cardProfile.setCipheringAlgorithm(null);
    cardProfile.setSignatureAlgorithm("AES_CMAC_64");
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
    commandSPI.setSynchroCounterMode(synchroCounterMode);
    spi.setCommandSPI(commandSPI);

    ResponseSPI responseSPI = new ResponseSPI();
    responseSPI.setCiphered(cipher);
    responseSPI.setPoRCertificateMode(CertificationMode.CC);
    responseSPI.setPoRMode(PoRMode.REPLY_ALWAYS);
    responseSPI.setPoRProtocol(PoRProtocol.SMS_SUBMIT);
    spi.setResponseSPI(responseSPI);
    cardProfile.setSPI(spi);

    cardProfile.setSPI(spi);

    return cardProfile;
  }

  private static CardProfile createProfileDes(final TransportProtocol transportProtocol, final boolean cipher,
                                              final SynchroCounterMode synchroCounterMode) {
    CardProfile cardProfile = new CardProfile();
    cardProfile.setTransportProtocol(transportProtocol);
    cardProfile.setCipheringAlgorithm(null);
    cardProfile.setSignatureAlgorithm(null);
    cardProfile.setTAR(new byte[]{ (byte) 0xb2, 0x05, 0x02 });

    KIC kic = new KIC();
    kic.setAlgorithmImplementation(AlgorithmImplementation.DES);
    kic.setCipheringAlgorithmMode(CipheringAlgorithmMode.TRIPLE_DES_CBC_2_KEYS);
    kic.setKeysetID((byte) 1);
    cardProfile.setKIC(kic);

    KID kid = new KID();
    kid.setAlgorithmImplementation(AlgorithmImplementation.DES);
    kid.setCertificationAlgorithmMode(CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS);
    kid.setKeysetID((byte) 1);
    cardProfile.setKID(kid);

    SPI spi = new SPI();
    CommandSPI commandSPI = new CommandSPI();
    commandSPI.setCertificationMode(CertificationMode.CC);
    commandSPI.setCiphered(cipher);
    commandSPI.setSynchroCounterMode(synchroCounterMode);
    spi.setCommandSPI(commandSPI);

    ResponseSPI responseSPI = new ResponseSPI();
    responseSPI.setCiphered(cipher);
    responseSPI.setPoRCertificateMode(CertificationMode.CC);
    responseSPI.setPoRMode(PoRMode.REPLY_ALWAYS);
    responseSPI.setPoRProtocol(PoRProtocol.SMS_SUBMIT);
    spi.setResponseSPI(responseSPI);
    cardProfile.setSPI(spi);

    cardProfile.setSPI(spi);

    return cardProfile;
  }

  @Before
  public void setup() throws Exception {
    System.setProperty(SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "debug");
    System.setProperty("java.util.logging.ConsoleHandler.level", "FINEST");
    /*
     * Adding security provider - it will do all security job
     */
    Security.addProvider(new BouncyCastleProvider());

    /*
     * Creating card profile - for each service(with unique TAR)
     */
    CardProfile cardProfile = createProfile();

    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    cipheringKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };
    signatureKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };
  }

  @Test
  public void should_create_and_recover_command_packet_with_no_security() throws Exception {
    /*
     * Creating card profile - for each service (with unique TAR)
     */
    CardProfile cardProfile = createProfile();
    cardProfile.setTransportProtocol(TransportProtocol.CAT_TP);

    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    /*
     * Data to be sent to applet. Commonly it is a APDU command for Remote File Management Applet.
     * Or RAM Applet.
     */
    byte[] data = new byte[]{ 1, 2, 3, 4, 5 };
    byte[] counter = new byte[]{ 0, 0, 0, 0, 2 };

    /*
     * Security keys. Mostly produced from master keys. See ICCIDKeyGenerator.
     */
    byte[] cipheringKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };
    byte[] signatureKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };

    byte[] packet = packetBuilder.buildCommandPacket(data, counter, cipheringKey, signatureKey);

    CommandPacket recoveredPacket = packetBuilder.recoverCommandPacket(packet, cipheringKey, signatureKey);

    Assert.assertEquals(cardProfile.getKIC(), recoveredPacket.getHeader().getKIC());
    Assert.assertEquals(cardProfile.getKID(), recoveredPacket.getHeader().getKID());
    Assert.assertArrayEquals(cardProfile.getTAR(), recoveredPacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0, 0, 0, 0, 0 }, recoveredPacket.getHeader().getCounter());
    Assert.assertArrayEquals(new byte[]{ 1, 2, 3, 4, 5 }, recoveredPacket.getData());
  }

  @Test
  public void should_build_command_packet_no_security() throws Exception {
    byte[] data = new byte[]{ (byte) 0xaa, (byte) 0xbb };
    byte[] tar = new byte[]{ 0x01, 0x02, 0x03 };
    CardProfile cardProfile = new CardProfile();
    cardProfile.setTransportProtocol(TransportProtocol.SMS_PP);
    SPI spi = new SPI();
    // No RC, CC or DS, No Ciphering
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x00));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x22));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x00));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.NO_SECURITY, (byte) 0x00));
    cardProfile.setTAR(tar);
    cardProfile.setSignatureAlgorithm(SignatureManager.AES_CMAC_64);
    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);
    byte[] commandBytes = packetBuilder.buildCommandPacket(data, null, null, null);

    Assert.assertArrayEquals(
        new byte[]{ (byte) 0x00, (byte) 0x10, (byte) 0x0d, (byte) 0x00, (byte) 0x22, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x02, (byte) 0x03, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xaa, (byte) 0xbb },
        commandBytes);
  }

  @Test
  public void should_build_command_packet_des() throws Exception {
    byte[] data = Hex.decode("A0A40000022F05A0D6000001AA");
    byte[] tar = new byte[]{ (byte) 0xb0, (byte) 0x00, (byte) 0x10 };
    byte[] counter = new byte[]{ 0, 0, 0, (byte) 0x15, (byte) 0x6c };
    byte[] cipheringKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    byte[] signatureKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    CardProfile cardProfile = new CardProfile();
    cardProfile.setTransportProtocol(TransportProtocol.SMS_PP);
    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x12));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x21));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x10));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.CC, (byte) 0x15));
    cardProfile.setTAR(tar);
    cardProfile.setSignatureAlgorithm(SignatureManager.DES_MAC8_ISO9797_M1);
    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);
    byte[] commandBytes = packetBuilder.buildCommandPacket(data, counter, cipheringKey, signatureKey);

    Assert.assertArrayEquals(Hex.decode("00231512211015B00010000000156C008C75DF0CCB3B7628A0A40000022F05A0D6000001AA"), commandBytes);
  }

  @Test
  public void should_build_command_packet_aes() throws Exception {
    byte[] data = new byte[]{ (byte) 0xaa, (byte) 0xbb };
    byte[] counter = new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 };
    byte[] tar = new byte[]{ 0x01, 0x02, 0x03 };
    CardProfile cardProfile = new CardProfile();
    cardProfile.setTransportProtocol(TransportProtocol.SMS_PP);
    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x06));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x21));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x12));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.CC, (byte) 0x12));
    cardProfile.setTAR(tar);
    cardProfile.setSignatureAlgorithm(SignatureManager.AES_CMAC_64);
    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);
    byte[] cipheringKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    byte[] signatureKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

    byte[] commandBytes = packetBuilder.buildCommandPacket(data, counter, cipheringKey, signatureKey);

    Assert.assertArrayEquals(
        new byte[]{ (byte) 0x00, (byte) 0x18, (byte) 0x15, (byte) 0x06, (byte) 0x21, (byte) 0x12, (byte) 0x12, (byte) 0x01,
            (byte) 0x02, (byte) 0x03, (byte) 0x48, (byte) 0x14, (byte) 0xCE, (byte) 0x84, (byte) 0xCB, (byte) 0xDE,
            (byte) 0xBC, (byte) 0x1A, (byte) 0x0D, (byte) 0xF2, (byte) 0x0A, (byte) 0x5E, (byte) 0xE2, (byte) 0x0E,
            (byte) 0x74, (byte) 0xC6 },
        commandBytes);
  }

  @Test
  public void should_build_command_packet_aes_cat_tp() throws Exception {
    byte[] data = new byte[]{ (byte) 0xaa, (byte) 0xbb };
    byte[] counter = new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 };
    byte[] tar = new byte[]{ 0x01, 0x02, 0x03 };
    CardProfile cardProfile = new CardProfile();
    cardProfile.setTransportProtocol(TransportProtocol.CAT_TP);
    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x06));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x21));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x12));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.CC, (byte) 0x12));
    cardProfile.setTAR(tar);
    cardProfile.setSignatureAlgorithm(SignatureManager.AES_CMAC_64);
    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);
    byte[] cipheringKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    byte[] signatureKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

    byte[] commandBytes = packetBuilder.buildCommandPacket(data, counter, cipheringKey, signatureKey);

    Assert.assertArrayEquals(
        new byte[]{ (byte) 0x01, (byte) 0x18, (byte) 0x15, (byte) 0x06, (byte) 0x21, (byte) 0x12, (byte) 0x12, (byte) 0x01,
            (byte) 0x02, (byte) 0x03, (byte) 0xE6, (byte) 0x68, (byte) 0x98, (byte) 0x20, (byte) 0x13, (byte) 0x08,
            (byte) 0xDA, (byte) 0x27, (byte) 0xD2, (byte) 0xA8, (byte) 0xF2, (byte) 0x31, (byte) 0x45, (byte) 0xA6,
            (byte) 0xF7, (byte) 0xC3 },
        commandBytes);
  }

  @Test
  public void should_build_large_command_packet_aes() throws Exception {
    byte[] data = new byte[256];
    for (int i = 0; i < data.length; i++) {
      data[i] = (byte) (i % 256);
    }
    byte[] counter = new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 };
    byte[] tar = new byte[]{ 0x01, 0x02, 0x03 };
    CardProfile cardProfile = new CardProfile();
    cardProfile.setTransportProtocol(TransportProtocol.SMS_PP);
    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x06));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x21));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x12));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.CC, (byte) 0x12));
    cardProfile.setTAR(tar);
    cardProfile.setSignatureAlgorithm(SignatureManager.AES_CMAC_64);
    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);
    byte[] cipheringKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    byte[] signatureKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    byte[] commandBytes = packetBuilder.buildCommandPacket(data, counter, cipheringKey, signatureKey);
    Assert.assertEquals(
        "01181506211212010203A73BAEB588B7B3B6C0BB9C2FEFAE845A9FADB52FF04ED32607E1CFE6EAA8BDC990B8F0683FB6526FABCA13B1CCB0E11C988F891A9B3B39C815D71F8AE0B279D680916FA0D861D788148B503B5FE332EA4D3FC152061DE47B3F96C28A2112EDE44D9EAE8DCFF7B1CDB6F7EA2C73649E41ABFAA10B8B5A89FC8C0DD9E044EE923F92B81DB72A08025FCEB2387D7DA1DCB7BDFE9590687B91B8D227E3596D4F1C49B878590C0A2A8EB054A8BF5ACA7B74405B996DBEEB16B2CC816D5788F43F128D46035108FAC047D9E621F23E466A705E4280E1061A9FB59FE3E2AA3B1DC02F9844263CD8CFA89405A7160B0D98275AD4EE5A88A4FCBD06D36837CC3596B5E9B824C931A43DF4FAD1BD245520A0E2CAE3",
        Util.toHexString(commandBytes));
  }

  @Test
  public void should_recover_command_packet() throws Exception {
    byte[] tar = new byte[]{ 0x01, 0x02, 0x03 };
    CardProfile cardProfile = new CardProfile();
    cardProfile.setTransportProtocol(TransportProtocol.SMS_PP);
    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x06));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x21));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x12));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.CC, (byte) 0x12));
    cardProfile.setTAR(tar);
    cardProfile.setSignatureAlgorithm(SignatureManager.AES_CMAC_64);
    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] cipheringKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    byte[] signatureKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

    byte[] commandPacketBytes = new byte[]{ 0x00, 0x18, 0x15, 0x06, 0x21, 0x12, 0x12, 0x01, 0x02, 0x03, 0x48, 0x14, (byte) 0xce, (byte) 0x84, (byte) 0xcb, (byte) 0xde, (byte) 0xbc, 0x1a, 0x0d, (byte) 0xf2, 0x0a, 0x5e, (byte) 0xe2, 0x0e, 0x74, (byte) 0xc6 };
    CommandPacket commandPacket = packetBuilder.recoverCommandPacket(commandPacketBytes, cipheringKey, signatureKey);

    Assert.assertEquals("KIC [keysetID=1, cipheringAlgorithmMode=AES_CBC, algorithmImplementation=AES]", commandPacket.getHeader().getKIC().toString());
    Assert.assertEquals("KID [keysetID=1, certificationAlgorithmMode=AES_CMAC, algorithmImplementation=AES]", commandPacket.getHeader().getKID().toString());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x01, 0x02, 0x03 }, commandPacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 }, commandPacket.getHeader().getCounter());
    Assert.assertEquals(0x00, commandPacket.getHeader().getPaddingCounter());
    Assert.assertArrayEquals(new byte[]{ (byte) 0xaa, (byte) 0xbb }, commandPacket.getData());
  }

  @Test
  public void should_recover_command_packet_aes() throws Exception {
    byte[] cardSecurity = new byte[] { (byte) 0x16, (byte) 0x00, (byte) 0x12, (byte) 0x12 , (byte) 0x00, (byte) 0x00, (byte) 0x00};
    CardProfile cardProfile = CardProfileCoder.encode(cardSecurity);
    cardProfile.setTransportProtocol(TransportProtocol.SMS_PP);
    // cardProfile.setSignatureAlgorithm(SignatureManager.AES_CMAC_64);
    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);
    byte[] cipheringKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    byte[] signatureKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

    byte[] commandPacketBytes = new byte[]{ 0x00, 0x18, 0x15, 0x06, 0x21, 0x12, 0x12, 0x01, 0x02, 0x03, 0x48, 0x14, (byte) 0xce, (byte) 0x84, (byte) 0xcb, (byte) 0xde, (byte) 0xbc, 0x1a, 0x0d, (byte) 0xf2, 0x0a, 0x5e, (byte) 0xe2, 0x0e, 0x74, (byte) 0xc6 };
    CommandPacket commandPacket = packetBuilder.recoverCommandPacket(commandPacketBytes, cipheringKey, signatureKey);

    Assert.assertEquals("KIC [keysetID=1, cipheringAlgorithmMode=AES_CBC, algorithmImplementation=AES]", commandPacket.getHeader().getKIC().toString());
    Assert.assertEquals("KID [keysetID=1, certificationAlgorithmMode=AES_CMAC, algorithmImplementation=AES]", commandPacket.getHeader().getKID().toString());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x01, 0x02, 0x03 }, commandPacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 }, commandPacket.getHeader().getCounter());
    Assert.assertEquals(0x00, commandPacket.getHeader().getPaddingCounter());
    Assert.assertArrayEquals(new byte[]{ (byte) 0xaa, (byte) 0xbb }, commandPacket.getData());
  }

  @Test
  public void should_recover_large_command_packet() throws Exception {
    byte[] tar = new byte[]{ 0x01, 0x02, 0x03 };
    CardProfile cardProfile = new CardProfile();
    cardProfile.setTransportProtocol(TransportProtocol.SMS_PP);
    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x06));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x21));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x12));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.CC, (byte) 0x12));
    cardProfile.setTAR(tar);
    cardProfile.setSignatureAlgorithm(SignatureManager.AES_CMAC_64);
    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] cipheringKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    byte[] signatureKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

    byte[] commandPacketBytes = Hex.decode(
        "01181506211212010203A73BAEB588B7B3B6C0BB9C2FEFAE845A9FADB52FF04ED32607E1CFE6EAA8BDC990B8F0683FB6526FABCA13B1CCB0E11C988F891A9B3B39C815D71F8AE0B279D680916FA0D861D788148B503B5FE332EA4D3FC152061DE47B3F96C28A2112EDE44D9EAE8DCFF7B1CDB6F7EA2C73649E41ABFAA10B8B5A89FC8C0DD9E044EE923F92B81DB72A08025FCEB2387D7DA1DCB7BDFE9590687B91B8D227E3596D4F1C49B878590C0A2A8EB054A8BF5ACA7B74405B996DBEEB16B2CC816D5788F43F128D46035108FAC047D9E621F23E466A705E4280E1061A9FB59FE3E2AA3B1DC02F9844263CD8CFA89405A7160B0D98275AD4EE5A88A4FCBD06D36837CC3596B5E9B824C931A43DF4FAD1BD245520A0E2CAE3");
    CommandPacket commandPacket = packetBuilder.recoverCommandPacket(commandPacketBytes, cipheringKey, signatureKey);

    Assert.assertEquals("KIC [keysetID=1, cipheringAlgorithmMode=AES_CBC, algorithmImplementation=AES]", commandPacket.getHeader().getKIC().toString());
    Assert.assertEquals("KID [keysetID=1, certificationAlgorithmMode=AES_CMAC, algorithmImplementation=AES]", commandPacket.getHeader().getKID().toString());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x01, 0x02, 0x03 }, commandPacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 }, commandPacket.getHeader().getCounter());
    Assert.assertEquals(0x02, commandPacket.getHeader().getPaddingCounter());
    Assert.assertEquals(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
        Util.toHexString(commandPacket.getData()));
  }

  @Test
  public void should_create_and_recover_response_packet_with_no_security() throws Exception {
    /*
     * Creating card profile - for each service (with unique TAR)
     */
    CardProfile cardProfile = createProfile();
    cardProfile.setTransportProtocol(TransportProtocol.CAT_TP);

    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    /*
     * Data sent by applet as response.
     */
    byte[] data = new byte[]{ 1, 2, 3, 4, 5 };
    byte[] counter = new byte[]{ 0, 0, 0, 0, 2 };

    /*
     * Security keys. Mostly produced from master keys. See ICCIDKeyGenerator.
     */
    byte[] cipheringKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };
    byte[] signatureKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };

    ResponsePacketStatus responsePacketStatus = ResponsePacketStatus.CNTR_LOW;

    byte[] packet = packetBuilder.buildResponsePacket(data, counter, cipheringKey, signatureKey, responsePacketStatus);

    ResponsePacket recoveredPacket = packetBuilder.recoverResponsePacket(packet, cipheringKey, signatureKey);

    Assert.assertArrayEquals(cardProfile.getTAR(), recoveredPacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0, 0, 0, 0, 0 }, recoveredPacket.getHeader().getCounter());
    Assert.assertEquals((byte) 0x00, recoveredPacket.getHeader().getPaddingCounter());
    Assert.assertEquals(ResponsePacketStatus.CNTR_LOW, recoveredPacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ 1, 2, 3, 4, 5 }, recoveredPacket.getData());
  }

  @Test
  public void should_recover_response_packet() throws Exception {
    byte[] responsePacketBytes = new byte[]{ 0x00, 0x0e, 0x0a, (byte) 0xb0, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x6e, 0x00 };
    ResponsePacket responsePacket = packetBuilder.recoverResponsePacket(responsePacketBytes, cipheringKey, signatureKey);

    Assert.assertEquals(ResponsePacketStatus.POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0xb0, 0x00, 0x10 }, responsePacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x01 }, responsePacket.getHeader().getCounter());
    Assert.assertEquals(0x00, responsePacket.getHeader().getPaddingCounter());
    Assert.assertArrayEquals(new byte[]{ 0x01, 0x6e, 0x00 }, responsePacket.getData());
  }

  @Test
  public void should_recover_response_packet_with_extra_data() throws Exception {
    // 027100000E0AB0011F000000000100000A9000
    byte[] responsePacketBytes = Hex.decode("000E0AB0011F000000000100000A9000");
    ResponsePacket responsePacket = packetBuilder.recoverResponsePacket(responsePacketBytes, cipheringKey, signatureKey);

    Assert.assertEquals(ResponsePacketStatus.POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0xB0, 0x01, 0x1F }, responsePacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x01 }, responsePacket.getHeader().getCounter());
    Assert.assertEquals(0x00, responsePacket.getHeader().getPaddingCounter());
    Assert.assertArrayEquals(new byte[]{ 0x0a, (byte) 0x90, 0x00 }, responsePacket.getData());
  }

  @Test
  public void should_build_response_packet() throws Exception {
    byte[] data = new byte[]{ (byte) 0x01, (byte) 0x90, (byte) 0x00 };
    byte[] responsePacketBytes = packetBuilder.buildResponsePacket(data, null, cipheringKey, signatureKey, ResponsePacketStatus.CIPHERING_ERROR);

    Assert.assertArrayEquals(
        new byte[]{ (byte) 0x00, 0x0E, 0x0A, (byte) 0xB0, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, (byte) 0x90, 0x00 },
        responsePacketBytes);
  }

  @Test
  public void should_build_sms_pp_response_packet_cc_aes_cmac_64() throws Exception {
    CardProfile cardProfile = createProfileAes(TransportProtocol.SMS_PP, false, SynchroCounterMode.NO_COUNTER);

    // The AES signature key
    final byte[] signatureKey = new byte[]{ (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16 };

    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] data = new byte[]{ (byte) 0xab, (byte) 0x07, (byte) 0x80, (byte) 0x01, (byte) 0x01, (byte) 0x23, (byte) 0x02, (byte) 0x90, (byte) 0x00 };
    byte[] counter = new byte[]{ (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
    byte[] responsePacketBytes = packetBuilder.buildResponsePacket(data, counter, null, signatureKey, ResponsePacketStatus.POR_OK);

    Assert.assertArrayEquals(
        new byte[]{ (byte) 0x00, (byte) 0x1c, (byte) 0x12,
            (byte) 0x00, (byte) 0x00, (byte) 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00,
            (byte) 0x00,
            (byte) 0x00,
            (byte) 0xf5, (byte) 0xab, (byte) 0x90, (byte) 0xfe, (byte) 0x3a, (byte) 0xab, (byte) 0xb6, (byte) 0xc3,
            (byte) 0xab, (byte) 0x07, (byte) 0x80, (byte) 0x01, (byte) 0x01, (byte) 0x23, (byte) 0x02, (byte) 0x90, (byte) 0x00 },
        responsePacketBytes);
  }

  @Test
  public void should_recover_response_packet_cc_aes_cmac_64_with_lengths_and_udhl() throws Exception {
    CardProfile cardProfile = createProfileAes(TransportProtocol.SMS_PP, false, SynchroCounterMode.NO_COUNTER);
    // The AES signature key
    final byte[] signatureKey = new byte[]{ (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16 };
    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] responsePacketBytes = Hex.decode("001C1200000100000000000000F5AB90FE3AABB6C3AB0780010123029000");
    ResponsePacket responsePacket = packetBuilder.recoverResponsePacket(responsePacketBytes, null, signatureKey);

    Assert.assertEquals(ResponsePacketStatus.POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x00, 0x00, 0x01 }, responsePacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 }, responsePacket.getHeader().getCounter());
    Assert.assertEquals(0x00, responsePacket.getHeader().getPaddingCounter());
    Assert.assertEquals(POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0xab, (byte) 0x07, (byte) 0x80, (byte) 0x01, (byte) 0x01, (byte) 0x23, (byte) 0x02, (byte) 0x90, (byte) 0x00 },
        responsePacket.getData());
  }

  @Test
  public void should_recover_response() throws Exception {
    CardProfile cardProfile = createProfileDes(TransportProtocol.SMS_PP, true, SynchroCounterMode.COUNTER_REPLAY_OR_CHECK_INCREMENT);
    cardProfile.getSPI().setCommandSPI(CommandSPICoder.encode((byte) 0x16));
    cardProfile.getSPI().setResponseSPI(ResponseSPICoder.encode((byte) 0x11));
    final byte[] cipherKey = Hex.decode("FBF4F3446B85A11BA5C2203425BABE4E");
    final byte[] signatureKey = Hex.decode("82D42649147EE723260F957786EDB172");
    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] responsePacketBytes = Hex.decode("00140A00000048B0E9A947EEE0A66D05D526A6E7EB44");
    ResponsePacket responsePacket = packetBuilder.recoverResponsePacket(responsePacketBytes, cipherKey, signatureKey);

    Assert.assertEquals(ResponsePacketStatus.POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x00, 0x00, 0x00 }, responsePacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x1a }, responsePacket.getHeader().getCounter());
    Assert.assertEquals(0x06, responsePacket.getHeader().getPaddingCounter());
    Assert.assertEquals(POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x01, (byte) 0x6e, (byte) 0x00 },
        responsePacket.getData());
  }

  @Test
  public void should_recover_response_packet_cat_tp() throws Exception {
    CardProfile cardProfile = createProfile();
    cardProfile.setTransportProtocol(TransportProtocol.CAT_TP);
    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] responsePacketBytes = Hex.decode("020e0ab0000100000000000000026101");
    ResponsePacket responsePacket = packetBuilder.recoverResponsePacket(responsePacketBytes, null, signatureKey);

    Assert.assertEquals(ResponsePacketStatus.POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0xb0, 0x00, 0x01 }, responsePacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 }, responsePacket.getHeader().getCounter());
    Assert.assertEquals(0x00, responsePacket.getHeader().getPaddingCounter());
    Assert.assertEquals(POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x02, (byte) 0x61, (byte) 0x01 }, responsePacket.getData());
  }

  @Ignore
  @Test
  public void should_build_response_packet_cc_aes_cmac_64_sms_pp() throws Exception {
    CardProfile cardProfile = createProfileAes(TransportProtocol.SMS_PP, false, SynchroCounterMode.NO_COUNTER);

    // The AES signature key
    final byte[] signatureKey = new byte[]{ (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16 };

    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] data = new byte[]{ (byte) 0xab, (byte) 0x07, (byte) 0x80, (byte) 0x01, (byte) 0x01, (byte) 0x23, (byte) 0x02, (byte) 0x90, (byte) 0x00 };
    byte[] counter = new byte[]{ (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
    byte[] responsePacketBytes = packetBuilder.buildResponsePacket(data, counter, null, signatureKey, ResponsePacketStatus.POR_OK);

    Assert.assertArrayEquals(
        new byte[]{ (byte) 0x00, (byte) 0x1c, (byte) 0x12, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
            0x00,
            (byte) 0x4e, (byte) 0x5e, (byte) 0x7f, (byte) 0x13, (byte) 0x21, (byte) 0xdc, (byte) 0x96, (byte) 0x8b,
            (byte) 0xab, 0x07, (byte) 0x80, 0x01, 0x01, 0x23, 0x02, (byte) 0x90, 0x00 },
        responsePacketBytes);
  }

  @Test
  public void should_build_response_packet_cc_aes_cmac_64_with_lengths_and_udhl_ciphered_and_recover() throws Exception {
    CardProfile cardProfile = createProfileAes(TransportProtocol.SMS_PP, true, SynchroCounterMode.COUNTER_REPLAY_OR_CHECK);

    // The AES signature key
    final byte[] signatureKey = new byte[]{ (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16 };
    final byte[] cipheringKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] data = new byte[]{ (byte) 0x90, (byte) 0x00 };
    byte[] counter = new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05 };
    byte[] responsePacketBytes = packetBuilder.buildResponsePacket(data, counter, cipheringKey, signatureKey, ResponsePacketStatus.POR_OK);

    ResponsePacket responsePacket = packetBuilder.recoverResponsePacket(responsePacketBytes, cipheringKey, signatureKey);

    Assert.assertEquals(ResponsePacketStatus.POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x00, 0x00, 0x01 }, responsePacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05 }, responsePacket.getHeader().getCounter());
    Assert.assertEquals(0x0f, responsePacket.getHeader().getPaddingCounter());
    Assert.assertEquals(POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x90, (byte) 0x00 }, responsePacket.getData());
  }

}
