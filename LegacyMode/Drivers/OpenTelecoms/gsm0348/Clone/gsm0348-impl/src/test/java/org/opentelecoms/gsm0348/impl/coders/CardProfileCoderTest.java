package org.opentelecoms.gsm0348.impl.coders;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.opentelecoms.gsm0348.api.model.CardProfile;
import org.opentelecoms.gsm0348.api.model.CertificationMode;
import org.opentelecoms.gsm0348.api.model.PoRMode;
import org.opentelecoms.gsm0348.api.model.PoRProtocol;
import org.opentelecoms.gsm0348.api.model.SPI;
import org.opentelecoms.gsm0348.api.model.SynchroCounterMode;
import org.opentelecoms.gsm0348.impl.crypto.SignatureManager;

public class CardProfileCoderTest {

  @Test
  public void test_no_security_card_profile_encoding() throws Exception {

    byte[] no_security_card_profile = new byte[7];

    CardProfile cardProfile = CardProfileCoder.encode(no_security_card_profile);

    assertEquals(0x00, cardProfile.getKIC().getKeysetID());
    assertEquals(0x00, cardProfile.getKID().getKeysetID());
    assertEquals((byte) 0x00, KICCoder.decode(cardProfile.getKIC()));
    assertEquals((byte) 0x00, KIDCoder.decode(cardProfile.getKID()));
    assertArrayEquals(new byte[]{ (byte) 0x00, (byte) 0x00, (byte) 0x00 }, cardProfile.getTAR());
  }

  @Test
  public void test_security_card_profile_encoding() throws Exception {

    byte[] card_profile = new byte[]{ 0x06, 0x21, 0x12, 0x12, (byte) 0xb0, 0x00, 0x10 };

    CardProfile cardProfile = CardProfileCoder.encode(card_profile);

    assertEquals(CertificationMode.CC, cardProfile.getSPI().getCommandSPI().getCertificationMode());
    assertEquals(SynchroCounterMode.NO_COUNTER, cardProfile.getSPI().getCommandSPI().getSynchroCounterMode());
    assertEquals(PoRMode.REPLY_ALWAYS, cardProfile.getSPI().getResponseSPI().getPoRMode());
    assertEquals(CertificationMode.NO_SECURITY, cardProfile.getSPI().getResponseSPI().getPoRCertificateMode());
    assertEquals(PoRProtocol.SMS_SUBMIT, cardProfile.getSPI().getResponseSPI().getPoRProtocol());
    assertEquals(0x01, cardProfile.getKIC().getKeysetID());
    assertEquals(0x01, cardProfile.getKID().getKeysetID());
    assertEquals((byte) 0x12, KICCoder.decode(cardProfile.getKIC()));
    assertEquals((byte) 0x12, KIDCoder.decode(cardProfile.getKID()));
    assertArrayEquals(new byte[]{ (byte) 0xb0, (byte) 0x00, (byte) 0x10 }, cardProfile.getTAR());
  }

  @Test
  public void test_security_card_profile_encoding_aes_cmac_64() throws Exception {

    byte[] card_profile = new byte[] { (byte) 0x16, (byte) 0x00, (byte) 0x12, (byte) 0x12 , (byte) 0xb0, (byte) 0x00, (byte) 0x10};

    CardProfile cardProfile = CardProfileCoder.encode(card_profile);

    assertEquals(CertificationMode.CC, cardProfile.getSPI().getCommandSPI().getCertificationMode());
    assertEquals(SynchroCounterMode.COUNTER_REPLAY_OR_CHECK, cardProfile.getSPI().getCommandSPI().getSynchroCounterMode());
    assertEquals(PoRMode.NO_REPLY, cardProfile.getSPI().getResponseSPI().getPoRMode());
    assertEquals(CertificationMode.NO_SECURITY, cardProfile.getSPI().getResponseSPI().getPoRCertificateMode());
    assertEquals(PoRProtocol.SMS_DELIVER_REPORT, cardProfile.getSPI().getResponseSPI().getPoRProtocol());
    assertEquals(0x01, cardProfile.getKIC().getKeysetID());
    assertEquals(0x01, cardProfile.getKID().getKeysetID());
    assertEquals((byte) 0x12, KICCoder.decode(cardProfile.getKIC()));
    assertEquals((byte) 0x12, KIDCoder.decode(cardProfile.getKID()));
    assertArrayEquals(new byte[]{ (byte) 0xb0, (byte) 0x00, (byte) 0x10 }, cardProfile.getTAR());

    assertEquals(SignatureManager.AES_CMAC_64, cardProfile.getSignatureAlgorithm());
  }

  @Test
  public void test_no_security_card_profile_decoding() throws Exception {

    CardProfile cardProfile = new CardProfile();
    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x00));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x00));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x00));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.NO_SECURITY, (byte) 0x00));
    cardProfile.setTAR(new byte[]{ (byte) 0x00, (byte) 0x00, (byte) 0x00 });

    byte[] bytes = CardProfileCoder.decode(cardProfile);

    assertArrayEquals(new byte[]{ (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }, bytes);
  }

  @Test
  public void test_security_card_profile_decoding() throws Exception {

    CardProfile cardProfile = new CardProfile();
    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x06));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x21));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x12));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.CC, (byte) 0x12));
    cardProfile.setTAR(new byte[]{ (byte) 0xb0, (byte) 0x00, (byte) 0x10 });

    byte[] bytes = CardProfileCoder.decode(cardProfile);

    assertArrayEquals(new byte[]{ (byte) 0x06, (byte) 0x21, (byte) 0x12, (byte) 0x12, (byte) 0xb0, (byte) 0x00, (byte) 0x10 }, bytes);
  }

}
