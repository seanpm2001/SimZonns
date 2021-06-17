package org.opentelecoms.gsm0348.impl;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.commons.beanutils.BeanUtils;
import org.opentelecoms.gsm0348.api.Gsm0348Exception;
import org.opentelecoms.gsm0348.api.PacketBuilder;
import org.opentelecoms.gsm0348.api.PacketBuilderConfigurationException;
import org.opentelecoms.gsm0348.api.Util;
import org.opentelecoms.gsm0348.api.model.CardProfile;
import org.opentelecoms.gsm0348.api.model.CertificationMode;
import org.opentelecoms.gsm0348.api.model.CommandPacket;
import org.opentelecoms.gsm0348.api.model.CommandPacketHeader;
import org.opentelecoms.gsm0348.api.model.CommandSPI;
import org.opentelecoms.gsm0348.api.model.KIC;
import org.opentelecoms.gsm0348.api.model.KID;
import org.opentelecoms.gsm0348.api.model.ResponsePacket;
import org.opentelecoms.gsm0348.api.model.ResponsePacketHeader;
import org.opentelecoms.gsm0348.api.model.ResponsePacketStatus;
import org.opentelecoms.gsm0348.api.model.ResponseSPI;
import org.opentelecoms.gsm0348.api.model.SPI;
import org.opentelecoms.gsm0348.api.model.SynchroCounterMode;
import org.opentelecoms.gsm0348.api.model.TransportProtocol;
import org.opentelecoms.gsm0348.impl.coders.CommandSPICoder;
import org.opentelecoms.gsm0348.impl.coders.KICCoder;
import org.opentelecoms.gsm0348.impl.coders.KIDCoder;
import org.opentelecoms.gsm0348.impl.coders.ResponsePacketStatusCoder;
import org.opentelecoms.gsm0348.impl.coders.ResponseSPICoder;
import org.opentelecoms.gsm0348.impl.crypto.CipheringManager;
import org.opentelecoms.gsm0348.impl.crypto.SignatureManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketBuilderImpl implements PacketBuilder {

  private static final Logger LOGGER = LoggerFactory.getLogger(PacketBuilderImpl.class);

  private static final int SPI_SIZE = 2;
  private static final int KIC_SIZE = 1;
  private static final int KID_SIZE = 1;
  private static final int TAR_SIZE = 3;
  private static final int COUNTER_SIZE = 5;
  private static final int PADDING_COUNTER_SIZE = 1;
  private static final int MINIMUM_COMMAND_PACKET_SIZE = 16;
  private static final int MINIMUM_RESPONSE_PACKET_SIZE = 13;
  private static final int HEADER_SIZE_WITHOUT_SIGNATURE = SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE + COUNTER_SIZE + PADDING_COUNTER_SIZE;
  private static final int STATUS_CODE_SIZE = 1;
  private static final int RESPONSE_HEADER_SIZE_WITHOUT_SIGNATURE = TAR_SIZE + COUNTER_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE;

  private static final byte[] SMS_CPI = new byte[]{ 0x02, 0x70, 0x00 };
  private static final byte[] SMS_RPI = new byte[]{ 0x02, 0x71, 0x00 };

  private static final byte[] CPI = new byte[]{ 0x01 };
  private static final byte[] RPI = new byte[]{ 0x02 };
  private static final byte[] IPI = new byte[]{ 0x03 };

  private static final byte[] USSD_CPI = new byte[]{ 0x03 };
  private static final byte[] USSD_RPI = new byte[]{ 0x04 };

  private static final byte[] BYTES_NULL = new byte[]{};

  private TransportProtocol transportProtocol;

  private boolean commandPacketCiphering;
  private boolean commandPacketSigning;
  private boolean responsePacketCiphering;
  private boolean responsePacketSigning;
  private boolean usingCounter;
  private CardProfile cardProfile;
  private String cipheringAlgorithmName;
  private String signatureAlgorithmName;
  private int cipherBlockSize;
  private int signatureSize;

  // https://www.etsi.org/deliver/etsi_ts/131100_131199/131115/06.05.00_60/ts_131115v060500p.pdf
  // https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1811
  // http://www.3gpp2.org/Public_html/Specs/C.S0078-0_v1.0_061106.pdf

  // SMS: CPI is mapped to IEIa defined in TS 23.040 and shall be set to '70'.
  // SMS: CPL is always 2 octets, not encoded to BER-TLV length
  // SMS: CHI is null
  // SMS: CHL is always 1 octet, not encoded to BER-TLV length
  // SMS: Secured Data including padding
  // SMS: RPI is mapped to IEIa defined in TS 23.040 and shall be set to '71'.

  // SMS_PP Command
  // It is recognised that most checksum algorithms require input data in modulo 8 length.
  // In order to achieve a modulo 8 length of the data before the RC/CC/DS field in the Command Header
  // the Length of the Command Packet and the Length of the Command Header shall be included in the calculation of RC/CC/DS if used.
  // These fields shall not be ciphered.

  // SMS_PP Response
  // In order to achieve a modulo 8 length of the data before the RC/CC/DS field in the Response Header, the Length of the Response Packet,
  // the Length of the Response Header and the three preceding octets(UDHL, IEIa and IEIDLa defined in TS 23.040 [3])
  // shall be included in the calculation of RC/CC/DS if used. These fields shall not be ciphered

  // CAT_TP: CPI is '01'.
  // CAT_TP: CHI is null
  // CAT_TP: CPI, CPL and CHL shall be included in the calculation of the RC/CC/DS

  // CAT_TP: RPI is '02'.
  // CAT_TP: RHI is null
  // CAT_TP: RPI, RPL and RHL shall be included in the calculation of the RC/CC/DS

  // TCPIP: CPI is '01'.
  // TCPIP: CHI is null
  // TCPIP: CPI, CPL and CHL shall be included in the calculation of the RC/CC/DS

  // TCPIP: RPI is '02'.
  // TCPIP: RHI is null
  // TCPIP: RPI, RPL and RHL shall be included in the calculation of the RC/CC/DS

  // TCPIP: IPI is '03'. (Identification Packet Identifier)
  // TCPIP: IPL is BER-TLV
  // TCPIP: Identification data tag
  // TCPIP: Length of identification data string: 1 octet
  // TCPIP: Identification data string

  public PacketBuilderImpl() {
  }

  public PacketBuilderImpl(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    setProfile(cardProfile);
  }

  private CardProfile copyProfile(CardProfile profile) throws Gsm0348Exception {
    try {
      return (CardProfile) BeanUtils.cloneBean(profile);
    } catch (Exception ex) {
      throw new Gsm0348Exception(ex);
    }
  }

  private void verifyProfile(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    if (cardProfile == null) {
      throw new PacketBuilderConfigurationException("CardProfile cannot be null");
    }

    if (cardProfile.getTransportProtocol() == null) {
      throw new PacketBuilderConfigurationException("Transport protocol cannot be null");
    }

    if (cardProfile.getSPI() == null) {
      throw new PacketBuilderConfigurationException("SPI cannot be null");
    }
    if (cardProfile.getSPI().getCommandSPI() == null) {
      throw new PacketBuilderConfigurationException("CommandSPI cannot be null");
    }
    if (cardProfile.getSPI().getCommandSPI().getCertificationMode() == null) {
      throw new PacketBuilderConfigurationException("CommandSPI CertificationMode cannot be null");
    }
    if (cardProfile.getSPI().getCommandSPI().getSynchroCounterMode() == null) {
      throw new PacketBuilderConfigurationException("CommandSPI SynchroCounterMode cannot be null");
    }
    if (cardProfile.getSPI().getResponseSPI() == null) {
      throw new PacketBuilderConfigurationException("ResponseSPI cannot be null");
    }
    if (cardProfile.getSPI().getResponseSPI().getPoRCertificateMode() == null) {
      throw new PacketBuilderConfigurationException("ResponseSPI PoRCertificateMode cannot be null");
    }
    if (cardProfile.getSPI().getResponseSPI().getPoRMode() == null) {
      throw new PacketBuilderConfigurationException("ResponseSPI PoRMode cannot be null");
    }
    if (cardProfile.getSPI().getResponseSPI().getPoRProtocol() == null) {
      throw new PacketBuilderConfigurationException("ResponseSPI PoRProtocol cannot be null");
    }

    final boolean commandCiphered = cardProfile.getSPI().getCommandSPI().isCiphered();
    if (commandCiphered) {
      if (cardProfile.getKIC() == null) {
        throw new PacketBuilderConfigurationException("KIC cannot be null for ciphered command");
      }
      if (cardProfile.getKIC().getAlgorithmImplementation() == null) {
        throw new PacketBuilderConfigurationException("KIC AlgorithmImplementation cannot be null for ciphered command");
      }
      if (cardProfile.getKIC().getCipheringAlgorithmMode() == null) {
        throw new PacketBuilderConfigurationException("KIC CipheringAlgorithmMode cannot be null for ciphered command");
      }
    }
    if (cardProfile.getKIC().getKeysetID() < 0x0 || cardProfile.getKIC().getKeysetID() > (byte) 0xf) {
      throw new PacketBuilderConfigurationException("KIC keySetID cannot be <0 and >15");
    }

    final boolean responseCiphered = cardProfile.getSPI().getResponseSPI().isCiphered();
    if (cardProfile.getKID() == null) {
      throw new PacketBuilderConfigurationException("KID cannot be null");
    }
    if (responseCiphered) {
      if (cardProfile.getKID().getAlgorithmImplementation() == null) {
        throw new PacketBuilderConfigurationException("KID AlgorithmImplementation cannot be null for ciphered response");
      }
      if (cardProfile.getKID().getCertificationAlgorithmMode() == null) {
        throw new PacketBuilderConfigurationException("KID CertificationAlgorithmMode cannot be null for ciphered response");
      }
    }
    if (cardProfile.getKID().getKeysetID() < 0x0 || cardProfile.getKID().getKeysetID() > (byte) 0xf) {
      throw new PacketBuilderConfigurationException("KID keySetID cannot be <0 and >15");
    }

    // TAR is mandatory for building, but optional for recovering
    if (cardProfile.getTAR() == null || cardProfile.getTAR().length != TAR_SIZE) {
      throw new PacketBuilderConfigurationException("TAR value null or not a 3 bytes array");
    }
  }

  private void setSigningAlgorithmName(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    final KID kid = cardProfile.getKID();
    switch (kid.getAlgorithmImplementation()) {
      case PROPRIETARY_IMPLEMENTATIONS:
      case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
        signatureAlgorithmName = cardProfile.getSignatureAlgorithm();
        if (signatureAlgorithmName == null || signatureAlgorithmName.isEmpty()) {
          throw new PacketBuilderConfigurationException(
              "In selected configuration signature algorithm name cannot be null or empty");
        }
        break;
      case DES:
        switch (kid.getCertificationAlgorithmMode()) {
          case DES_CBC:
            signatureAlgorithmName = SignatureManager.DES_MAC8_ISO9797_M1;
            break;

          case RESERVED:
            throw new PacketBuilderConfigurationException("Using reserved value for algorithm mode in KID");

          case TRIPLE_DES_CBC_2_KEYS:
          case TRIPLE_DES_CBC_3_KEYS:
            signatureAlgorithmName = SignatureManager.DES_EDE_MAC64;
            break;

          default:
            throw new PacketBuilderConfigurationException("Not implemented yet");
        }
        break;
      case AES:
        switch (kid.getCertificationAlgorithmMode()) {
          case AES_CMAC:
            final String signatureAlgorithm = cardProfile.getSignatureAlgorithm();
            if (signatureAlgorithm == null || signatureAlgorithm.isEmpty()) {
              throw new PacketBuilderConfigurationException(
                  "In selected configuration signature algorithm name cannot be null or empty");
            }
            if (!SignatureManager.AES_CMAC_32.equals(signatureAlgorithm) && !SignatureManager.AES_CMAC_64.equals(signatureAlgorithm)) {
              throw new PacketBuilderConfigurationException(
                  "For AES CMAC, the signature can only be AES_CMAC_32 or AES_CMAC_64, but was " + signatureAlgorithm);
            }
            signatureAlgorithmName = cardProfile.getSignatureAlgorithm();
            break;
          default:
            throw new PacketBuilderConfigurationException("Not implemented yet");
        }
        break;
      case CRC:
        switch (kid.getCertificationAlgorithmMode()) {
          case CRC_16:
            signatureAlgorithmName = SignatureManager.CRC_16;
            break;
          case CRC_32:
            signatureAlgorithmName = SignatureManager.CRC_32;
            break;
          case XOR_4:
            signatureAlgorithmName = SignatureManager.XOR4;
            break;
          case XOR_8:
            signatureAlgorithmName = SignatureManager.XOR8;
            break;
          default:
            throw new PacketBuilderConfigurationException(kid.getCertificationAlgorithmMode() + " is not implemented (yet)");
        }
        break;
      default:
        throw new PacketBuilderConfigurationException("Not implemented yet");
    }
    try {
      signatureSize = SignatureManager.signLength(signatureAlgorithmName);
    } catch (NoSuchAlgorithmException ex) {
      throw new PacketBuilderConfigurationException(ex);
    }
  }

  private void setCipheringAlgorithmName(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    final KIC kic = cardProfile.getKIC();
    switch (kic.getAlgorithmImplementation()) {
      case PROPRIETARY_IMPLEMENTATIONS:
      case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
        cipheringAlgorithmName = cardProfile.getCipheringAlgorithm();
        if (cipheringAlgorithmName == null || cipheringAlgorithmName.isEmpty()) {
          throw new PacketBuilderConfigurationException(
              "In selected configuration ciphering algorithm name cannot be null or empty");
        }
        break;
      case DES:
        switch (kic.getCipheringAlgorithmMode()) {
          case DES_CBC:
            cipheringAlgorithmName = "DES/CBC/NoPadding";
            break;

          case DES_ECB:
            cipheringAlgorithmName = "DES/ECB/NoPadding";
            break;

          case TRIPLE_DES_CBC_2_KEYS:
          case TRIPLE_DES_CBC_3_KEYS:
            cipheringAlgorithmName = "DESede/CBC/NoPadding";
            break;

          default:
            throw new PacketBuilderConfigurationException("Not implemented yet");
        }
        break;
      case AES:
        switch (kic.getCipheringAlgorithmMode()) {
          case AES_CBC:
            cipheringAlgorithmName = "AES/CBC/NoPadding";
            break;
          default:
            throw new PacketBuilderConfigurationException("Not implemented yet");
        }
        break;
      default:
        throw new PacketBuilderConfigurationException("Not implemented yet");
    }
    try {
      cipherBlockSize = CipheringManager.getBlockSize(cipheringAlgorithmName);
    } catch (GeneralSecurityException ex) {
      throw new PacketBuilderConfigurationException(ex);
    }
  }

  @Override
  public CardProfile getProfile() {
    try {
      return copyProfile(cardProfile);
    } catch (Gsm0348Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public void setProfile(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    verifyProfile(cardProfile);

    transportProtocol = cardProfile.getTransportProtocol();

    CommandSPI commandSPI = cardProfile.getSPI().getCommandSPI();
    ResponseSPI responseSPI = cardProfile.getSPI().getResponseSPI();

    if (commandSPI.getCertificationMode() == CertificationMode.DS) {
      throw new PacketBuilderConfigurationException("Digital signature in command packets is not supported");
    }
    if (responseSPI.getPoRCertificateMode() == CertificationMode.DS) {
      throw new PacketBuilderConfigurationException("Digital signature in response packets is not supported");
    }
    commandPacketCiphering = cardProfile.getSPI().getCommandSPI().isCiphered();
    responsePacketCiphering = cardProfile.getSPI().getResponseSPI().isCiphered();

    if (commandPacketCiphering || responsePacketCiphering) {
      setCipheringAlgorithmName(cardProfile);
    }

    commandPacketSigning = commandSPI.getCertificationMode() != CertificationMode.NO_SECURITY;
    responsePacketSigning = responseSPI.getPoRCertificateMode() != CertificationMode.NO_SECURITY;

    if (commandPacketSigning || responsePacketSigning) {
      setSigningAlgorithmName(cardProfile);
    }

    usingCounter = commandSPI.getSynchroCounterMode() != SynchroCounterMode.NO_COUNTER;
    if (!usingCounter) {
      LOGGER.debug("Counter is turned off - counter field in packet will be filled with zeroes");
    }

    try {
      this.cardProfile = copyProfile(cardProfile);
    } catch (Gsm0348Exception e) {
      throw new PacketBuilderConfigurationException("Cannot copy profile", e);
    }
  }

  @Override
  public boolean isConfigured() {
    return cardProfile != null;
  }

  private byte[] getSPI() throws CodingException {
    byte[] result = new byte[2];
    result[0] = CommandSPICoder.decode(cardProfile.getSPI().getCommandSPI());
    result[1] = ResponseSPICoder.decode(cardProfile.getSPI().getResponseSPI());
    return result;
  }

  private SPI getSPI(byte[] data) throws CodingException {
    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode(data[0]));
    spi.setResponseSPI(ResponseSPICoder.encode(data[1]));
    return spi;
  }

  @Override
  public byte[] buildCommandPacket(byte[] data, byte[] counter, byte[] cipheringKey, byte[] signatureKey)
      throws PacketBuilderConfigurationException, Gsm0348Exception {
    if (!isConfigured()) {
      throw new PacketBuilderConfigurationException("Not configured");
    }

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Creating {} command packet.\n\tData: {}\n\tCounter: {}\n\tCipheringKey: {}\n\tSigningKey: {}",
          transportProtocol
          , Util.toHexString(data)
          , Util.toHexString(counter)
          , Util.toHexString(cipheringKey)
          , Util.toHexString(signatureKey));
    }

    if (commandPacketCiphering && (cipheringKey == null)) {
      throw new PacketBuilderConfigurationException("Ciphering is enabled - ciphering key must be specified");
    }
    if (commandPacketSigning && (signatureKey == null)) {
      throw new PacketBuilderConfigurationException("Signing is enabled - signature key must be specified");
    }
    if (counter == null && usingCounter) {
      throw new PacketBuilderConfigurationException("Counter is null and required by configuration");
    }
    if (counter != null && counter.length != COUNTER_SIZE) {
      throw new PacketBuilderConfigurationException("Counter size mismatch. Current is "
          + (counter != null ? counter.length : "null") + ", required is " + COUNTER_SIZE);
    }

    try {
      LOGGER.trace("Signing: {}", responsePacketSigning);
      final int signatureLength = commandPacketSigning ? signatureSize : 0;
      LOGGER.debug("Signature length: {}", signatureLength);

      byte[] signature = new byte[signatureLength];
      byte[] dataBytes = (data == null) ? new byte[0] : data;
      byte[] counterBytes = usingCounter ? counter : new byte[COUNTER_SIZE];
      int paddingCounter = 0;

      ByteBuffer header = createHeader(HEADER_SIZE_WITHOUT_SIGNATURE + signatureLength);
      final int headerLengthAndIdSize = header.position();

      byte[] spi = getSPI();
      header.put(spi);
      LOGGER.debug("SPI: " + Util.toHexArray(spi));

      byte kic = KICCoder.decode(cardProfile.getKIC());
      header.put(kic);
      LOGGER.debug("KIC: {}", Util.toHex(kic));

      byte kid = KIDCoder.decode(cardProfile.getKID());
      header.put(kid);
      LOGGER.debug("KID: {}", Util.toHex(kid));

      byte[] tar = cardProfile.getTAR();
      header.put(tar);
      LOGGER.debug("TAR: {}", Util.toHexArray(tar));

      header.put(counterBytes);
      LOGGER.debug("Counter: {}", Util.toHexArray(counterBytes));

      if (commandPacketCiphering) {
        final int dataSize = COUNTER_SIZE + PADDING_COUNTER_SIZE + signatureLength + dataBytes.length;
        LOGGER.trace("Data size: {}, block size: {}", dataSize, cipherBlockSize);
        paddingCounter = getPadding(dataSize, cipherBlockSize);
      }

      header.put((byte) (paddingCounter & 0xff));
      LOGGER.debug("Padding counter: {}", Util.toHex((byte) (paddingCounter & 0xff)));

      final int length = header.capacity() + dataBytes.length + paddingCounter;

      final byte[] cpi;
      final byte[] cpl;

      switch (cardProfile.getTransportProtocol()) {
        case SMS_CB:
        case SMS_PP:
          cpi = BYTES_NULL;
          cpl = Util.encodeTwoBytesLength(length);
          break;
        case CAT_TP:
        case TCP_IP:
          cpi = CPI;
          cpl = Util.encodeLength(length);
          break;
        case USSD:
          cpi = USSD_CPI;
          cpl = Util.encodeLength(length);
          break;
        default:
          throw new PacketBuilderConfigurationException("Transport not set");
      }

      if (commandPacketSigning) {
        // Part or all of these fields may also be included in the calculation of the RC/CC/DS, depending on implementation (e.g. SMS).
        // CPI / CPL / CHI  CHL
        // These fields are included in the calculation of the RC/CC/DS.
        // SPI / KIC / KID / TAR / CNTR / PCNTR / SECURED DATA WITH PADDING

        // SMS_PP - CPI - UDH 02 70 00 is not taken in the RC/CC/DS calculation

        ByteBuffer signData = ByteBuffer.allocate(cpi.length + cpl.length + header.capacity() - signatureLength + dataBytes.length + paddingCounter);
        signData.put(cpi);
        signData.put(cpl);
        signData.put(header.array(), 0, header.capacity() - signatureLength);
        signData.put(dataBytes);
        // Padding data (zeros) are already in buffer

        LOGGER.debug("Signing data[{}]: {} ({})", signData.capacity(), Util.toHexString(signData.array()), signatureAlgorithmName);
        signature = SignatureManager.sign(signatureAlgorithmName, signatureKey, signData.array());
        LOGGER.debug("Signature: {} length: {}", Util.toHexString(signature), signature.length);
        header.put(signature);
      }
      if (signature.length != signatureLength) {
        throw new Gsm0348Exception("The generated signature length doesn't match the expected length");
      }
      LOGGER.debug("Header: {} length: {}", Util.toHexString(header.array()), header.capacity());

      if (commandPacketCiphering) {

        byte[] cipherData = new byte[COUNTER_SIZE + PADDING_COUNTER_SIZE + signatureLength + dataBytes.length];
        ByteBuffer cipherBuffer = ByteBuffer.wrap(cipherData);
        cipherBuffer.put(counterBytes);
        cipherBuffer.put((byte) (paddingCounter & 0xff));
        cipherBuffer.put(signature);
        cipherBuffer.put(dataBytes);

        // Cipher aligned on blocksize data, as NoPadding is used now
        byte[] alignedCipherData = alignDataOnBlockSize(cipherData, cipherBlockSize);
        LOGGER.debug("Ciphering command data: {} length: {}", Util.toHexString(alignedCipherData), alignedCipherData.length);
        byte[] cipheredData = CipheringManager.encipher(cipheringAlgorithmName, cipheringKey, alignedCipherData);
        LOGGER.debug("Ciphered command data: {} length: {}", Util.toHexString(cipheredData), cipheredData.length);

        final byte[] clearHeader = new byte[headerLengthAndIdSize + SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE];
        System.arraycopy(header.array(), 0, clearHeader, 0, clearHeader.length);
        LOGGER.debug("Ciphered command header: {} length: {}", Util.toHexString(clearHeader), clearHeader.length);

        byte[] result = createPacket(cpi, clearHeader, cipheredData);
        LOGGER.debug("Ciphered command packet created: {} length: {}", Util.toHexString(result), result.length);
        return result;
      }
      LOGGER.debug("Command header: {} length: {}", Util.toHexString(header.array()), header.capacity());
      byte[] result = createPacket(cpi, header.array(), dataBytes);
      LOGGER.debug("Command packet created: {} length: {}", Util.toHexString(result), result.length);
      return result;

    } catch (GeneralSecurityException e) {
      throw new Gsm0348Exception(e);
    }
  }

  @Override
  public byte[] buildResponsePacket(byte[] data, byte[] counter, byte[] cipheringKey, byte[] signatureKey,
                                    ResponsePacketStatus responseStatus) throws PacketBuilderConfigurationException, Gsm0348Exception {
    if (!isConfigured()) {
      throw new PacketBuilderConfigurationException("Not configured");
    }

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Creating {} response packet.\n\tData: {}\n\tCounter: {}\n\tCipheringKey: {}\n\tSigningKey: {}"
          , transportProtocol
          , Util.toHexString(data)
          , Util.toHexString(counter)
          , Util.toHexString(cipheringKey)
          , Util.toHexString(signatureKey));
    }

    if (responsePacketCiphering && (cipheringKey == null)) {
      throw new PacketBuilderConfigurationException("Ciphering is enabled - ciphering key must be specified");
    }
    if (responsePacketSigning && (signatureKey == null)) {
      throw new PacketBuilderConfigurationException("Signing is enabled - signature key must be specified");
    }
    if (counter == null && usingCounter) {
      throw new PacketBuilderConfigurationException("Counter is null and required by configuration");
    }
    if (counter != null && counter.length != COUNTER_SIZE) {
      throw new PacketBuilderConfigurationException("Counter size mismatch. Current is "
          + (counter != null ? counter.length : "null") + ", required is " + COUNTER_SIZE);
    }

    try {
      LOGGER.trace("Signing: {}", responsePacketSigning);
      final int signatureLength = responsePacketSigning ? signatureSize : 0;
      LOGGER.debug("Signature length: {}", signatureLength);
      final int headerLength = RESPONSE_HEADER_SIZE_WITHOUT_SIGNATURE + signatureLength;
      LOGGER.debug("Header length: {}", headerLength);

      byte[] signature = new byte[signatureLength];
      byte[] dataBytes = (data == null) ? new byte[0] : data;
      byte[] counterBytes = usingCounter ? counter : new byte[COUNTER_SIZE];
      int paddingCounter = 0;

      ByteBuffer header = createHeaderOneByteLength(BYTES_NULL, RESPONSE_HEADER_SIZE_WITHOUT_SIGNATURE + signatureLength);
      final int headerLengthAndIdSize = header.position();

      byte[] tar = cardProfile.getTAR();
      header.put(cardProfile.getTAR());
      LOGGER.debug("TAR: {}", Util.toHexArray(tar));

      header.put(counterBytes);
      LOGGER.debug("Counter: {}", Util.toHexArray(counterBytes));

      if (responsePacketCiphering) {
        final int dataSize = COUNTER_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE + signatureLength + dataBytes.length;
        paddingCounter = getPadding(dataSize, cipherBlockSize);
      }

      header.put((byte) (paddingCounter & 0xff));
      LOGGER.debug("Padding counter: {}", Util.toHex((byte) (paddingCounter & 0xff)));

      byte statusCode = (byte) (responseStatus.ordinal() & 0xff);
      header.put(statusCode);
      LOGGER.debug("Status code: {}", Util.toHex(statusCode));

      final int length = header.capacity() + dataBytes.length + paddingCounter;

      final byte[] rpi;
      final byte[] rpl;

      switch (cardProfile.getTransportProtocol()) {
        case SMS_PP:
          rpi = BYTES_NULL;
          rpl = Util.encodeTwoBytesLength(length);
          break;
        case SMS_CB:
          throw new PacketBuilderConfigurationException("Response packet is not defined for SMS-CB");
        case CAT_TP:
        case TCP_IP:
          rpi = RPI;
          rpl = Util.encodeLength(length);
          break;
        case USSD:
          rpi = USSD_RPI;
          rpl = Util.encodeLength(length);
          break;
        default:
          throw new PacketBuilderConfigurationException("Transport " + cardProfile.getTransportProtocol() + " not set or implemented");
      }

      if (responsePacketSigning) {

        ByteBuffer signData;
        switch (cardProfile.getTransportProtocol()) {
          case SMS_PP:
            // rpi is null as it's the UDH 027100
            signData = ByteBuffer.allocate(
                SMS_RPI.length + rpl.length + headerLengthAndIdSize + TAR_SIZE + COUNTER_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE + dataBytes.length + paddingCounter);
            signData.put(SMS_RPI);
            break;
          case CAT_TP:
          case TCP_IP:
          case USSD:
            signData = ByteBuffer.allocate(
                rpi.length + rpl.length + headerLengthAndIdSize + TAR_SIZE + COUNTER_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE + dataBytes.length + paddingCounter);
            signData.put(rpi);
            break;
          default:
            throw new PacketBuilderConfigurationException("Transport " + cardProfile.getTransportProtocol() + " not set or implemented");
        }
        signData.put(rpl);
        signData.put((byte) (header.capacity() - headerLengthAndIdSize));

        LOGGER.debug("Header: {}", Util.toHexArray(header.array()));
        signData.put(header.array(), headerLengthAndIdSize, header.capacity() - headerLengthAndIdSize - signatureLength);
        signData.put(dataBytes);
        // Padding data (zeros) is already in buffer
        LOGGER.debug("Signing data[{}]: {} ({})", signData.capacity(), Util.toHexString(signData.array()), signatureAlgorithmName);

        signature = SignatureManager.sign(signatureAlgorithmName, signatureKey, signData.array());
        LOGGER.debug("Signature: {} length: {}", Util.toHexString(signature), signature.length);
        header.put(signature);
      }
      if (signature.length != signatureLength) {
        throw new Gsm0348Exception("The generated signature length doesn't match the expected length");
      }

      if (responsePacketCiphering) {
        LOGGER.trace("Ciphering response");

        byte[] cipherData = new byte[COUNTER_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE + signatureLength + dataBytes.length];
        ByteBuffer cipherBuffer = ByteBuffer.wrap(cipherData);

        cipherBuffer.put(counterBytes);
        cipherBuffer.put((byte) (paddingCounter & 0xff));
        cipherBuffer.put((byte) (responseStatus.ordinal() & 0xff));
        cipherBuffer.put(signature);
        cipherBuffer.put(dataBytes);

        // Cipher aligned on blocksize data, as NoPadding is used now
        byte[] alignedCipherData = alignDataOnBlockSize(cipherData, cipherBlockSize);
        LOGGER.debug("Ciphering response data[{}]: {}", alignedCipherData.length, Util.toHexString(alignedCipherData));
        byte[] cipheredData = CipheringManager.encipher(cipheringAlgorithmName, cipheringKey, alignedCipherData);
        LOGGER.debug("Ciphered response data[{}]: {}", cipheredData.length, Util.toHexString(cipheredData));

        final byte[] clearHeader = new byte[headerLengthAndIdSize + TAR_SIZE];
        System.arraycopy(header.array(), 0, clearHeader, 0, clearHeader.length);

        LOGGER.debug("Ciphered response header: {} length: {}", Util.toHexString(clearHeader), clearHeader.length);
        byte[] result = createPacket(rpi, clearHeader, cipheredData);
        LOGGER.debug("Ciphered response packet created: {} length: {}", Util.toHexString(result), result.length);
        return result;
      }
      LOGGER.debug("Response header data: {} length: {}", Util.toHexString(header.array()), header.capacity());
      byte[] result = createPacket(rpi, header.array(), dataBytes);
      LOGGER.debug("Response packet created: {} length: {}", Util.toHexString(result), result.length);
      return result;
    } catch (GeneralSecurityException e) {
      throw new Gsm0348Exception(e);
    }
  }

  @Override
  public CommandPacket recoverCommandPacket(byte[] data, byte[] cipheringKey, byte[] signatureKey) throws Gsm0348Exception {

    if (data == null) {
      throw new IllegalArgumentException("Packet data cannot be null");
    }

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Recovering command packet.\n\tData: {}\n\tCipheringKey: {}\n\tSigningKey: {}",
          Util.toHexArray(data),
          Util.toHexArray(cipheringKey),
          Util.toHexArray(signatureKey));
    }

    ByteBuffer dataBuffer = ByteBuffer.wrap(data);

    final byte[] cpi;
    final byte[] cpl;
    final int packetLength;
    switch (transportProtocol) {
      case SMS_CB:
      case SMS_PP:
        cpi = BYTES_NULL;
        cpl = Util.getTwoBytesLengthBytes(dataBuffer);
        packetLength = Util.decodeLengthTwo(cpl);
        break;
      case CAT_TP:
      case TCP_IP:
        cpi = new byte[]{ dataBuffer.get() };
        if (!Arrays.equals(cpi, CPI)) {
          throw new Gsm0348Exception("CPI " + Util.toHexString(cpi) + " is not expected");
        }
        cpl = Util.getEncodedLengthBytes(dataBuffer);
        packetLength = Util.decodeLength(cpl);
        break;
      case USSD:
        cpi = new byte[]{ dataBuffer.get() };
        if (!Arrays.equals(cpi, USSD_CPI)) {
          throw new Gsm0348Exception("USSD CPI " + Util.toHexString(cpi) + " is not expected");
        }
        cpl = Util.getEncodedLengthBytes(dataBuffer);
        packetLength = Util.decodeLength(cpl);
        break;
      default:
        throw new Gsm0348Exception("Transport " + transportProtocol + " not implemented");
    }

    if (data.length - cpi.length - cpl.length != packetLength) {
      throw new Gsm0348Exception(
          "Length of raw data doesn't match packet length. Expected " + packetLength + " but found " + (data.length - cpi.length - cpl.length));
    }

    // Header length depending on transport protocol
    final byte[] chi = BYTES_NULL;
    final byte[] chl = Util.getOneBytesLengthBytes(dataBuffer);
    final int headerLength = Util.decodeLengthOne(chl);

    final byte[] spiBytes = new byte[SPI_SIZE];
    dataBuffer.get(spiBytes);
    LOGGER.debug("SPI: {}", Util.toHexArray(spiBytes));
    final SPI spi = getSPI(spiBytes);

    final byte[] kicBytes = new byte[KIC_SIZE];
    dataBuffer.get(kicBytes);
    LOGGER.debug("KIC: {}", Util.toHexArray(kicBytes));
    final KIC kic = KICCoder.encode(kicBytes[0]);

    final byte[] kidBytes = new byte[KID_SIZE];
    dataBuffer.get(kidBytes);
    LOGGER.debug("KID: {}", Util.toHexArray(kidBytes));
    final KID kid = KIDCoder.encode(spi.getCommandSPI().getCertificationMode(), kidBytes[0]);

    final byte[] tar = new byte[TAR_SIZE];
    dataBuffer.get(tar);
    LOGGER.debug("TAR: {}", Util.toHexArray(tar));

    CommandSPI commandSPI = spi.getCommandSPI();
    commandPacketSigning = commandSPI.getCertificationMode() != CertificationMode.NO_SECURITY;
    commandPacketCiphering = commandSPI.isCiphered();

    cardProfile.setSPI(spi);
    cardProfile.setKIC(kic);
    cardProfile.setKID(kid);

    if (commandPacketCiphering) {
      setCipheringAlgorithmName(cardProfile);
    }
    if (commandPacketSigning) {
      setSigningAlgorithmName(cardProfile);
    }

    final byte[] counter = new byte[COUNTER_SIZE];
    final int signatureLength = commandPacketSigning ? signatureSize : 0;

    if (commandPacketCiphering && (cipheringKey == null || cipheringKey.length == 0)) {
      throw new PacketBuilderConfigurationException(
          "Ciphering is enabled - ciphering key must be specified. Provided: "
              + ((cipheringKey.length == 0) ? "empty" : Util.toHexArray(cipheringKey)));
    }
    if (commandPacketSigning && (signatureKey == null || signatureKey.length == 0)) {
      throw new PacketBuilderConfigurationException(
          "Signing is enabled - signature key must be specified. Provided: "
              + ((signatureKey.length == 0) ? "empty" : Util.toHexArray(signatureKey)));
    }

    if (data.length < MINIMUM_COMMAND_PACKET_SIZE + signatureLength) {
      String message = "rawdata too small to be command packet. Expected to be >= "
          + (MINIMUM_COMMAND_PACKET_SIZE + signatureLength) + ", but found " + data.length;
      if (data.length >= MINIMUM_COMMAND_PACKET_SIZE) {
        message += ". It can be caused by incorrect profile(SPI value). Check SPI!";
        LOGGER.warn("Packet received(raw): {}", Util.toHexArray(data));
      }
      throw new Gsm0348Exception(message);
    }

    final byte[] signature = new byte[signatureLength];
    LOGGER.trace("Signature length: {}", signatureLength);

    int paddingCounter;
    byte[] packetData;

    try {

      if (commandPacketCiphering) {

        byte[] ciphered = new byte[dataBuffer.remaining()];
        dataBuffer.get(ciphered);

        LOGGER.debug("Ciphered: {} ({} bytes)", Util.toHexArray(ciphered), ciphered.length);
        byte[] deciphered = CipheringManager.decipher(cipheringAlgorithmName, cipheringKey, ciphered);
        LOGGER.debug("Deciphered: {} ({} bytes)", Util.toHexArray(deciphered), deciphered.length);

        final int minimumDecipheredLength = COUNTER_SIZE + PADDING_COUNTER_SIZE + signatureLength;
        if (deciphered.length < minimumDecipheredLength) {
         throw new Gsm0348Exception("Deciphered data returned not enough data");
        }

        final ByteBuffer decipheredBuffer = ByteBuffer.wrap(deciphered);
        decipheredBuffer.get(counter);
        LOGGER.debug("Counter: {}", Util.toHexArray(counter));
        paddingCounter = decipheredBuffer.get() & 0xff;
        LOGGER.debug("Padding counter: {}", paddingCounter);
        decipheredBuffer.get(signature);
        LOGGER.debug("Signature: {} length: {}", Util.toHexString(signature), signature.length);

        final int dataSize = packetLength - chi.length - chl.length - headerLength;
        final int dataSizeToCopy = deciphered.length - COUNTER_SIZE - PADDING_COUNTER_SIZE - signatureLength;

        packetData = new byte[dataSize];
        decipheredBuffer.get(packetData, 0, dataSizeToCopy);

      } else {

        // no ciphering
        dataBuffer.get(counter);
        LOGGER.debug("Counter: {}", Util.toHexArray(counter));

        paddingCounter = dataBuffer.get() & 0xff;
        LOGGER.debug("Padding counter: {}", paddingCounter);
        if (paddingCounter != 0) {
          throw new Gsm0348Exception(
              "Command packet ciphering is off but padding counter is not 0. So it can be corrupted packet or configuration doesn't match provided data");
        }

        dataBuffer.get(signature);
        LOGGER.debug("Signature: {} length: {}", Util.toHexString(signature), signature.length);

        final int dataSize = packetLength - headerLength - chi.length - chl.length;
        if (dataSize != dataBuffer.remaining()) {
          throw new IllegalStateException("Expected data size doesn't match buffer size remaining");
        }
        packetData = new byte[dataBuffer.remaining()];
        dataBuffer.get(packetData);
      }
      LOGGER.debug("Packet data: {} length: {}", Util.toHexArray(packetData), packetData.length);

      if (commandPacketSigning) {
        int addonAmount = 0;
        switch (cardProfile.getTransportProtocol()) {
          case SMS_CB:
          case SMS_PP:
            // SMS_PP: CPI mapped as 027100
            // addonAmount = CPI_AS_IEDI.length + cpl.length + chi.length + chl.length;
            addonAmount = cpi.length + cpl.length + chi.length + chl.length;
            break;
          case CAT_TP:
          case TCP_IP:
            addonAmount = cpi.length + cpl.length + chi.length + chl.length;
            break;
          case USSD:
            addonAmount = cpi.length + cpl.length + chi.length + chl.length;
            break;
        }

        ByteBuffer signData = ByteBuffer.allocate(addonAmount + HEADER_SIZE_WITHOUT_SIGNATURE + packetData.length);

        signData.put(cpi);
        signData.put(cpl);
        signData.put(chi);
        signData.put(chl);

        // Always unencrypted
        signData.put(data, cpi.length + cpl.length + chi.length + chl.length, SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE);
        signData.put(counter);
        signData.put((byte) (paddingCounter & 0xff));
        signData.put(packetData);

        LOGGER.debug("Verify: {} length: {} ({})", Util.toHexArray(signData.array()), signData.capacity(), signatureAlgorithmName);
        final boolean valid = SignatureManager.verify(signatureAlgorithmName, signatureKey, signData.array(), signature);
        if (!valid) {
          throw new Gsm0348Exception("Signatures don't match");
        }
        LOGGER.trace("Signatures do match");
      }

      final CommandPacketHeader packetHeader = new CommandPacketHeader();
      packetHeader.setSPI(spi);
      packetHeader.setKIC(kic);
      packetHeader.setKID(kid);
      packetHeader.setTAR(tar);
      packetHeader.setCounter(counter);
      packetHeader.setPaddingCounter((byte) (paddingCounter & 0xff));
      packetHeader.setSecurity(signature);

      if (paddingCounter > 0) {
        packetData = removePadding(packetData, paddingCounter);
      }
      final CommandPacket packet = new CommandPacket();
      packet.setHeader(packetHeader);
      packet.setData(packetData);
      LOGGER.debug("Command packet recovered: {}", packet);
      return packet;
    } catch (GeneralSecurityException e) {
      throw new Gsm0348Exception(e);
    }
  }

  @Override
  public ResponsePacket recoverResponsePacket(byte[] data, byte[] cipheringKey, byte[] signatureKey)
      throws PacketBuilderConfigurationException, Gsm0348Exception {

    if (data == null) {
      throw new IllegalArgumentException("Packet data cannot be null");
    }

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Recovering {} response packet.\n\tData: {}\n\tCipheringKey: {}\n\tSigningKey: {}",
          transportProtocol,
          Util.toHexArray(data),
          Util.toHexArray(cipheringKey),
          Util.toHexArray(signatureKey));
    }

    if (!isConfigured()) {
      throw new PacketBuilderConfigurationException("Not configured");
    }

    if (responsePacketCiphering && (cipheringKey == null || cipheringKey.length == 0)) {
      throw new PacketBuilderConfigurationException(
          "Response ciphering is enabled - ciphering key must be specified. Provided: "
              + ((cipheringKey.length == 0) ? "empty" : Util.toHexArray(cipheringKey)));
    }
    if (responsePacketSigning && (signatureKey == null || signatureKey.length == 0)) {
      throw new PacketBuilderConfigurationException(
          "Response signing is enabled - signature key must be specified. Provided: "
              + ((signatureKey.length == 0) ? "empty" : Util.toHexArray(signatureKey)));
    }

    ByteBuffer dataBuffer = ByteBuffer.wrap(data);

    final byte[] rpi;
    final byte[] rpl;
    final int packetLength;
    switch (cardProfile.getTransportProtocol()) {
      case SMS_PP:
        // As in 3GPP 31.115 table 3, the SMS_PP response doesn't contain the 027100 RPI
        // See createPacket
        rpi = BYTES_NULL;
        rpl = Util.getTwoBytesLengthBytes(dataBuffer);
        packetLength = Util.decodeLengthTwo(rpl);
        break;
      case CAT_TP:
      case TCP_IP:
        rpi = new byte[]{ dataBuffer.get() };
        if (!Arrays.equals(rpi, RPI)) {
          throw new Gsm0348Exception("RPI " + Util.toHexString(rpi) + " is not expected");
        }
        rpl = Util.getEncodedLengthBytes(dataBuffer);
        packetLength = Util.decodeLength(rpl);
        break;
      case USSD:
        rpi = new byte[]{ dataBuffer.get() };
        if (!Arrays.equals(rpi, USSD_RPI)) {
          throw new Gsm0348Exception("USSD RPI " + Util.toHexString(rpi) + " is not expected");
        }
        rpl = Util.getEncodedLengthBytes(dataBuffer);
        packetLength = Util.decodeLength(rpl);
        break;
      default:
        throw new Gsm0348Exception("Transport " + cardProfile.getTransportProtocol() + " not implemented");
    }

    if (data.length - rpi.length - rpl.length != packetLength) {
      throw new Gsm0348Exception("Length of raw data doesn't match packet length. Expected " + packetLength + " but found "
          + (data.length - rpi.length - rpl.length));
    }

    // Header length depending on mode
    final byte[] rhi = BYTES_NULL;
    final byte[] rhl = Util.getOneBytesLengthBytes(dataBuffer);
    final int headerLength = Util.decodeLengthOne(rhl);

    final byte[] tar = new byte[TAR_SIZE];
    dataBuffer.get(tar);
    LOGGER.debug("TAR: {}", Util.toHexArray(tar));
    final int positionCiphering = dataBuffer.position();
    final byte[] counter = new byte[COUNTER_SIZE];
    final int signatureLength = responsePacketSigning ? signatureSize : 0;

    if (data.length < MINIMUM_RESPONSE_PACKET_SIZE + signatureLength) {
      String message = "rawdata too small to be response packet. Expected to be >= "
          + (MINIMUM_RESPONSE_PACKET_SIZE + signatureLength) + ", but found " + data.length;
      if (data.length >= MINIMUM_RESPONSE_PACKET_SIZE) {
        message += ". It can be caused by incorrect profile(SPI value). Check SPI!";
        LOGGER.warn("Packet received(raw): {}", Util.toHexArray(data));
      }
      throw new Gsm0348Exception(message);
    }

    final byte[] signature = new byte[signatureLength];
    int paddingCounter;
    byte statusCode;
    byte[] packetData;

    try {

      if (responsePacketCiphering) {

        dataBuffer.position(positionCiphering);
        byte[] ciphered = new byte[dataBuffer.remaining()];
        dataBuffer.get(ciphered);

        LOGGER.debug("Ciphered: {} ({} bytes)", Util.toHexArray(ciphered), ciphered.length);
        byte[] deciphered = CipheringManager.decipher(cipheringAlgorithmName, cipheringKey, ciphered);

        final int minimumDecipheredLength = COUNTER_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE + signatureLength;
        if (deciphered.length < minimumDecipheredLength) {
          throw new Gsm0348Exception("Deciphered response data returned not enough data");
        }

        ByteBuffer decipheredBuffer = ByteBuffer.wrap(deciphered);
        LOGGER.debug("Deciphered: {} ({} bytes)", Util.toHexArray(deciphered), deciphered.length);

        decipheredBuffer.get(counter);
        LOGGER.debug("Counter: {}", Util.toHexArray(counter));
        paddingCounter = decipheredBuffer.get() & 0xff;
        LOGGER.debug("Padding counter: {}", paddingCounter);
        statusCode = decipheredBuffer.get();
        LOGGER.debug("Status code: {}", Util.toHex(statusCode));

        decipheredBuffer.get(signature);
        LOGGER.debug("Signature: {} length: {}", Util.toHexString(signature), signature.length);

        final int dataSize = packetLength - headerLength - rhi.length - rhl.length;
        final int dataSizeToCopy = deciphered.length - COUNTER_SIZE - PADDING_COUNTER_SIZE - STATUS_CODE_SIZE - signatureLength;

        if (dataSize < dataSizeToCopy) {
          throw new Gsm0348Exception(
              "Response packet recovery failure. Possibly because of unexpected security bytes length. Actual: " + dataSize + " Expected: " + dataSizeToCopy);
        }

        packetData = new byte[dataSize];
        System.arraycopy(deciphered, COUNTER_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE + signatureLength, packetData, 0, dataSizeToCopy);

      } else {

        // no ciphering
        dataBuffer.get(counter);
        LOGGER.debug("Counter: {}", Util.toHexArray(counter));
        paddingCounter = dataBuffer.get() & 0xff;
        LOGGER.debug("Padding counter: {}", paddingCounter);
        if (paddingCounter != 0) {
          throw new Gsm0348Exception(
              "Response packet ciphering is off but padding counter is not 0. So it can be corrupted packet or configuration doesn't match provided data");
        }
        statusCode = dataBuffer.get();
        LOGGER.debug("Status code: {}", Util.toHex(statusCode));
        dataBuffer.get(signature);
        LOGGER.debug("Signature: {} length: {}", Util.toHexString(signature), signature.length);

        packetData = new byte[packetLength - rhi.length - rhl.length - headerLength];
        dataBuffer.get(packetData);
      }
      LOGGER.debug("Packet data: {}", Util.toHexArray(packetData));

      if (responsePacketSigning) {

        final ByteBuffer signData;

        switch (cardProfile.getTransportProtocol()) {
          case SMS_PP:
            // In order to achieve a modulo 8 length of the data before the RC/CC/DS fiel in the Response Header,
            // the Length of the Response Packet, the Length of the Response Header
            // and the three preceding octets (UDHL, IEIa and IEIDLa defined in TS 23.040 [3]) shall be included
            // in the calculation of RC/CC/DS if used.
            signData = ByteBuffer.allocate(
                SMS_RPI.length + rpl.length + rhi.length + rhl.length + TAR_SIZE + COUNTER_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE + packetData.length);
            signData.put(SMS_RPI);
            break;
          case CAT_TP:
          case TCP_IP:
          case USSD:
            signData = ByteBuffer.allocate(
                rpi.length + rpl.length + rhi.length + rhl.length + TAR_SIZE + COUNTER_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE + packetData.length);
            signData.put(rpi);
            break;
          default:
            throw new Gsm0348Exception("Transport " + cardProfile.getTransportProtocol() + " not implemented");
        }

        signData.put(rpl);
        signData.put(rhi);
        signData.put(rhl);

        signData.put(tar);
        signData.put(counter);
        signData.put((byte) (paddingCounter & 0xff));
        signData.put(statusCode);
        signData.put(packetData);

        LOGGER.debug("Verify: {} length: {} ({})", Util.toHexArray(signData.array()), signData.capacity(), signatureAlgorithmName);
        boolean valid = SignatureManager.verify(signatureAlgorithmName, signatureKey, signData.array(), signature);
        if (!valid) {
          throw new Gsm0348Exception("Signatures don't match");
        }
        LOGGER.trace("Signatures do match");
      }

      ResponsePacketHeader packetHeader = new ResponsePacketHeader();
      packetHeader.setTAR(tar);
      packetHeader.setCounter(counter);
      packetHeader.setPaddingCounter((byte) (paddingCounter & 0xff));
      packetHeader.setResponseStatus(ResponsePacketStatusCoder.encode(statusCode));
      packetHeader.setSecurity(signature);

      ResponsePacket packet = new ResponsePacket();
      if (paddingCounter > 0) {
        packetData = removePadding(packetData, paddingCounter);
      }
      packet.setData(packetData);
      packet.setHeader(packetHeader);

      LOGGER.debug("Response packet recovered: {}", packet);
      return packet;

    } catch (GeneralSecurityException e) {
      throw new Gsm0348Exception(e);
    }
  }

  private byte[] createPacket(final byte[] pi, final byte[] first, final byte[] second)
      throws Gsm0348Exception {
    switch (transportProtocol) {
      case SMS_CB:
      case SMS_PP:
        return createPacketWithTwoBytesLength(first, second);
      case CAT_TP:
      case TCP_IP:
      case USSD:
        return createPacketWithEncodedLength(pi, first, second);
    }
    throw new Gsm0348Exception("Not implemented");
  }

  private byte[] createPacketWithTwoBytesLength(final byte[] first, final byte[] second) {
    // CPI or RPI is always NULL for SMS
    // first contains CHI/CHL or RHI/RHL, but not the CPI/CPL or RPI/RPL
    int length = first.length + second.length;
    byte[] pi = BYTES_NULL;
    byte[] pl = new byte[]{ (byte) (length >> 8), (byte) (length & 0xff) };
    return createPacket(pi, pl, first, second);
  }

  private byte[] createPacketWithEncodedLength(final byte[] pi, final byte[] first, final byte[] second) {
    // first contains CHI/CHL or RHI/RHL, but not the CPI/CPL or RPI/RPL
    int length = first.length + second.length;
    byte[] pl = Util.encodeLength(length);
    return createPacket(pi, pl, first, second);
  }

  private byte[] createPacket(final byte[] cpi, final byte[] cpl, final byte[] first, final byte[] second) {
    ByteBuffer bb = ByteBuffer.allocate(cpi.length + cpl.length + first.length + second.length);
    bb.put(cpi);
    bb.put(cpl);
    bb.put(first);
    bb.put(second);
    return bb.array();
  }

  private ByteBuffer createHeaderOneByteLength(final byte[] hi, final int length) {
    byte[] hl = new byte[]{ (byte) (length & 0xff) };
    ByteBuffer header = ByteBuffer.allocate(hi.length + hl.length + length);
    header.put(hi);
    header.put(hl);
    return header;
  }

  private ByteBuffer createHeaderLength(final byte[] hi, final int length) {
    byte[] hl = Util.encodeLength(length);
    ByteBuffer header = ByteBuffer.allocate(hi.length + hl.length + length);
    header.put(hi);
    header.put(hl);
    return header;
  }

  private int getPadding(final int dataSize, final int blockSize) {
    final int remainder = dataSize % blockSize;
    if (remainder != 0) {
      return (blockSize - remainder);
    }
    return 0;
  }

  private byte[] removePadding(final byte[] data, final int padding) {
    // Remove padding after decipher
    byte[] dataWithoutPadding = new byte[data.length - padding];
    System.arraycopy(data, 0, dataWithoutPadding, 0, dataWithoutPadding.length);
    return dataWithoutPadding;
  }

  private byte[] alignDataOnBlockSize(final byte[] data, final int blockSize) {
    final int newLength = aligned(data.length, blockSize);
    if (newLength > data.length) {
      final byte[] dataPadded = new byte[newLength];
      System.arraycopy(data, 0, dataPadded, 0, data.length);
      return dataPadded;
    }
    return data;
  }

  ByteBuffer createHeader(final int headerLength)
      throws Gsm0348Exception {
    switch (transportProtocol) {
      case SMS_CB:
      case SMS_PP:
        return createHeaderOneByteLength(BYTES_NULL, headerLength);
      case CAT_TP:
      case TCP_IP:
      case USSD:
        return createHeaderLength(BYTES_NULL, headerLength);
      default:
        throw new Gsm0348Exception("Transport not implemented");
    }
  }

  private int aligned(final int length, final int blockSize) {
    final int align = length % blockSize;
    if (0 != align) {
      return length + blockSize - align;
    }
    return length;
  }
}
