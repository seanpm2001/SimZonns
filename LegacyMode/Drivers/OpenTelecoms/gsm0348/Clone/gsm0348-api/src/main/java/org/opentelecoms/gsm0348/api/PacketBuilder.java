package org.opentelecoms.gsm0348.api;

import org.opentelecoms.gsm0348.api.model.CardProfile;
import org.opentelecoms.gsm0348.api.model.CommandPacket;
import org.opentelecoms.gsm0348.api.model.ResponsePacket;
import org.opentelecoms.gsm0348.api.model.ResponsePacketStatus;


/**
 * This interface describes GSM 03.48 packet builder. Instances of this
 * interface must create and recover GSM 03.48 {@linkplain CommandPacket} and
 * {@linkplain ResponsePacket} including their enciphering, deciphering,
 * signing(RC,CC,DS) and signature verification.
 *
 * @author Victor Platov
 */
public interface PacketBuilder {
  /**
   * Returns profile used or null if builder is not configured.
   *
   * @return {@linkplain CardProfile} used.
   */
  CardProfile getProfile();

  /**
   * Sets builder profile providing all needed for packet builder and
   * recovering information. Builder <strong>must</strong> be configured
   * before usage. Profile state can be checked using
   * {@linkplain PacketBuilder#isConfigured isConfigured} method.
   *
   * @param cardProfile - any {@linkplain CardProfile} instance.
   * @throws NullPointerException                if <strong>cardProfile</strong> parameter is null.
   * @throws PacketBuilderConfigurationException if configuration is in inconsistent state.
   */
  void setProfile(CardProfile cardProfile) throws PacketBuilderConfigurationException;

  /**
   * Returns builder configuration state. After
   * {@linkplain PacketBuilder#setProfile cardProfile} method
   * called if no exception thrown builder should turn no configured state and
   * this method return <code>true</code>. Otherwise it will should return
   * <code>false</code>.
   *
   * @return builder configuration state
   */
  boolean isConfigured();

  /**
   * Builds {@linkplain CommandPacket}.
   *
   * @param data         - data to be sent. Can be null if no data sending needed.
   * @param counter      - counter value. If not used can be null.
   * @param cipheringKey - ciphering key. Used only if enciphering is needed, otherwise
   *                     can be null.
   * @param signatureKey - signature key. Used only if signing is needed, otherwise can
   *                     be null.
   * @return byte[] with {@linkplain CommandPacket}
   * @throws PacketBuilderConfigurationException if builder if not configured or if ciphering and/or signing
   *                                             is on but key is not provided.
   * @throws Gsm0348Exception                    in other cases.
   */
  byte[] buildCommandPacket(byte[] data, byte[] counter, byte[] cipheringKey, byte[] signatureKey)
      throws PacketBuilderConfigurationException, Gsm0348Exception;

  /**
   * Recovers {@linkplain ResponsePacket} from byte array.
   *
   * @param data         - data to be decoded.
   * @param cipheringKey - ciphering key. Used only if enciphering is needed, otherwise
   *                     can be null.
   * @param signatureKey - signature key. Used only if signing is needed, otherwise can
   *                     be null.
   * @return {@linkplain ResponsePacket}
   * @throws NullPointerException                if data is null or empty.
   * @throws PacketBuilderConfigurationException if builder if not configured or if ciphering and/or signing
   *                                             is on but key is not provided.
   * @throws Gsm0348Exception                    in other cases.
   */
  ResponsePacket recoverResponsePacket(byte[] data, byte[] cipheringKey, byte[] signatureKey)
      throws PacketBuilderConfigurationException, Gsm0348Exception;

  /**
   * Builds {@linkplain ResponsePacket}.
   *
   * @param data           - data to be sent. Can be null if no data sending needed.
   * @param counter        - counter value. If not used can be null.
   * @param cipheringKey   - ciphering key. Used only if enciphering is needed, otherwise
   *                       can be null.
   * @param signatureKey   - signature key. Used only if signing is needed, otherwise can
   *                       be null.
   * @param responseStatus - {@linkplain ResponsePacketStatus} of the building
   *                       message.
   * @return byte[] with {@linkplain ResponsePacket}
   * @throws PacketBuilderConfigurationException if builder if not configured or if ciphering and/or signing
   *                                             is on but key is not provided.
   * @throws Gsm0348Exception                    in other cases.
   */
  byte[] buildResponsePacket(byte[] data, byte[] counter, byte[] cipheringKey, byte[] signatureKey,
                             ResponsePacketStatus responseStatus) throws PacketBuilderConfigurationException, Gsm0348Exception;

  /**
   * Recovers {@linkplain CommandPacket} from byte array.
   *
   * @param data         - data to be decoded.
   * @param cipheringKey - ciphering key. Used only if enciphering is needed, otherwise
   *                     can be null.
   * @param signatureKey - signature key. Used only if signing is needed, otherwise can
   *                     be null.
   * @return {@linkplain CommandPacket}
   * @throws NullPointerException                if data is null or empty.
   * @throws Gsm0348Exception                    in other cases.
   */
  CommandPacket recoverCommandPacket(byte[] data, byte[] cipheringKey, byte[] signatureKey) throws Gsm0348Exception;
}
