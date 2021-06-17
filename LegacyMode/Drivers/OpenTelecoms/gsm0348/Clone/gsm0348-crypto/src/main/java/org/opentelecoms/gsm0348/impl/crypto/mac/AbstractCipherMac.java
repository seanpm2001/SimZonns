package org.opentelecoms.gsm0348.impl.crypto.mac;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.opentelecoms.gsm0348.impl.crypto.CipherParameters;
import org.opentelecoms.gsm0348.impl.crypto.Mac;
import org.opentelecoms.gsm0348.impl.crypto.params.KeyParameter;
import org.opentelecoms.gsm0348.impl.crypto.params.ParametersWithIV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractCipherMac implements Mac {
  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractCipherMac.class);
  private final String m_algFullName;
  private final String m_algShortName;
  private final int m_size;
  private Cipher m_cipher;
  private byte[] m_key;
  private byte[] m_iv;

  AbstractCipherMac(String algFullName, String algShortName, int size) {
    m_algFullName = algFullName;
    m_algShortName = algShortName;
    m_size = size;
  }

  public void init(CipherParameters cipheringParams) throws IllegalArgumentException {
    if (cipheringParams instanceof ParametersWithIV) {
      m_iv = ((ParametersWithIV) cipheringParams).getIV();
      if (m_iv == null) {
        throw new IllegalArgumentException("IV cannot be null");
      }

      cipheringParams = ((ParametersWithIV) cipheringParams).getParameters();
    }

    if (!(cipheringParams instanceof KeyParameter)) {
      m_iv = null;
      throw new IllegalArgumentException("cipheringParams must contain KeyParameter");
    }
    m_key = ((KeyParameter) cipheringParams).getKey();
    if (m_key == null) {
      m_iv = null;
      throw new IllegalArgumentException("Key cannot be null");
    }
    try {
      m_cipher = Cipher.getInstance(m_algFullName);

      Key keySpec = new SecretKeySpec(m_key, m_algShortName);
      if (m_iv != null) {
        m_cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(m_iv));
      } else {
        m_cipher.init(Cipher.ENCRYPT_MODE, keySpec);
      }
    } catch (GeneralSecurityException ex) {
      throw new IllegalArgumentException(ex);
    }
  }

  public String getAlgorithmName() {
    return m_algFullName;
  }

  public int getMacSize() {
    return m_size;
  }

  public void update(byte input) throws IllegalStateException {
    m_cipher.update(new byte[]{ input });
  }

  public void update(byte[] input, int inputOffset, int inputLen) throws IllegalStateException {
    m_cipher.update(input, inputOffset, inputLen);
  }

  public int doFinal(byte[] output, int outputOffset) throws IllegalStateException {
    try {
      byte[] result = m_cipher.doFinal();
      System.arraycopy(result, 0, output, outputOffset, m_size);
      return m_size;
    } catch (IllegalBlockSizeException e) {
      LOGGER.error("Could not cipher (illegal block size)", e);
    } catch (BadPaddingException e) {
      LOGGER.error("Could not cipher (bad padding)", e);
    }
    return 0;
  }

  public void reset() {
    try {
      m_cipher.doFinal();
    } catch (IllegalBlockSizeException e) {
      LOGGER.error("Could not cipher (illegal block size)", e);
    } catch (BadPaddingException e) {
      LOGGER.error("Could not cipher (bad padding)", e);
    }
  }
}
