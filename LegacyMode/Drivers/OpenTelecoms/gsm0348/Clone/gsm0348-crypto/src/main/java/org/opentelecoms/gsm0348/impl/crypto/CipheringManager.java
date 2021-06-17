package org.opentelecoms.gsm0348.impl.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opentelecoms.gsm0348.api.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This utility class is used for ciphering operations during GSM 03.48 packet creation and recovering.
 *
 * @author Victor Platov
 */
public class CipheringManager {
  private static final Logger LOGGER = LoggerFactory.getLogger(CipheringManager.class);

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      final Provider provider = new BouncyCastleProvider();
      LOGGER.trace("Adding security provider {} ({})", provider.getName(), provider.getInfo());
      final int position = Security.addProvider(provider);
      if (position == -1) {
        LOGGER.info("Security provider {} ({}) was already installed", provider.getName(), provider.getInfo());
      } else {
        LOGGER.debug("Security provider {} ({}) added at position {}", provider.getName(), provider.getInfo(), position);
      }
    }
  }

  private CipheringManager() {
  }

  private static Cipher getCipher(final String alg) throws NoSuchAlgorithmException, NoSuchPaddingException {
    LOGGER.debug("Creating cipher for name: {}", alg);
    return Cipher.getInstance(alg);
  }

  /**
   * Returns block size for transformation name specified. Name can be specified ether by only name, e.g., DES or with mode and padding, e.g.,
   * DES/EDE/ZeroBytePadding.
   *
   * @param transformation - the name of the transformation, e.g., DES/CBC/PKCS5Padding.
   * @return cipher's block size
   * @throws NullPointerException     if the transformation is null or empty string.
   * @throws NoSuchAlgorithmException if transformation with specified name not found
   * @throws NoSuchPaddingException   if transformation contains a padding scheme that is not available.
   */
  public static int getBlockSize(final String transformation) throws NoSuchAlgorithmException, NoSuchPaddingException {
    if (transformation == null || transformation.length() == 0) {
      throw new IllegalArgumentException("Transformation name can not be null or empty");
    }
    final int blockSize = getCipher(transformation).getBlockSize();
    LOGGER.trace("The block size for transformation {} is {}", transformation, blockSize);
    return blockSize;
  }

  /**
   * Deciphers data with specified transformation and key.
   *
   * @param transformation - the name of the transformation, e.g., DES/CBC/PKCS5Padding.
   * @param key            - key for cipher.
   * @param data           - data to be deciphered.
   * @return deciphered data
   * @throws NullPointerException               if transformation is null or empty, or key or data are null.
   * @throws NoSuchAlgorithmException           if transformation with specified name not found.
   * @throws NoSuchPaddingException             if transformation contains a padding scheme that is not available.
   * @throws InvalidKeyException                if the given key is inappropriate for this cipher, or if the given key has a key size that exceeds the maximum
   *                                            allowable key size.
   * @throws IllegalBlockSizeException          if the length of data provided is incorrect, i.e., does not match the block size of the cipher.
   * @throws BadPaddingException                if particular padding mechanism is expected for the input data but the data is not padded properly.
   * @throws InvalidAlgorithmParameterException if invalid or inappropriate algorithm parameters specified.
   */
  public static byte[] decipher(final String transformation, final byte[] key, final byte[] data) throws IllegalBlockSizeException,
      BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
    return doWork(transformation, key, data, Cipher.DECRYPT_MODE);
  }

  private static void initCipher(final Cipher cipher, final int mode, final byte[] key)
      throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
    LOGGER.debug("Initializing cipher: {} key length: {} bits", cipher.getAlgorithm(), key.length * 8);
    final int blockSize = getBlockSize(cipher.getAlgorithm());
    LOGGER.trace("Block size for {}: {}", cipher.getAlgorithm(), blockSize);
    final SecretKeySpec keySpec = new SecretKeySpec(key, cipher.getAlgorithm());
    if (key.length > Cipher.getMaxAllowedKeyLength(cipher.getAlgorithm())) {
      LOGGER.error("The maximum allowed key length is {} for {}", Cipher.getMaxAllowedKeyLength(cipher.getAlgorithm()), cipher.getAlgorithm());
      throw new IllegalArgumentException("The key length is above the maximum, please install JCE unlimited strength jurisdiction policy files");
    }
    final IvParameterSpec ivParameterSpec =
        cipher.getAlgorithm().contains("CBC") ? new IvParameterSpec(new byte[blockSize]) : null;

    cipher.init(mode, keySpec, ivParameterSpec);
  }

  /**
   * Enciphers data with specified transformation, key and initialization vector.
   *
   * @param transformation - the name of the transformation, e.g., DES/CBC/PKCS5Padding.
   * @param key            - key for cipher.
   * @param data           - data to be enciphered.
   * @return enciphered data
   * @throws NullPointerException               if transformation is null or empty, or key, data or iv are null.
   * @throws NoSuchAlgorithmException           if transformation with specified name not found.
   * @throws NoSuchPaddingException             if transformation contains a padding scheme that is not available.
   * @throws InvalidKeyException                if the given key is inappropriate for this cipher, or if the given key has a keysize that exceeds the maximum
   *                                            allowable key size.
   * @throws IllegalBlockSizeException          if the length of data provided is incorrect, i.e., does not match the block size of the cipher.
   * @throws BadPaddingException                if particular padding mechanism is expected for the input data but the data is not padded properly.
   * @throws InvalidAlgorithmParameterException if invalid or inappropriate algorithm parameters specified.
   */
  public static byte[] encipher(final String transformation, final byte[] key, final byte[] data)
      throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
    //final int blockSize = getBlockSize(transformation);
    // Is it aligned on blocksize
//    if (data.length % blockSize != 0) {
//      final int alignedlength = aligned(data.length, blockSize);
//      return doWork(transformation, key, Arrays.copyOf(data, alignedlength), Cipher.ENCRYPT_MODE);
//    }
    return doWork(transformation, key, data, Cipher.ENCRYPT_MODE);
  }

  private static byte[] doWork(final String transformation, final byte[] key, final byte[] data, final int mode)
      throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
      NoSuchPaddingException, InvalidKeyException {
    if (transformation == null || transformation.length() == 0 || key == null || data == null) {
      throw new IllegalArgumentException();
    }
    Cipher cipher = null;
    try {
      cipher = getCipher(transformation);
      initCipher(cipher, mode, key);
      byte[] result = cipher.doFinal(data);
      return result;
    } catch (IllegalBlockSizeException e) {
      LOGGER.error(
          "Illegal block size. Input data size is " + data.length + " cipher block size is " + cipher.getBlockSize()
              + " cipher name is " + cipher.getAlgorithm(), e);
      throw e;
    } catch (BadPaddingException e) {
      LOGGER.error(
          "Data is not padded correctly. Input data size is " + data.length + " cipher block size is "
              + cipher.getBlockSize() + " cipher name is " + cipher.getAlgorithm() + " data=["
              + Util.toHexArray(data) + "]", e);
      throw e;
    } catch (InvalidAlgorithmParameterException e) {
      LOGGER.error("Invalid algorithm parameters. Transformation name:" + transformation, e);
      throw e;
    } catch (NoSuchAlgorithmException e) {
      LOGGER.error("Algorithm not found. Transformation name:" + transformation, e);
      throw e;
    } catch (NoSuchPaddingException e) {
      LOGGER.error("Padding scheme not found. Transformation name:" + transformation, e);
      throw e;
    } catch (InvalidKeyException e) {
      LOGGER.error("Invalid key provided. Key:" + Util.toHexArray(key), e);
      throw e;
    }
  }

  protected static int aligned(final int length, final int blockSize) {
    final int align = length % blockSize;
    if (0 != align) {
      return length + blockSize - align;
    }
    return length;
  }
}
