package com.crypto.aes.utils;

import com.crypto.aes.exception.CryptoException;
import lombok.extern.log4j.Log4j2;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * Utility class providing AES-256 encryption and decryption using GCM mode.
 * <p>
 * Key derivation is performed using PBKDF2 with HMAC-SHA256.
 * The encrypted payload contains the IV prepended to the ciphertext.
 * </p>
 *
 * <b>Security Notes:</b>
 * <ul>
 *   <li>AES/GCM provides confidentiality and integrity.</li>
 *   <li>The IV is randomly generated for each encryption.</li>
 *   <li>Passwords and salts must be securely managed by the caller.</li>
 * </ul>
 */
@Log4j2
public class AES256 {
    /**
     * Algorithm used for deriving a cryptographic key from a password.
     */
    private static final String FACTORY_ALGO = "PBKDF2WithHmacSHA256";

    /**
     * Cipher transformation specifying AES encryption in Galois/Counter Mode (GCM)
     * with no padding.
     */
    private static final String CIPHER_ALGO = "AES/GCM/NoPadding";

    /**
     * Length of the Initialization Vector (IV) in bytes.
     */
    private static final int IV_LENGTH_BYTE = 12;

    /**
     * Length of the authentication tag in bits.
     */
    private static final int TAG_LENGTH_BIT = 128;

    /**
     * Length of the AES encryption key in bits.
     */
    private static final int KEY_LENGTH_BIT = 256;

    /**
     * Number of iterations used during password-based key derivation.
     */
    private static final int ITERATION_COUNT = 65536;

    /**
     * Private constructor to prevent instantiation.
     * <p>
     * This class is intended to be used as a utility class with static methods only.
     * </p>
     */
    private AES256() {
        // Prevent instantiation
    }

    /**
     * Encrypts plain text using AES-256-GCM.
     *
     * @param data     the data to encrypt
     * @param password  the password used for key derivation
     * @param salt      the salt used for key derivation
     * @return Base64-encoded encrypted string (IV + ciphertext)
     * @throws CryptoException if encryption fails
     */
    public static String encrypt(byte[] data, String password, String salt) {
        if (data == null || data.length == 0) {
            log.warn("Encryption skipped: input data is null or empty.");
            return null;
        }
        try {
            log.debug("Starting AES-256 encryption process.");
            byte[] iv = new byte[IV_LENGTH_BYTE];
            new SecureRandom().nextBytes(iv);

            SecretKeySpec keySpec = deriveKey(password, salt);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            byte[] cipherText = cipher.doFinal(data);

            byte[] combined = ByteBuffer.allocate(iv.length + cipherText.length)
                    .put(iv)
                    .put(cipherText)
                    .array();

            log.debug("Encryption successful. Payload size: {} bytes", combined.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception ex) {
            log.error("Encryption failed due to an unexpected error.", ex);
            throw new CryptoException("Unable to encrypt data securely.", ex);
        }
    }


    /**
     * Decrypts AES-256-GCM encrypted data.
     *
     * @param encryptedBase64 Base64-encoded encrypted payload (IV + ciphertext)
     * @param password        the password used for key derivation
     * @param salt            the salt used for key derivation
     * @return decrypted plain text
     * @throws CryptoException if decryption fails or payload is invalid
     */
    public static String decrypt(String encryptedBase64, String password, String salt) {
        if (encryptedBase64 == null || encryptedBase64.isEmpty()) {
            log.warn("Decryption skipped: encrypted input is null or empty.");
            return encryptedBase64;
        }
        try {
            log.debug("Starting AES-256 decryption process.");
            byte[] decoded = Base64.getDecoder().decode(encryptedBase64);

            if (decoded.length < IV_LENGTH_BYTE) {
                log.error("Invalid encrypted payload: insufficient length.");
                throw new IllegalArgumentException("Invalid encrypted payload.");
            }

            byte[] iv = new byte[IV_LENGTH_BYTE];
            System.arraycopy(decoded, 0, iv, 0, iv.length);

            byte[] cipherText = new byte[decoded.length - IV_LENGTH_BYTE];
            System.arraycopy(decoded, iv.length, cipherText, 0, cipherText.length);

            SecretKeySpec keySpec = deriveKey(password, salt);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            byte[] plainText = cipher.doFinal(cipherText);
            log.debug("Decryption completed successfully.");
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            log.error("Decryption failed due to an unexpected error.", ex);
            throw new CryptoException("Unable to decrypt data securely.", ex);
        }
    }


    /**
     * Derives an AES-256 key from a password and salt using PBKDF2.
     *
     * @param password the password
     * @param salt     the salt
     * @return derived AES secret key
     */
    private static SecretKeySpec deriveKey(String password, String salt) {
        Objects.requireNonNull(password, "Password required for key derivation");
        Objects.requireNonNull(salt, "Salt required for key derivation");

        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt.getBytes(StandardCharsets.UTF_8),
                ITERATION_COUNT,
                KEY_LENGTH_BIT
        );
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(FACTORY_ALGO);
            SecretKey secretKey = factory.generateSecret(spec);
            return new SecretKeySpec(secretKey.getEncoded(), "AES");
        } catch (Exception ex) {
            log.error("Key derivation failed using algorithm: {}", FACTORY_ALGO, ex);
            throw new CryptoException("Key derivation failed", ex);
        } finally {
            spec.clearPassword();
            log.debug("Password cleared from memory after key derivation.");
        }
    }
}
