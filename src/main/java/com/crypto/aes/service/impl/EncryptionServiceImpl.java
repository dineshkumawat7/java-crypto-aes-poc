package com.crypto.aes.service.impl;

import com.crypto.aes.config.AESProperties;
import com.crypto.aes.exception.CryptoException;
import com.crypto.aes.service.EncryptionService;
import com.crypto.aes.utils.AES256;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Service implementation for AES-256 encryption and decryption.
 * <p>
 * Uses {@link AESProperties} to fetch password and salt from configuration.
 * Wraps AES256 utility and handles logging and validation of input data.
 * </p>
 */
@Log4j2
@Service
public class EncryptionServiceImpl implements EncryptionService {

    @Autowired
    private AESProperties aesProperties;

    /**
     * Encrypts the given plain text using AES-256-GCM.
     *
     * @param plainText plain text to encrypt
     * @return Base64-encoded encrypted string
     * @throws CryptoException if encryption fails
     */
    @Override
    public String encrypt(String plainText) {
        if (!StringUtils.hasText(plainText)) {
            log.warn("Encryption requested with null or empty input data.");
            throw new IllegalArgumentException("Input data cannot be null or empty for encryption.");
        }

        try {
            log.debug("Starting encryption for input data (length: {}).", plainText.length());
            String encryptedData = AES256.encrypt(plainText, aesProperties.getPassword(), aesProperties.getSalt());
            log.info("Encryption completed successfully (input length: {}, encrypted length: {}).",
                    plainText.length(), encryptedData.length());
            return encryptedData;
        } catch (CryptoException ex) {
            log.error("Encryption failed due to a cryptographic error.", ex);
            throw ex;
        } catch (Exception ex) {
            log.error("Unexpected error occurred during encryption.", ex);
            throw new CryptoException("Encryption failed due to unexpected error.", ex);
        }
    }

    /**
     * Decrypts the given Base64-encoded encrypted string using AES-256-GCM.
     *
     * @param encryptedText Base64-encoded encrypted text
     * @return decrypted plain text
     * @throws CryptoException if decryption fails
     */
    @Override
    public String decrypt(String encryptedText) {
        if (!StringUtils.hasText(encryptedText)) {
            log.warn("Decryption requested with null or empty input data.");
            throw new IllegalArgumentException("Input data cannot be null or empty for decryption.");
        }

        try {
            log.debug("Starting decryption for input data (length: {}).", encryptedText.length());
            String decryptedData = AES256.decrypt(encryptedText, aesProperties.getPassword(), aesProperties.getSalt());
            log.info("Decryption completed successfully (encrypted length: {}, output length: {}).",
                    encryptedText.length(), decryptedData.length());
            return decryptedData;
        } catch (CryptoException ex) {
            log.error("Decryption failed due to a cryptographic error.", ex);
            throw ex;
        } catch (Exception ex) {
            log.error("Unexpected error occurred during decryption.", ex);
            throw new CryptoException("Decryption failed due to unexpected error.", ex);
        }
    }
}
