package com.crypto.aes.service;

/**
 * Service interface for AES-256 encryption and decryption operations.
 */
public interface EncryptionService {

    /**
     * Encrypts the given plain text using AES-256 encryption.
     *
     * @param plainText the text to encrypt (must not be null or empty)
     * @return a Base64-encoded encrypted string
     * @throws IllegalArgumentException                 if {@code plainText} is null or empty
     * @throws com.crypto.aes.exception.CryptoException if encryption fails
     */
    String encrypt(String plainText);

    /**
     * Decrypts the given Base64-encoded encrypted text using AES-256 decryption.
     *
     * @param encryptedText the Base64-encoded encrypted text (must not be null or empty)
     * @return the decrypted plain text
     * @throws IllegalArgumentException                 if {@code encryptedText} is null or empty
     * @throws com.crypto.aes.exception.CryptoException if decryption fails
     */
    String decrypt(String encryptedText);
}
