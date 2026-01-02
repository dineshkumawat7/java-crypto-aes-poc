package com.crypto.aes.service;

/**
 * Service interface for AES-256 encryption and decryption operations.
 */
public interface EncryptionService {

    /**
     * Encrypts the given data using AES-256-GCM encryption.
     *
     * <p>This method supports both text and binary data. The encrypted output
     * is a Base64-encoded string that includes the IV and ciphertext.</p>
     *
     * @param data the input data to encrypt (must not be null or empty)
     * @return a Base64-encoded encrypted string containing IV + ciphertext
     * @throws IllegalArgumentException                 if {@code data} is null or empty
     * @throws com.crypto.aes.exception.CryptoException if encryption fails
     */
    String encrypt(byte[] data);

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
