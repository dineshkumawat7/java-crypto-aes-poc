package com.crypto.aes.exception;

/**
 * Custom runtime exception for cryptographic operations.
 * <p>
 * This exception is used to wrap underlying cryptographic exceptions
 * (e.g., encryption/decryption failures, key derivation errors)
 * and provide a consistent exception type for AES-related operations.
 * </p>
 */
public class CryptoException extends RuntimeException {

    /**
     * Constructs a new CryptoException with the specified detail message and cause.
     *
     * @param message the detail message explaining the reason for the exception
     * @param cause   the underlying exception that triggered this exception
     */
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new CryptoException with the specified detail message.
     *
     * @param message the detail message explaining the reason for the exception
     */
    public CryptoException(String message) {
        super(message);
    }
}
