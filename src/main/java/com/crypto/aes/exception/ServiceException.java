package com.crypto.aes.exception;

/**
 * Custom runtime exception for service layer errors.
 * <p>
 * This exception is intended to be used in service classes to indicate
 * failures unrelated to cryptography (e.g., business logic, validation errors,
 * or integration issues) while providing a consistent exception type.
 * </p>
 */
public class ServiceException extends RuntimeException {

    /**
     * Constructs a new ServiceException with the specified detail message and cause.
     *
     * @param message the detail message explaining the reason for the exception
     * @param cause   the underlying exception that triggered this exception
     */
    public ServiceException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new ServiceException with the specified detail message.
     *
     * @param message the detail message explaining the reason for the exception
     */
    public ServiceException(String message) {
        super(message);
    }
}
