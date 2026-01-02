package com.crypto.aes.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration properties for AES encryption/decryption.
 * <p>
 * Reads password and salt from application.yaml under crypto.aes.*
 * </p>
 */
@Configuration
@ConfigurationProperties(prefix = "crypto.aes")
@Getter
@Setter
public class AESProperties {

    /**
     * Password used for AES key derivation.
     */
    private String password;

    /**
     * Salt used for AES key derivation.
     */
    private String salt;
}
