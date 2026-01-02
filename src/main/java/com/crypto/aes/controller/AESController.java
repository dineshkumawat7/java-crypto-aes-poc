package com.crypto.aes.controller;

import com.crypto.aes.exception.ServiceException;
import com.crypto.aes.service.EncryptionService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * REST controller for AES-256 encryption and decryption endpoints.
 * <p>
 * Provides API endpoints to encrypt and decrypt data using AES-256-GCM.
 * Uses {@link EncryptionService} for actual cryptographic operations.
 * </p>
 */
@Log4j2
@RestController
@RequestMapping("api/v1/aes/")
public class AESController {

    @Autowired
    private EncryptionService encryptionService;

    /**
     * Health check endpoint.
     *
     * @return a simple JSON indicating service status
     */
    @GetMapping(value = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getHealth() {
        log.debug("Health check requested.");
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("status", "UP");
        return ResponseEntity.ok(health);
    }

    /**
     * Encrypts plain text using AES-256.
     *
     * @param planText plain text to encrypt
     * @return encrypted data as Base64 string
     */
    @PostMapping(value = "/encrypt", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> encrypt(@RequestBody String planText) {
        if (planText == null || planText.isBlank()) {
            log.warn("Encryption request received with empty or null data.");
            return ResponseEntity.badRequest().body("Input data cannot be empty.");
        }

        try {
            log.info("Processing encryption request for payload: {}", planText);
            String encryptedData = encryptionService.encrypt(planText);
            log.info("Encryption successful for request payload (length: {}).", planText.length());
            return ResponseEntity.ok(encryptedData);
        } catch (ServiceException ex) {
            log.error("Encryption failed due to a cryptographic error.", ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Encryption failed. Please try again later.");
        }
    }

    /**
     * Decrypts Base64 encrypted data using AES-256.
     *
     * @param encryptedData Base64-encoded encrypted text
     * @return decrypted plain text
     */
    @PostMapping(value = "/decrypt", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> decrypt(@RequestBody String encryptedData) {
        if (encryptedData == null || encryptedData.isBlank()) {
            log.warn("Decryption request received with empty or null data.");
            return ResponseEntity.badRequest().body("Input data cannot be empty.");
        }

        try {
            log.info("Processing decryption request for payload: {}", encryptedData);
            String decryptedData = encryptionService.decrypt(encryptedData);
            log.info("Decryption successful for request payload (length: {}).", encryptedData.length());
            return ResponseEntity.ok(decryptedData);
        } catch (ServiceException ex) {
            log.error("Decryption failed due to a cryptographic error.", ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Decryption failed. Please ensure the encrypted data is valid.");
        }
    }
}
