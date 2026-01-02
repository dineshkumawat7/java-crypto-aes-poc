package com.crypto.aes.controller;

import com.crypto.aes.exception.ServiceException;
import com.crypto.aes.service.EncryptionService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
    @PostMapping(value = "/encrypt/text", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> encryptText(@RequestBody(required = false) String planText) {
        if (planText == null || planText.isBlank()) {
            log.warn("Encryption request received with empty or null data.");
            return ResponseEntity.badRequest().body("Input data cannot be empty.");
        }

        try {
            log.info("Processing encryption request for payload: {}", planText);
            String encryptedData = encryptionService.encrypt(planText.getBytes(StandardCharsets.UTF_8));
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
    public ResponseEntity<String> decrypt(@RequestBody(required = false) String encryptedData) {
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

    /**
     * Encrypts an uploaded file using AES-256.
     *
     * @param file the uploaded file
     * @return encrypted data as Base64 string
     */
    @PostMapping(value = "/encrypt/media", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> encryptMedia(@RequestParam("file") MultipartFile file) {
        if (file == null || file.isEmpty()) {
            log.warn("Encryption request received with empty or null file.");
            return ResponseEntity.badRequest().body("File cannot be empty.");
        }

        try {
            log.info("Processing encryption request for file: {} (size: {} bytes)", file.getOriginalFilename(), file.getSize());
            byte[] fileBytes = file.getBytes();
            String encryptedData = encryptionService.encrypt(fileBytes);
            log.info("Encryption successful for file: {} (size: {} bytes)", file.getOriginalFilename(), file.getSize());
            return ResponseEntity.ok(encryptedData);
        } catch (IOException e) {
            log.error("Failed to read uploaded file.", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to read the uploaded file.");
        } catch (ServiceException ex) {
            log.error("Encryption failed due to a cryptographic error.", ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Encryption failed. Please try again later.");
        }
    }

    /**
     * Decrypts Base64-encoded encrypted media (any type: PDF, image, video, etc.)
     * and returns it as a downloadable file.
     *
     * <p>The client must provide the encrypted data as a Base64 string in the request body.
     * The server decrypts it using AES-256 and returns the raw bytes with the specified filename.
     * The Content-Type is set to 'application/octet-stream' so the client can handle any file type.</p>
     *
     * @param encryptedData Base64-encoded encrypted file content
     * @param filename      Optional filename for the downloaded file (default: "decrypted-file")
     * @return ResponseEntity containing the decrypted bytes ready for download
     */
    @PostMapping(value = "/decrypt/media", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> decryptFile(@RequestBody(required = false) String encryptedData,
                                              @RequestParam(value = "filename", defaultValue = "decrypted-file") String filename) {
        if (encryptedData == null || encryptedData.isBlank()) {
            log.warn("Decryption request with empty or null data.");
            return ResponseEntity.badRequest().body(null);
        }

        try {
            log.info("Starting decryption for file: '{}', encrypted payload length: {} characters",
                    filename, encryptedData.length());
            byte[] decryptedBytes = encryptionService.decrypt(encryptedData).getBytes();

            log.info("Decryption successful for file: '{}', decrypted size: {} bytes",
                    filename, decryptedBytes.length);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE)
                    .body(decryptedBytes);
        } catch (ServiceException ex) {
            log.error("Decryption failed due to a cryptographic error for file: '{}'", filename, ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }
}
