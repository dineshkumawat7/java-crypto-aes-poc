package com.crypto.aes;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the AES Crypto Spring Boot application.
 * <p>
 * This class bootstraps the Spring application context and starts the embedded server.
 * </p>
 */
@SpringBootApplication
public class JavaCryptoAesPocApplication {

	/**
	 * Main method to start the Spring Boot application.
	 *
	 * @param args command-line arguments (optional)
	 */
	public static void main(String[] args) {
		SpringApplication.run(JavaCryptoAesPocApplication.class, args);
	}

}
