package com.example.validation_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ValidationServiceApplication {

	public static void main(String[] args) {
		System.setProperty("com.sun.security.enableCRLDP", "true");
		System.setProperty("com.sun.security.enableAIA", "true");
		System.setProperty("com.sun.net.ssl.checkRevocation", "true");

		SpringApplication.run(ValidationServiceApplication.class, args);
	}
}