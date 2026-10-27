package com.cybershield.detector;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.TimeZone;

@SpringBootApplication
public class CyberShieldApplication {

    public static void main(String[] args) {
        // Enforce UTC timezone for consistent timestamps
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        SpringApplication.run(CyberShieldApplication.class, args);
    }
}
