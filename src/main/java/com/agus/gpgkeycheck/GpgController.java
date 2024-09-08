package com.agus.gpgkeycheck;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;

@RestController
@RequestMapping("/api/gpg")
public class GpgController {
    @PostMapping("/validate")
    public ResponseEntity<String> validateGpgKey(
            @RequestParam("file") MultipartFile file,
            @RequestParam("passphrase") String passphrase) {

        try (InputStream inputStream = file.getInputStream()) {
            boolean isValid = GpgKeyValidator.validatePassphrase(inputStream.readAllBytes(), passphrase);
            if (isValid) {
                return ResponseEntity.ok("Valid GPG key and passphrase.");
            } else {
                return ResponseEntity.badRequest().body("Invalid GPG key or passphrase.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("An error occurred while validating the GPG key.");
        }
    }
}
