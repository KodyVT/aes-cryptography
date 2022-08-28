package com.github.kodyvt.aes_cryptography.constants;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum CryptographySelector {
    CBC("AES/CBC/PKCS5Padding", "PBKDF2WithHmacSHA256", 16, 16, 0),
    GCM("AES/GCM/NoPadding", "PBKDF2WithHmacSHA256", 16, 12, 128);

    private final String type;
    private final String keyFactory;
    private final int saltSize;
    private final int ivSize;
    private final int tagSize;
}
