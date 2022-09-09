package com.github.kodyvt.aes_cryptography.commons.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@AllArgsConstructor
public class EncryptProperties {
    private String publicKey;
    private String encryptString;
}
