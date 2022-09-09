package com.github.kodyvt.aes_cryptography.commons.exceptions;

public class CryptographyException extends Exception {
    public CryptographyException(String message) {
        super(message);
    }

    public CryptographyException(String message, Throwable cause) {
        super(message, cause);
    }
}