package com.github.kodyvt.aes_cryptography.components;

import com.github.kodyvt.aes_cryptography.constants.CryptographySelector;
import com.github.kodyvt.aes_cryptography.exceptions.CryptographyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

final class CryptographyCommons {
    private CryptographyCommons() {
    }

    public static SecretKey generateKeyFromPassword(CryptographySelector cryptographySelector, String password, byte[] salt) throws CryptographyException {
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(cryptographySelector.getKeyFactory());
            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);

            return new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");
        } catch (Exception e) {
            throw new CryptographyException("Exception generating key from password", e);
        }
    }

    public static void processFile(Cipher cipher, File inputFile, File outputFile) throws CryptographyException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFile)) {
            try (FileOutputStream fileOutputStream = new FileOutputStream(outputFile)) {
                byte[] inputBytes = new byte[64];
                int bytesRead;

                while ((bytesRead = fileInputStream.read(inputBytes)) != -1) {
                    byte[] outBytes = cipher.update(inputBytes, 0, bytesRead);
                    if (outBytes != null) {
                        fileOutputStream.write(outBytes);
                    }
                }

                byte[] outBytes = cipher.doFinal();
                if (outBytes != null) {
                    fileOutputStream.write(outBytes);
                }
            }
        } catch (Exception e) {
            throw new CryptographyException("Error during cryptography process", e);
        }
    }

    public static byte[] generateRandom(int numBytes) {
        byte[] returnValue = new byte[numBytes];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(returnValue);

        return returnValue;
    }

    public static byte[] generateKey(byte[] iv, byte[] salt) {
        byte[] complement = generateRandom(16);

        return ByteBuffer
                .allocate(iv.length + salt.length + complement.length)
                .put(iv)
                .put(salt)
                .put(complement)
                .array();
    }

    public static byte[] generateKey(byte[] iv, byte[] salt, byte[] encrypt) {
        return ByteBuffer
                .allocate(iv.length + salt.length + encrypt.length)
                .put(iv)
                .put(salt)
                .put(encrypt)
                .array();
    }
}
