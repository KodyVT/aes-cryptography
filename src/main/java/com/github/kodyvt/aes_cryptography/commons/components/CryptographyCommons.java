package com.github.kodyvt.aes_cryptography.commons.components;

import com.github.kodyvt.aes_cryptography.commons.constants.CryptographySelector;
import com.github.kodyvt.aes_cryptography.commons.exceptions.CryptographyException;
import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

final class CryptographyCommons {
    public static final String ALGORITHM = "AES";

    private CryptographyCommons() {
    }

    public static SecretKey generateSecretKey(CryptographySelector cryptographySelector, String password, byte[] salt) throws CryptographyException {
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(cryptographySelector.getKeyFactory());
            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);

            return new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), ALGORITHM);
        } catch (Exception e) {
            throw new CryptographyException("Exception when generating the secret key", e);
        }
    }

    public static byte[] generateRandomArray(int numberBytes) {
        byte[] returnValue = new byte[numberBytes];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(returnValue);

        return returnValue;
    }

    public static void processFile(Cipher cipher, File inputFile, File outputFile, boolean deleteInputFile) throws CryptographyException {
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

            if (Boolean.TRUE.equals(deleteInputFile)) {
                FileUtils.forceDelete(inputFile);
            }
        } catch (Exception e) {
            throw new CryptographyException("Error during cryptography process", e);
        }
    }
}
