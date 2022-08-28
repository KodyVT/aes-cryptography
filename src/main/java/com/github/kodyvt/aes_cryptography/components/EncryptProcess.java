package com.github.kodyvt.aes_cryptography.components;

import com.github.kodyvt.aes_cryptography.constants.CryptographySelector;
import com.github.kodyvt.aes_cryptography.exceptions.CryptographyException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileOutputStream;
import java.util.Base64;

public final class EncryptProcess {
    private final CryptographySelector cryptographySelector;
    private final String password;

    public EncryptProcess(CryptographySelector cryptographySelector, String password) {
        this.cryptographySelector = cryptographySelector;
        this.password = password;
    }

    public File encryptFileWhitFileKey(File inputFile, File outputFile, boolean deleteInputFile) throws CryptographyException {
        if (Boolean.TRUE.equals(inputFile.isFile())) {
            byte[] encryptKey = this.encryptFile(inputFile, outputFile, deleteInputFile);

            return this.generateFileKey(outputFile, encryptKey);
        } else {
            throw new CryptographyException("Input file is a directory, encryption is not possible");
        }
    }

    public String encryptFileWhitStringKey(File inputFile, File outputFile, boolean deleteInputFile) throws CryptographyException {
        if (Boolean.TRUE.equals(inputFile.isFile())) {
            byte[] encryptKey = this.encryptFile(inputFile, outputFile, deleteInputFile);

            return this.generateStringKey(encryptKey);
        } else {
            throw new CryptographyException("Input file is a directory, encryption is not possible");
        }
    }

    public String encryptString(String inputString) throws CryptographyException {
        try {
            byte[] iv = CryptographyCommons.generateRandom(this.cryptographySelector.getIvSize());
            byte[] salt = CryptographyCommons.generateRandom(this.cryptographySelector.getSaltSize());

            Cipher cipher = this.initializeCipher(iv, salt);
            byte[] encrypt = CryptographyCommons.generateKey(iv, salt, cipher.doFinal(inputString.getBytes()));

            return Base64.getEncoder().encodeToString(encrypt);
        } catch (Exception e) {
            throw new CryptographyException("Error encrypting file", e);
        }
    }

    private byte[] encryptFile(File inputFile, File outputFile, boolean deleteInputFile) throws CryptographyException {
        try {
            byte[] iv = CryptographyCommons.generateRandom(this.cryptographySelector.getIvSize());
            byte[] salt = CryptographyCommons.generateRandom(this.cryptographySelector.getSaltSize());

            Cipher cipher = this.initializeCipher(iv, salt);
            CryptographyCommons.processFile(cipher, inputFile, outputFile);

            if (Boolean.TRUE.equals(deleteInputFile)) {
                FileUtils.forceDelete(inputFile);
            }

            return CryptographyCommons.generateKey(iv, salt);
        } catch (Exception e) {
            throw new CryptographyException("Error encrypting file", e);
        }
    }

    private Cipher initializeCipher(byte[] iv, byte[] salt) throws CryptographyException {
        try {
            Cipher cipher = Cipher.getInstance(this.cryptographySelector.getType());
            SecretKey secretKey = CryptographyCommons.generateKeyFromPassword(this.cryptographySelector, this.password, salt);

            switch (this.cryptographySelector) {
                case CBC -> cipher.init(
                        Cipher.ENCRYPT_MODE
                        , secretKey
                        , new IvParameterSpec(iv)
                );
                case GCM -> cipher.init(
                        Cipher.ENCRYPT_MODE, secretKey
                        , new GCMParameterSpec(this.cryptographySelector.getTagSize(), iv)
                );
                default -> throw new CryptographyException("The encryption option is not valid");
            }

            return cipher;
        } catch (Exception e) {
            throw new CryptographyException("Error initializing process", e);
        }
    }

    private File generateFileKey(File outputFile, byte[] key) throws CryptographyException {
        File keyReturn = new File(String.format("%s/%s.key", outputFile.getParent(), FilenameUtils.removeExtension(outputFile.getName())));

        try (FileOutputStream outputStream = new FileOutputStream(keyReturn)) {
            outputStream.write(key);

            return keyReturn;
        } catch (Exception e) {
            throw new CryptographyException("Error generating decryption key", e);
        }
    }

    private String generateStringKey(byte[] key) {
        return Base64.getEncoder().encodeToString(key);
    }
}
