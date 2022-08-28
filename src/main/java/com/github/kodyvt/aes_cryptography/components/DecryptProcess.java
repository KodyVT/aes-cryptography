package com.github.kodyvt.aes_cryptography.components;

import com.github.kodyvt.aes_cryptography.constants.CryptographySelector;
import com.github.kodyvt.aes_cryptography.exceptions.CryptographyException;
import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.Base64;

public final class DecryptProcess {
    private final CryptographySelector cryptographySelector;
    private final String password;

    public DecryptProcess(CryptographySelector cryptographySelector, String password) {
        this.cryptographySelector = cryptographySelector;
        this.password = password;
    }

    public void decryptFileWhitKey(File inputFile, File outputFile, File fileKey, boolean deleteInputFile) throws CryptographyException {
        if (Boolean.TRUE.equals(inputFile.isFile())) {
            ByteBuffer byteBuffer;
            try {
                byteBuffer = ByteBuffer.wrap(Files.readAllBytes(fileKey.toPath()));
                byte[] iv = new byte[this.cryptographySelector.getIvSize()];
                byteBuffer.get(iv);
                byte[] salt = new byte[this.cryptographySelector.getSaltSize()];
                byteBuffer.get(salt);

                this.decryptFile(inputFile, outputFile, salt, iv);

                if (Boolean.TRUE.equals(deleteInputFile)) {
                    FileUtils.forceDelete(inputFile);
                    FileUtils.forceDelete(fileKey);
                }
            } catch (IOException e) {
                throw new CryptographyException("Could not read the key", e);
            }
        } else {
            throw new CryptographyException("Input file is a directory, encryption is not possible");
        }
    }

    public void decryptFileWhitKey(File inputFile, File outputFile, String stringKey, boolean deleteInputFile) throws CryptographyException {
        if (Boolean.TRUE.equals(inputFile.isFile())) {
            ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(stringKey));

            try {
                byte[] iv = new byte[this.cryptographySelector.getIvSize()];
                byteBuffer.get(iv);
                byte[] salt = new byte[this.cryptographySelector.getSaltSize()];
                byteBuffer.get(salt);

                this.decryptFile(inputFile, outputFile, salt, iv);

                if (Boolean.TRUE.equals(deleteInputFile)) {
                    FileUtils.forceDelete(inputFile);
                }
            } catch (IOException e) {
                throw new CryptographyException("Could not read the key", e);
            }
        } else {
            throw new CryptographyException("Input file is a directory, encryption is not possible");
        }
    }

    public String decryptString(String inputString) throws CryptographyException {
        try {
            byte[] encryptBytes = Base64.getDecoder().decode(inputString);

            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptBytes);
            byte[] iv = new byte[this.cryptographySelector.getIvSize()];
            byteBuffer.get(iv);
            byte[] salt = new byte[this.cryptographySelector.getSaltSize()];
            byteBuffer.get(salt);
            byte[] encoder = new byte[encryptBytes.length - (this.cryptographySelector.getIvSize() + this.cryptographySelector.getSaltSize())];
            byteBuffer.get(encoder);

            Cipher cipher = this.initializeCipher(iv, salt);
            return new String(cipher.doFinal(encoder));
        } catch (Exception e) {
            throw new CryptographyException("Error decrypting file", e);
        }
    }

    private void decryptFile(File inputFile, File outputFile, byte[] salt, byte[] iv) throws CryptographyException {
        try {
            Cipher cipher = this.initializeCipher(iv, salt);
            CryptographyCommons.processFile(cipher, inputFile, outputFile);
        } catch (Exception e) {
            throw new CryptographyException("Error decrypting file", e);
        }
    }

    private Cipher initializeCipher(byte[] iv, byte[] salt) throws CryptographyException {
        try {
            Cipher cipher = Cipher.getInstance(this.cryptographySelector.getType());
            SecretKey secretKey = CryptographyCommons.generateKeyFromPassword(this.cryptographySelector, this.password, salt);

            switch (this.cryptographySelector) {
                case CBC -> cipher.init(
                        Cipher.DECRYPT_MODE
                        , secretKey
                        , new IvParameterSpec(iv)
                );
                case GCM -> cipher.init(
                        Cipher.DECRYPT_MODE
                        , secretKey
                        , new GCMParameterSpec(this.cryptographySelector.getTagSize(), iv)
                );
                default -> throw new CryptographyException("The decryption option is not valid");
            }

            return cipher;
        } catch (Exception e) {
            throw new CryptographyException("Error initializing process", e);
        }
    }
}
