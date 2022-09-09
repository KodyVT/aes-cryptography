package com.github.kodyvt.aes_cryptography.commons.components;

import com.github.kodyvt.aes_cryptography.commons.constants.CryptographySelector;
import com.github.kodyvt.aes_cryptography.commons.exceptions.CryptographyException;
import com.github.kodyvt.aes_cryptography.commons.models.EncryptProperties;
import lombok.RequiredArgsConstructor;
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

@RequiredArgsConstructor
public final class DecryptProcess {
    public static final String TEMPORAL_NAME = "decrypt.dec";
    public static final String DIRECTORY_ERROR = "Input file is a directory, decryption is not possible";
    public static final String DECRYPT_ERROR = "Error decrypting file";
    private final CryptographySelector cryptographySelector;
    private final String password;

    public void decryptFileWhitKey(File inputFile, File fileKey) throws CryptographyException {
        if (Boolean.TRUE.equals(inputFile.isFile())) {
            ByteBuffer byteBuffer;
            try {
                byteBuffer = ByteBuffer.wrap(Files.readAllBytes(fileKey.toPath()));
                byte[] iv = new byte[this.cryptographySelector.getIvSize()];
                byteBuffer.get(iv);
                byte[] salt = new byte[this.cryptographySelector.getSaltSize()];
                byteBuffer.get(salt);

                this.decryptFile(inputFile, salt, iv);
                FileUtils.forceDelete(fileKey);
            } catch (IOException e) {
                throw new CryptographyException("Could not read the key", e);
            }
        } else {
            throw new CryptographyException(DIRECTORY_ERROR);
        }
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

                this.decryptFile(inputFile, outputFile, salt, iv, deleteInputFile);

                if (Boolean.TRUE.equals(deleteInputFile)) {
                    FileUtils.forceDelete(inputFile);
                    FileUtils.forceDelete(fileKey);
                }
            } catch (IOException e) {
                throw new CryptographyException("Could not read the key", e);
            }
        } else {
            throw new CryptographyException(DIRECTORY_ERROR);
        }
    }

    public void decryptFileWhitKey(File inputFile, String stringKey) throws CryptographyException {
        if (Boolean.TRUE.equals(inputFile.isFile())) {
            ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(stringKey));
            byte[] iv = new byte[this.cryptographySelector.getIvSize()];
            byteBuffer.get(iv);
            byte[] salt = new byte[this.cryptographySelector.getSaltSize()];
            byteBuffer.get(salt);

            this.decryptFile(inputFile, salt, iv);
        } else {
            throw new CryptographyException(DIRECTORY_ERROR);
        }
    }

    public void decryptFileWhitKey(File inputFile, File outputFile, String stringKey, boolean deleteInputFile) throws CryptographyException {
        if (Boolean.TRUE.equals(inputFile.isFile())) {
            ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(stringKey));
            byte[] iv = new byte[this.cryptographySelector.getIvSize()];
            byteBuffer.get(iv);
            byte[] salt = new byte[this.cryptographySelector.getSaltSize()];
            byteBuffer.get(salt);

            this.decryptFile(inputFile, outputFile, salt, iv, deleteInputFile);
        } else {
            throw new CryptographyException(DIRECTORY_ERROR);
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
            byte[] complement = new byte[this.cryptographySelector.getComplementSize()];
            byteBuffer.get(complement);
            byte[] encoder = new byte[encryptBytes.length - (this.cryptographySelector.getIvSize() + this.cryptographySelector.getSaltSize() + this.cryptographySelector.getComplementSize())];
            byteBuffer.get(encoder);

            Cipher cipher = this.initializeCipher(iv, salt);
            return new String(cipher.doFinal(encoder));
        } catch (Exception e) {
            throw new CryptographyException(DECRYPT_ERROR, e);
        }
    }

    public String decryptString(EncryptProperties encryptProperties) throws CryptographyException {
        try {
            byte[] encryptBytes = Base64.getDecoder().decode(encryptProperties.getEncryptString());
            byte[] publicKey = Base64.getDecoder().decode(encryptProperties.getPublicKey());

            ByteBuffer byteBuffer = ByteBuffer.wrap(publicKey);
            byte[] iv = new byte[this.cryptographySelector.getIvSize()];
            byteBuffer.get(iv);
            byte[] salt = new byte[this.cryptographySelector.getSaltSize()];
            byteBuffer.get(salt);

            Cipher cipher = this.initializeCipher(iv, salt);
            return new String(cipher.doFinal(encryptBytes));
        } catch (Exception e) {
            throw new CryptographyException(DECRYPT_ERROR, e);
        }
    }

    public String decryptString(String publicKey, String encryptString) throws CryptographyException {
        EncryptProperties encryptProperties = new EncryptProperties(publicKey, encryptString);

        return this.decryptString(encryptProperties);
    }

    private void decryptFile(File inputFile, byte[] salt, byte[] iv) throws CryptographyException {
        try {
            File outputFile = new File(String.format("%s/%s", inputFile.getParent(), TEMPORAL_NAME));

            Cipher cipher = this.initializeCipher(iv, salt);
            CryptographyCommons.processFile(cipher, inputFile, outputFile, true);

            if (Boolean.FALSE.equals(outputFile.renameTo(inputFile))) {
                throw new CryptographyException("Error renaming original file after crypto process");
            }
        } catch (Exception e) {
            throw new CryptographyException(DECRYPT_ERROR, e);
        }
    }

    private void decryptFile(File inputFile, File outputFile, byte[] salt, byte[] iv, boolean deleteInputFile) throws CryptographyException {
        try {
            Cipher cipher = this.initializeCipher(iv, salt);
            CryptographyCommons.processFile(cipher, inputFile, outputFile, deleteInputFile);
        } catch (Exception e) {
            throw new CryptographyException(DECRYPT_ERROR, e);
        }
    }

    private Cipher initializeCipher(byte[] iv, byte[] salt) throws CryptographyException {
        try {
            Cipher cipher = Cipher.getInstance(this.cryptographySelector.getType());
            SecretKey secretKey = CryptographyCommons.generateSecretKey(this.cryptographySelector, this.password, salt);

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
