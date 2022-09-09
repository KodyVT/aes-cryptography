package com.github.kodyvt.aes_cryptography.commons.components;

import com.github.kodyvt.aes_cryptography.commons.constants.CryptographySelector;
import com.github.kodyvt.aes_cryptography.commons.exceptions.CryptographyException;
import com.github.kodyvt.aes_cryptography.commons.models.EncryptProperties;
import lombok.RequiredArgsConstructor;
import org.apache.commons.io.FilenameUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.util.Base64;

import static com.github.kodyvt.aes_cryptography.commons.components.CryptographyCommons.generateRandomArray;

@RequiredArgsConstructor
public final class EncryptProcess {
    public static final String TEMPORAL_NAME = "encrypt.enc";
    public static final String DIRECTORY_ERROR = "Input file is a directory, encryption is not possible";
    public static final String ENCRYPT_ERROR = "Error encrypting file";
    private final CryptographySelector cryptographySelector;
    private final String password;

    public File encryptFileWhitFilePublicKey(File inputFile) throws CryptographyException {
        if (Boolean.TRUE.equals(inputFile.isFile())) {
            byte[] encryptKey = this.encryptFile(inputFile);

            return this.generateFileKey(inputFile, encryptKey);
        } else {
            throw new CryptographyException(DIRECTORY_ERROR);
        }
    }

    public File encryptFileWhitFilePublicKey(File inputFile, File outputFile, boolean deleteInputFile) throws CryptographyException {
        if (Boolean.TRUE.equals(inputFile.isFile())) {
            byte[] encryptKey = this.encryptFile(inputFile, outputFile, deleteInputFile);

            return this.generateFileKey(outputFile, encryptKey);
        } else {
            throw new CryptographyException(DIRECTORY_ERROR);
        }
    }

    public String encryptFileWhitStringPublicKey(File inputFile) throws CryptographyException {
        if (Boolean.TRUE.equals(inputFile.isFile())) {
            byte[] encryptKey = this.encryptFile(inputFile);

            return this.generateStringKey(encryptKey);
        } else {
            throw new CryptographyException(DIRECTORY_ERROR);
        }
    }

    public String encryptFileWhitStringPublicKey(File inputFile, File outputFile, boolean deleteInputFile) throws CryptographyException {
        if (Boolean.TRUE.equals(inputFile.isFile())) {
            byte[] encryptKey = this.encryptFile(inputFile, outputFile, deleteInputFile);

            return this.generateStringKey(encryptKey);
        } else {
            throw new CryptographyException(DIRECTORY_ERROR);
        }
    }

    public String encryptString(String inputString) throws CryptographyException {
        try {
            byte[] iv = CryptographyCommons.generateRandomArray(this.cryptographySelector.getIvSize());
            byte[] salt = CryptographyCommons.generateRandomArray(this.cryptographySelector.getSaltSize());

            Cipher cipher = this.initializeCipher(iv, salt);
            byte[] encryptArray = cipher.doFinal(inputString.getBytes());
            byte[] encryptKey = this.generatePublicKey(iv, salt);


            byte[] encrypt = ByteBuffer.allocate(encryptKey.length + encryptArray.length)
                    .put(encryptKey)
                    .put(encryptArray)
                    .array();

            return Base64.getEncoder().encodeToString(encrypt);
        } catch (Exception e) {
            throw new CryptographyException(ENCRYPT_ERROR, e);
        }
    }

    public EncryptProperties encryptStringWhitPublicKey(String inputString) throws CryptographyException {
        try {
            byte[] iv = CryptographyCommons.generateRandomArray(this.cryptographySelector.getIvSize());
            byte[] salt = CryptographyCommons.generateRandomArray(this.cryptographySelector.getSaltSize());

            Cipher cipher = this.initializeCipher(iv, salt);
            byte[] encryptArray = cipher.doFinal(inputString.getBytes());
            byte[] publicKey = this.generatePublicKey(iv, salt);

            return new EncryptProperties(
                    Base64.getEncoder().encodeToString(publicKey),
                    Base64.getEncoder().encodeToString(encryptArray)
            );
        } catch (Exception e) {
            throw new CryptographyException(ENCRYPT_ERROR, e);
        }
    }

    private byte[] encryptFile(File inputFile) throws CryptographyException {
        File outputFile = new File(String.format("%s/%s", inputFile.getParent(), TEMPORAL_NAME));

        byte[] publicKey = this.encryptFile(inputFile, outputFile, true);
        if (Boolean.FALSE.equals(outputFile.renameTo(inputFile))) {
            throw new CryptographyException("Error renaming original file after crypto process");
        }

        return publicKey;
    }

    private byte[] encryptFile(File inputFile, File outputFile, boolean deleteInputFile) throws CryptographyException {
        try {
            byte[] iv = generateRandomArray(this.cryptographySelector.getIvSize());
            byte[] salt = generateRandomArray(this.cryptographySelector.getSaltSize());

            Cipher cipher = this.initializeCipher(iv, salt);
            CryptographyCommons.processFile(cipher, inputFile, outputFile, deleteInputFile);

            return this.generatePublicKey(iv, salt);
        } catch (Exception e) {
            throw new CryptographyException(ENCRYPT_ERROR, e);
        }
    }

    private Cipher initializeCipher(byte[] iv, byte[] salt) throws CryptographyException {
        try {
            Cipher cipher = Cipher.getInstance(this.cryptographySelector.getType());
            SecretKey secretKey = CryptographyCommons.generateSecretKey(this.cryptographySelector, this.password, salt);

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

    private byte[] generatePublicKey(byte[] iv, byte[] salt) {
        byte[] complement = CryptographyCommons.generateRandomArray(CryptographySelector.CBC.getComplementSize());

        return ByteBuffer.allocate(iv.length + salt.length + complement.length)
                .put(iv)
                .put(salt)
                .put(complement)
                .array();
    }
}
