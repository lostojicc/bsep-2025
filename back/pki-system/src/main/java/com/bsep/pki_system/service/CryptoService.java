package com.bsep.pki_system.service;


import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.UUID;

@Service
public class CryptoService {

    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int AES_KEY_SIZE = 256;
    private static final int IV_SIZE = 16;

    /**
     * Generate a random AES key
     */
    public SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    /**
     * Encrypt text with AES key and random IV
     * Returns Base64( IV + ciphertext )
     */
    public String encryptAES(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] cipherText = cipher.doFinal(plainText.getBytes());

        // prepend IV to ciphertext
        byte[] ivAndCipher = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, ivAndCipher, 0, iv.length);
        System.arraycopy(cipherText, 0, ivAndCipher, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(ivAndCipher);
    }

    /**
     * Decrypt Base64( IV + ciphertext ) with AES key
     */
    public String decryptAES(String cipherBase64, SecretKey key) throws Exception {
        byte[] ivAndCipher = Base64.getDecoder().decode(cipherBase64);

        byte[] iv = new byte[IV_SIZE];
        byte[] cipherText = new byte[ivAndCipher.length - IV_SIZE];

        System.arraycopy(ivAndCipher, 0, iv, 0, IV_SIZE);
        System.arraycopy(ivAndCipher, IV_SIZE, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] plainBytes = cipher.doFinal(cipherText);
        return new String(plainBytes);
    }

    /**
     * Generate RSA key pair (4096 bits)
     */
    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(1024);
        return keyGen.generateKeyPair();
    }

    /**
     * Utility: encode key to Base64 for storing
     */
    public String encodeKey(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Utility: decode AES key from Base64
     */
    public SecretKey decodeAESKey(String base64Key) {
        byte[] decoded = Base64.getDecoder().decode(base64Key);
        return new javax.crypto.spec.SecretKeySpec(decoded, 0, decoded.length, "AES");
    }

    public String generateRandomPassword() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}