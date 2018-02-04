package com.example.demo.service;


import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class AesCryptoService {
    private static final String CRYPTO_ALGORITHM = "AES";
    private static final String CRYPTO_AES_METHOD = "AES/CBC/PKCS7Padding";
    protected static String cryptoProvider = "BC";


    public static byte[] encrypt(byte[] key, byte[] data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, CRYPTO_ALGORITHM);
            Cipher cipher = getCipher(CRYPTO_AES_METHOD);
            byte[] ivParam = createInitialVector(key, cipher.getBlockSize());
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(
                    ivParam));

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(byte[] key, byte[] data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, CRYPTO_ALGORITHM);
            Cipher cipher = getCipher(CRYPTO_AES_METHOD);
            byte[] ivParam = createInitialVector(key, cipher.getBlockSize());
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(
                    ivParam));

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    protected static Cipher getCipher(String cipherType) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(cipherType, cryptoProvider);
        return cipher;
    }

    protected static byte[] createInitialVector(byte[] key, int blockSize) {
        byte[] ivParam = new byte[blockSize];
        System.arraycopy(key, 0, ivParam, 0, ivParam.length);
        return ivParam;
    }
}
