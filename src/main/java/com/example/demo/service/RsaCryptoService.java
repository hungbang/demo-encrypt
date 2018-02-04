package com.example.demo.service;


import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static com.example.demo.service.AesCryptoService.cryptoProvider;

public class RsaCryptoService {

    public static final String CRYPTO_RSA_METHOD = "RSA/ECB/PKCS1Padding";
    public static final String CRYPTO_RSA_ALGORITHM = "RSA";

    public static byte[] encryptWithRSAPublicKey(PublicKey publicKey, byte[] dataEncrypted) {
        try {
            Cipher cipher = getCipherRSA(CRYPTO_RSA_METHOD);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return cipher.doFinal(dataEncrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected static Cipher getCipherRSA(String cipherType) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(cipherType, cryptoProvider);
        return cipher;
    }

    public static byte[] decryptWithRSAPrivatekey(PrivateKey privateKey, byte[] dataEncrypted) {
        try {
            Cipher cipher = getCipherRSA(CRYPTO_RSA_METHOD);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            return cipher.doFinal(dataEncrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
