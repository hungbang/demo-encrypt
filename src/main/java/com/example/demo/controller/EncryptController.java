package com.example.demo.controller;


import com.example.demo.pojo.AESDataNeedToEncrypt;
import com.example.demo.pojo.DataNeedToDecrypt;
import com.example.demo.pojo.DataParam;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.io.Serializable;
import java.security.*;
import java.security.spec.*;

import org.apache.tomcat.util.codec.binary.Base64;

@RestController
public class EncryptController {


    private String keyValue = "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";

    protected static String cryptoProvider = "BC";

    private static final Object CRYPTO_ALGORITHM = "AES";

    @RequestMapping(value = "/encrypt", method = RequestMethod.POST)
    public ResponseEntity encryptData(@RequestBody DataParam dataParam) {
        byte[] byteEncrypted = encrypt(dataParam.getAesKey().getBytes(), dataParam.getData().getBytes());
        String dataEncrypted = Base64.encodeBase64String(byteEncrypted);
        return ResponseEntity.ok(dataEncrypted);
    }

    @RequestMapping(value = "/encryptKeyAES", method = RequestMethod.POST)
    public ResponseEntity encryptKeyAES(@RequestBody AESDataNeedToEncrypt dataParam) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(dataParam.getPublicKey()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        byte[] byteEncrypted = encryptWithRSAPublicKey(publicKey, dataParam.getAesKeyValue().getBytes());
        String dataEncrypted = Base64.encodeBase64String(byteEncrypted);
        return ResponseEntity.ok(dataEncrypted);
    }

    @RequestMapping(value = "/decrypt", method = RequestMethod.POST)
    public ResponseEntity decryptData(@RequestBody DataNeedToDecrypt dataParam) {
        String dataReturn = "";
        try {
            PrivateKey privateKey = getPrivateKeyByKeyValue(keyValue);
            byte[] dataEncryptKeyBytes = Base64.decodeBase64(dataParam.getAesKey());
            byte[] byteAesKey = decryptWithRSAPrivatekey(privateKey, dataEncryptKeyBytes);
            byte[] cipherValueBytes = Base64.decodeBase64(dataParam.getDataEncrypted());
            byte[] data = decrypt(byteAesKey, cipherValueBytes);
            dataReturn = String.valueOf(data);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return ResponseEntity.ok(dataReturn);
    }


    public byte[] decrypt(byte[] key, byte[] data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = getCipher("AES/CBC/PKCS7Padding");
            byte[] ivParam = createInitialVector(key, cipher.getBlockSize());
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(
                    ivParam));

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public byte[] encrypt(byte[] key, byte[] data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = getCipher("AES/CBC/PKCS7Padding");
            byte[] ivParam = createInitialVector(key, cipher.getBlockSize());
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(
                    ivParam));

            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected Cipher getCipher(String cipherType) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", cryptoProvider);
        return cipher;
    }

    protected Cipher getCipherRSA(String cipherType) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", cryptoProvider);
        return cipher;
    }

    protected byte[] createInitialVector(byte[] key, int blockSize) {
        byte[] ivParam = new byte[blockSize];
        System.arraycopy(key, 0, ivParam, 0, ivParam.length);
        return ivParam;
    }

    private WalletClientKeyPair getKeyPair(String key) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        WalletClientKeyPair walletClientKeyPair = objectMapper.readValue(key, WalletClientKeyPair.class);
        return walletClientKeyPair;
    }

    private String getPlainText(String base64EncodedCipher) {
        return new String(decrypt(PassPhraseKMSKeyProviderImpl.getKeyEncryptionKey(),
                Base64.decodeBase64(base64EncodedCipher)));
    }
    private PrivateKey getPrivateKeyByKeyValue(String keyValue) throws IOException {
        PrivateKey privateKey;
        try {
            String s = getPlainText(keyValue);
            byte[] privateKeyBytes = Base64.decodeBase64(getKeyPair(s).getPrivateKey());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

            privateKey = keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return privateKey;
    }

    private EncryptedData getEncryptedData(String s) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(s, EncryptedData.class);
    }


    public byte[] decryptWithRSAPrivatekey(PrivateKey privateKey, byte[] dataEncrypted) {
        try {
            Cipher cipher = getCipherRSA("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            return cipher.doFinal(dataEncrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encryptWithRSAPublicKey(PublicKey publicKey, byte[] dataEncrypted) {
        try {
            Cipher cipher = getCipherRSA("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return cipher.doFinal(dataEncrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}

class WalletClientKeyPair {

    private String privateKey;
    private String publicKey;

    public WalletClientKeyPair() {
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}

class EncryptedData implements Serializable {

    @NotNull
    private String encryptionMethod;

    @NotNull
    private String cipherValue;

    public String getEncryptionMethod() {
        return encryptionMethod;
    }

    public void setEncryptionMethod(String encryptionMethod) {
        this.encryptionMethod = encryptionMethod;
    }

    public String getCipherValue() {
        return cipherValue;
    }

    public void setCipherValue(String cipherValue) {
        this.cipherValue = cipherValue;
    }
}

class PassPhraseKMSKeyProviderImpl{

    private static final String KMS_ENCRYPTION_KEY = "qKLTvlBzNZeyaTGvnjx9gg==";




    public static byte[] getKeyEncryptionKey() {
        return Base64.decodeBase64(KMS_ENCRYPTION_KEY);
    }

}
