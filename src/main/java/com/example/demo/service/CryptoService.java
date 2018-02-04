package com.example.demo.service;



import com.example.demo.pojo.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tomcat.util.codec.binary.Base64;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Properties;

import static com.example.demo.service.AesCryptoService.encrypt;
import static com.example.demo.service.RsaCryptoService.CRYPTO_RSA_ALGORITHM;

public class CryptoService {

    /**
     * key aes value should be :  16 character,24 character or 32 character.
     * @param prop
     */

    private CryptoService(Properties prop){
        this.prop = prop;
    }

    Properties prop;

    public static CryptoService newInstance(){
        Properties prop = new Properties();
        InputStream in = ClassLoader.getSystemResourceAsStream("application.properties");
        try {
            prop.load(in);
            return new CryptoService(prop);
        } catch (IOException e) {
            System.out.println("Can't load properties file config.");
            throw new RuntimeException();
        }
    }

    public String decryptDataWithAESKeyEncrypted(DataNeedToDecrypt dataParam) throws IOException {
        PrivateKey privateKey = getPrivateKeyByKeyValue(prop.getProperty("key.value"));
        byte[] dataEncryptKeyBytes = Base64.decodeBase64(dataParam.getAesKey());
        byte[] byteAesKey = RsaCryptoService.decryptWithRSAPrivatekey(privateKey, dataEncryptKeyBytes);
        byte[] cipherValueBytes = Base64.decodeBase64(dataParam.getDataEncrypted());
        byte[] data = AesCryptoService.decrypt(byteAesKey, cipherValueBytes);
        return new String(data);
    }


    public String encryptAESByRSAPublicKey(AESDataNeedToEncrypt dataParam) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(dataParam.getPublicKey()));
        KeyFactory keyFactory = KeyFactory.getInstance(CRYPTO_RSA_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        byte[] byteEncrypted = RsaCryptoService.encryptWithRSAPublicKey(publicKey, dataParam.getAesKeyValue().getBytes());
        String dataEncrypted = Base64.encodeBase64String(byteEncrypted);

        return dataEncrypted;
    }

    public String encryptDataByAESKey(DataParam dataParam){
        byte[] byteEncrypted = encrypt(dataParam.getAesKey().getBytes(), dataParam.getData().getBytes());
       return  Base64.encodeBase64String(byteEncrypted);
    }





    //Utils to handle encrypt and decrypted
    private PrivateKey getPrivateKeyByKeyValue(String keyValue) throws IOException {
        PrivateKey privateKey;
        try {
            String s = getPlainText(keyValue);
            byte[] privateKeyBytes = Base64.decodeBase64(getKeyPair(s).getPrivateKey());
            KeyFactory keyFactory = KeyFactory.getInstance(CRYPTO_RSA_ALGORITHM);

            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

            privateKey = keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return privateKey;
    }
    private String getPlainText(String base64EncodedCipher) {
        return new String(AesCryptoService.decrypt(PassPhraseKMSKeyProviderImpl.getKeyEncryptionKey(),
                Base64.decodeBase64(base64EncodedCipher)));
    }


    private WalletClientKeyPair getKeyPair(String key) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        WalletClientKeyPair walletClientKeyPair = objectMapper.readValue(key, WalletClientKeyPair.class);
        return walletClientKeyPair;
    }

}


