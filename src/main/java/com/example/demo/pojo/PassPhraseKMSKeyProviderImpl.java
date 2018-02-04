package com.example.demo.pojo;

import org.apache.tomcat.util.codec.binary.Base64;

/**
 * Created by KAI on 2/4/18.
 */
public class PassPhraseKMSKeyProviderImpl {
    private static final String KMS_ENCRYPTION_KEY = "qKLTvlBzNZeyaTGvnjx9gg==";


    public static byte[] getKeyEncryptionKey() {
        return Base64.decodeBase64(KMS_ENCRYPTION_KEY);
    }

}
