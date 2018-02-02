package com.example.demo.pojo;

public class AESDataNeedToEncrypt {
    private String publicKey;
    private String aesKeyValue;

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getAesKeyValue() {
        return aesKeyValue;
    }

    public void setAesKeyValue(String aesKeyValue) {
        this.aesKeyValue = aesKeyValue;
    }
}
