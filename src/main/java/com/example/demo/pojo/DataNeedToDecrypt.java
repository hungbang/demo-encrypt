package com.example.demo.pojo;

public class DataNeedToDecrypt {
    private String aesKey;
    private String dataEncrypted;


    public String getAesKey() {
        return aesKey;
    }

    public void setAesKey(String aesKey) {
        this.aesKey = aesKey;
    }

    public String getDataEncrypted() {
        return dataEncrypted;
    }

    public void setDataEncrypted(String dataEncrypted) {
        this.dataEncrypted = dataEncrypted;
    }
}
