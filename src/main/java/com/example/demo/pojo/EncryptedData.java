package com.example.demo.pojo;

import javax.validation.constraints.NotNull;


public class EncryptedData {


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
