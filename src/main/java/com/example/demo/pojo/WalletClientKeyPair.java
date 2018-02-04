package com.example.demo.pojo;


public class WalletClientKeyPair {


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
