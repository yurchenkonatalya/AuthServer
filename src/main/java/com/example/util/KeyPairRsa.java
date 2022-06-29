package com.example.util;

import lombok.Data;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Data
public class KeyPairRsa {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public KeyPairRsa() throws Exception {
        privateKey = getPrivateKey("/Users/yurchenko/IdeaProjects/AuthServer/src/main/resources/private.txt");
        publicKey = getPublicKey("/Users/yurchenko/IdeaProjects/AuthServer/src/main/resources/public.txt");
    }

    private PrivateKey getPrivateKey(String filename){
        try {
            File f = new File(filename);
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] keyBytes = new byte[(int) f.length()];
            dis.readFully(keyBytes);
            dis.close();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch(NoSuchAlgorithmException | IOException | InvalidKeySpecException e){
            e.printStackTrace();
        }
        return null;
    }

    private static PublicKey getPublicKey(String filename)
            throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
