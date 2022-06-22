package com.example.util;

import lombok.Data;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

@Data
public class RsaKeyGenerator {

    public RsaKeyGenerator() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        try (FileOutputStream fos = new FileOutputStream("/Users/yurchenko/IdeaProjects/AuthServer/src/main/resources/public.txt")) {
            fos.write(publicKey.getEncoded());
        }
        try (FileOutputStream fos2 = new FileOutputStream("/Users/yurchenko/IdeaProjects/AuthServer/src/main/resources/private.txt")) {
            fos2.write(privateKey.getEncoded());
        }
    }
}
