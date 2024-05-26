package com.example.demo.controller;

import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;


@RestController
public class AESController {
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;

    private final String secretKey="secretKey";

    @GetMapping("/encrypt")
    public String encrypt(@RequestHeader("input") String strToEncrypt, @RequestHeader("salt")String salt) {
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec);

            byte[] cipherText = cipher.doFinal(strToEncrypt.getBytes("UTF-8"));
            byte[] encryptedData = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            // Handle the exception properly
            e.printStackTrace();
            return null;
        }
    }
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }
    @GetMapping("/decrypt")
    public String decrypt(@RequestHeader("input") String strToDecrypt,  @RequestHeader("salt")String salt) {

        try {
            byte[] encryptedData = Base64.getDecoder().decode(strToDecrypt);
            byte[] iv = new byte[16];
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);

            byte[] cipherText = new byte[encryptedData.length - 16];
            System.arraycopy(encryptedData, 16, cipherText, 0, cipherText.length);

            byte[] decryptedText = cipher.doFinal(cipherText);
            return new String(decryptedText, "UTF-8");
        } catch (Exception e) {
            // Handle the exception properly
            e.printStackTrace();
            return null;
        }
    }

    @GetMapping("/encrypt/v2")
    public String encryptV2(@RequestHeader("input") String strToEncrypt, @RequestHeader("salt")String salt) {
        try {
            String saltGenerated = KeyGenerators.string().generateKey();
            BytesEncryptor stronger = Encryptors.stronger(secretKey, saltGenerated);
            byte[] encrypt = stronger.encrypt(strToEncrypt.getBytes());
            return Base64.getEncoder().encodeToString(encrypt);
        } catch (Exception e) {
            // Handle the exception properly
            e.printStackTrace();
            return e.getMessage();
        }
    }

    @GetMapping("/decrypt/v2")
    public String decryptV2(@RequestHeader("input") String strToDecrypt,  @RequestHeader("salt")String salt) {

        try {
            BytesEncryptor stronger = Encryptors.stronger(secretKey, salt);
            byte[] decrypted = stronger.decrypt(strToDecrypt.getBytes());
            return Base64.getEncoder().encodeToString(decrypted);
        } catch (Exception e) {
            // Handle the exception properly
            e.printStackTrace();
            return null;
        }
    }

    @CrossOrigin
    @GetMapping("/getRSApublicKey")
    public Object getRSAPublicKey() throws IOException {
        File publicKey = new File("F:\\APPLICATION DEVELOPMENT\\RSA\\public.pem");
        String content = new String(Files.readAllBytes(publicKey.toPath()));
        return Map.of("publicKey",content);
    }
    @GetMapping("/decryptRSA")
    public String decrypt(@RequestHeader("input") String strToDecrypt) throws Exception {
        File privateKeyFile = new File("F:\\APPLICATION DEVELOPMENT\\RSA\\private1.pem");
        String privKeyStrBase64Encoded = new String(Files.readAllBytes(privateKeyFile.toPath()));
        privKeyStrBase64Encoded = privKeyStrBase64Encoded.replace("-----BEGIN PRIVATE KEY-----", "");
        privKeyStrBase64Encoded = privKeyStrBase64Encoded.replaceAll(System.lineSeparator(), "");
        privKeyStrBase64Encoded = privKeyStrBase64Encoded.replace("-----END PRIVATE KEY-----", "");
        byte[] privateKeyBytes = Base64.getDecoder().decode(privKeyStrBase64Encoded.getBytes());
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey= keyFactory.generatePrivate(privateKeySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)), StandardCharsets.UTF_8);
    }

    @GetMapping("/decryptRSA/v2")
    public String decryptV2(@RequestHeader("input") String strToDecrypt) throws Exception {
        File privateKeyFile = new File("F:\\APPLICATION DEVELOPMENT\\RSA\\private1.pem");
        String privKeyStrBase64Encoded = new String(Files.readAllBytes(privateKeyFile.toPath()));
        PrivateKey privateKey = stringToPrivateKey(privKeyStrBase64Encoded, "keypass".toCharArray());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Cipher cipherRsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRsa.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipherRsa.doFinal(Base64.getDecoder().decode(strToDecrypt)), StandardCharsets.UTF_8);
    }

    static public PrivateKey stringToPrivateKey(String s, char[] password)
            throws IOException, PKCSException {
        PrivateKeyInfo pki;
        try (PEMParser pemParser = new PEMParser(new StringReader(s))) {
            Object o = pemParser.readObject();
            if (o instanceof PKCS8EncryptedPrivateKeyInfo) { // encrypted private key in pkcs8-format
                PKCS8EncryptedPrivateKeyInfo epki = (PKCS8EncryptedPrivateKeyInfo) o;
                JcePKCSPBEInputDecryptorProviderBuilder builder =
                        new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC");
                InputDecryptorProvider idp = builder.build(password);
                pki = epki.decryptPrivateKeyInfo(idp);
            } else if (o instanceof PEMEncryptedKeyPair) { // encrypted private key in pkcs8-format
                PEMEncryptedKeyPair epki = (PEMEncryptedKeyPair) o;
                PEMKeyPair pkp = epki.decryptKeyPair(new BcPEMDecryptorProvider(password));
                pki = pkp.getPrivateKeyInfo();
            } else if (o instanceof PEMKeyPair) { // unencrypted private key
                PEMKeyPair pkp = (PEMKeyPair) o;
                pki = pkp.getPrivateKeyInfo();
            } else {
                throw new PKCSException("Invalid encrypted private key class: " + o.getClass().getName());
            }
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return converter.getPrivateKey(pki);
        }
    }


}
