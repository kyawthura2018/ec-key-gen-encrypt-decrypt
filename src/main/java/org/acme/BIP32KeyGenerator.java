package org.acme;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

public class BIP32KeyGenerator {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static Map<String, String> generateNewKey() throws Exception {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        // Convert the seed to a Base64 string
        String base64Seed = Base64.getEncoder().encodeToString(seed);

        KeyPair masterKey = generateMasterKey(seed);
        String privateKey = ((ECPrivateKey) masterKey.getPrivate()).getS().toString(16);
        String publicKey = bytesToHex(masterKey.getPublic().getEncoded());
        return Map.of(
                "seed", base64Seed,
                "privateKey", privateKey,
                "publicKey", publicKey
        );
    }

    static KeyPair generateMasterKey(byte[] seed) throws Exception {
        byte[] hash = hmacSHA512("Bitcoin seed".getBytes(), seed);
        byte[] il = Arrays.copyOfRange(hash, 0, 32);
        BigInteger masterPrivateKeyInt = new BigInteger(1, il).mod(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16));
        return generateKeyPair(masterPrivateKeyInt);
    }

    static byte[] generateChainCode(byte[] seed) throws Exception {
        byte[] hash = hmacSHA512("Bitcoin seed".getBytes(), seed);
        return Arrays.copyOfRange(hash, 32, 64);
    }

    static KeyPair deriveChildKey(KeyPair parentKey, byte[] parentChainCode, int index) throws Exception {
        byte[] parentPubKey = parentKey.getPublic().getEncoded();
        byte[] data = new byte[parentPubKey.length + 4];
        System.arraycopy(parentPubKey, 0, data, 0, parentPubKey.length);
        data[data.length - 4] = (byte) ((index >> 24) & 0xFF);
        data[data.length - 3] = (byte) ((index >> 16) & 0xFF);
        data[data.length - 2] = (byte) ((index >> 8) & 0xFF);
        data[data.length - 1] = (byte) (index & 0xFF);

        byte[] hash = hmacSHA512(parentChainCode, data);
        byte[] il = Arrays.copyOfRange(hash, 0, 32);
        byte[] ir = Arrays.copyOfRange(hash, 32, 64);

        BigInteger leftInt = new BigInteger(1, il);
        BigInteger childPrivateKeyInt = ((ECPrivateKey) parentKey.getPrivate()).getS().add(leftInt).mod(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16));
        return generateKeyPair(childPrivateKeyInt);
    }

    private static byte[] hmacSHA512(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512", "BC");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        return mac.doFinal(data);
    }

    private static KeyPair generateKeyPair(BigInteger privateKeyInt) throws Exception {
        // Retrieve EC parameters for secp256k1
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

        // Create private key spec with the private key integer and EC parameters
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyInt, ecSpec);

        // Initialize KeyFactory and generate private key
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Generate the corresponding public key
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256k1");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(ecGenSpec);
        PublicKey publicKey = keyGen.generateKeyPair().getPublic();

        return new KeyPair(publicKey, privateKey);
    }

    static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Function to generate a shared secret using ECDH
    public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        return new SecretKeySpec(sharedSecret, 0, 16, "AES");
    }

    // Function to encrypt data
    public static String encryptWithBip32(String plaintext, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16]; // 16 bytes for AES block size
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        byte[] encryptedWithIv = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(ciphertext, 0, encryptedWithIv, iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }

    // Function to decrypt data
    public static String decryptWithBip32(String encryptedTextWithIv, SecretKey aesKey) throws Exception {
        byte[] encryptedWithIvBytes = Base64.getDecoder().decode(encryptedTextWithIv);

        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[encryptedWithIvBytes.length - 16];
        System.arraycopy(encryptedWithIvBytes, 0, iv, 0, 16);
        System.arraycopy(encryptedWithIvBytes, 16, ciphertext, 0, ciphertext.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted);
    }
}

