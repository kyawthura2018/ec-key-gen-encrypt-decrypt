package org.acme;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.Credentials;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

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
        String publicKey = convertPublicKeyToUncompressedHex(masterKey.getPublic());
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

    public static String generateWalletAddress(int index, String seed) throws Exception {
        // Decode the Base64 seed
        byte[] importedSeed = Base64.getDecoder().decode(seed);

        // Generate master key pair (BIP-32)
        Bip32ECKeyPair masterKeypair = Bip32ECKeyPair.generateKeyPair(importedSeed);

        // Derivation path: m/44'/60'/0'/0/i
        int[] path = {
                44 | 0x80000000,  // purpose'
                60 | 0x80000000,  // coin_type' (60 = ETH)
                0 | 0x80000000,   // account'
                0,                // change (0 = external)
                index                // address_index
        };

        // Derive the child key
        Bip32ECKeyPair childKey = Bip32ECKeyPair.deriveKeyPair(masterKeypair, path);

        // Generate wallet/address
        Credentials credentials = Credentials.create(childKey);
        return credentials.getAddress();
    }

    private static byte[] hmacSHA512(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512", "BC");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        return mac.doFinal(data);
    }

    public static KeyPair generateKeyPair(BigInteger privateKeyInt) throws Exception {
        // Retrieve EC parameters for secp256k1 from BouncyCastle
        ECParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

        // Convert BouncyCastle ECParameterSpec to java.security.spec.ECParameterSpec
        java.security.spec.ECParameterSpec ecSpec = new java.security.spec.ECParameterSpec(
                new EllipticCurve(
                        new java.security.spec.ECFieldFp(bcSpec.getCurve().getField().getCharacteristic()),
                        bcSpec.getCurve().getA().toBigInteger(),
                        bcSpec.getCurve().getB().toBigInteger()
                ),
                new java.security.spec.ECPoint(
                        bcSpec.getG().getAffineXCoord().toBigInteger(),
                        bcSpec.getG().getAffineYCoord().toBigInteger()
                ),
                bcSpec.getN(),
                bcSpec.getH().intValue()
        );

        // Create the private key spec using the private key integer and EC parameters
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyInt, bcSpec);

        // Initialize KeyFactory and generate private key
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Calculate the public key point based on the private key
        org.bouncycastle.math.ec.ECPoint bcPublicKeyPoint = bcSpec.getG().multiply(privateKeyInt).normalize();

        // Convert BouncyCastle ECPoint to java.security.spec.ECPoint
        java.security.spec.ECPoint w = new java.security.spec.ECPoint(
                bcPublicKeyPoint.getAffineXCoord().toBigInteger(),
                bcPublicKeyPoint.getAffineYCoord().toBigInteger()
        );

        // Create the public key spec
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(w, ecSpec);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

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

    public static String convertPublicKeyToUncompressedHex(PublicKey publicKey) throws Exception {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("The provided key is not an EC public key");
        }

        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECPoint ecPoint = ecPublicKey.getW();

        // Get X and Y coordinates as byte arrays
        byte[] xBytes = ecPoint.getAffineX().toByteArray();
        byte[] yBytes = ecPoint.getAffineY().toByteArray();

        // Ensure both coordinates are 32 bytes long (padding if necessary)
        xBytes = padToLength(xBytes, 32);
        yBytes = padToLength(yBytes, 32);

        // Convert to hex strings
        String xHex = bytesToHex(xBytes);
        String yHex = bytesToHex(yBytes);

        // Combine with '04' prefix
        return "04" + xHex + yHex;
    }

    private static byte[] padToLength(byte[] bytes, int length) {
        if (bytes.length == length) {
            return bytes;
        }
        byte[] paddedBytes = new byte[length];
        int srcPos = Math.max(0, bytes.length - length);
        int destPos = Math.max(0, length - bytes.length);
        int copyLength = Math.min(bytes.length, length);

        System.arraycopy(bytes, srcPos, paddedBytes, destPos, copyLength);
        return paddedBytes;
    }

    public static byte[] signData(String data, PrivateKey privateKey) throws Exception {
        // Initialize the signature object with ECDSA and SHA-256
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(privateKey);

        // Update the signature object with the data
        ecdsaSign.update(data.getBytes("UTF-8"));

        // Sign the data and return the Base64 encoded signature
        byte[] signature = ecdsaSign.sign();
        System.out.println("Signature: " + bytesToHex(signature));
//        return Base64.getEncoder().encodeToString(signature);
        return signature;
    }

    public static boolean verifySignature(PublicKey publicKey, String data, byte[] signature) throws Exception {
        // Initialize the Signature instance with the correct algorithm for ECDSA
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(data.getBytes(StandardCharsets.UTF_8));

        // Verify the signature
        return ecdsaVerify.verify(signature);
    }

    // Convert hex public key to ECPublicKey
    public static PublicKey convertHexToPublicKey(String publicKey) throws Exception {
        // Construct public key
        BigInteger x = new BigInteger(publicKey.substring(2, 66), 16);
        BigInteger y = new BigInteger(publicKey.substring(66), 16);
        ECPoint pubPoint = new ECPoint(x, y);

        // Get EC parameter specification for secp256k1
        // Define EC parameter spec
        ECNamedCurveParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECCurve curve = bcSpec.getCurve();
        EllipticCurve ellipticCurve = new EllipticCurve(
                new ECFieldFp(curve.getField().getCharacteristic()),
                curve.getA().toBigInteger(),
                curve.getB().toBigInteger());
        ECPoint ecPoint = new ECPoint(
                bcSpec.getG().getAffineXCoord().toBigInteger(),
                bcSpec.getG().getAffineYCoord().toBigInteger());
        java.security.spec.ECParameterSpec ecParameters = new ECNamedCurveSpec("secp256k1", ellipticCurve, ecPoint, bcSpec.getN(), bcSpec.getH());

        // Generate public key
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(pubSpec);
    }
}

