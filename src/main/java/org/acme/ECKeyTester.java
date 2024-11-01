package org.acme;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import javax.crypto.*;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static org.acme.BIP32KeyGenerator.*;

@Command(name = "greeting", mixinStandardHelpOptions = true)
public class ECKeyTester implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(ECKeyTester.class);
    private static final String ALGORITHM = "ECDSA";
    private static final String CURVE_NAME = "secp256k1";
    private static final String PROVIDER = "BC";
    private static final String ENCRYPTION_SCHEME = "ECIES";
    private static final byte[] importedSeed = Base64.getDecoder()
                .decode("H5ype5qKmR/rmM013QdVQpvUvcdCp4Pl1+8pkm8N8JU4YlfKt+LNJYpnax34nm+yHqkuqBWJUe1ks857KR3qbw==");
    @Parameters(paramLabel = "Kyawthura", defaultValue = "picocli", description = "Your name.")
    String name;

    @Override
    public void run() {
        System.out.printf("Hello %s, go go commando!\n", name);
        try {
//            KeyPair ecKeyPair =
//                    loadKeyPairFromSeed(importedSeed);
//            String text = "Hello World! Welcome to SECP Cryptography.";
//            LOGGER.info("Original TEXT = " + text);
//            String cipher = encrypt(text, ecKeyPair.getPublic());
//            LOGGER.info("Encrypted Data : "+cipher);
//             String original = decrypt(cipher, ecKeyPair.getPrivate());
//             LOGGER.info("Decrypted Data : " + original);
            bip21Tester();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void bip21Tester() throws Exception {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);

        // Convert the seed to a Base64 string
        String base64Seed = Base64.getEncoder().encodeToString(seed);
        System.out.println("Seed in Base64: " + base64Seed);

        // Generate Master Key and Chain Code
        KeyPair masterKeyPair = generateMasterKey(seed);
        byte[] chainCode = generateChainCode(seed);
        final var aesKey = generateSharedSecret(masterKeyPair.getPrivate(), masterKeyPair.getPublic());

        String plaintext = "Hello, this is encrypted!";
        String cipher = encryptWithBip32(plaintext, aesKey);
        System.out.println("Encrypted: " + cipher);

        // Decrypt data using the AES key
        String decrypted = decryptWithBip32(cipher, aesKey);
        System.out.println("Decrypted: " + decrypted);

        // Print the master key and chain code
        System.out.println("Master Private Key: " + ((ECPrivateKey) masterKeyPair.getPrivate()).getS().toString(16));
        System.out.println("Master Public Key: " + convertPublicKeyToUncompressedHex(masterKeyPair.getPublic()));
        System.out.println("Chain Code: " + bytesToHex(chainCode));

        // Derive a child key
        KeyPair childKey = deriveChildKey(masterKeyPair, chainCode, 0);
        System.out.println("Child Private Key: " + ((ECPrivateKey) childKey.getPrivate()).getS().toString(16));
    }

    public static void loadKeyPair(){
        try{
            // Set up Bouncy Castle provider
            Security.addProvider(new BouncyCastleProvider());

            // Derive the private and public keys from the seed
            ECKeyGenerationParameters keyGenParams = generateKeyGenerationParameters(importedSeed);
            AsymmetricCipherKeyPair keyPair = generateKeyPair(keyGenParams);

            // Extract the private and public key values
            ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters) keyPair.getPublic();

            // Print the private and public key values
            System.out.println("Private Key: " + privateKeyParams.getD());
            System.out.println("Public Key: " + publicKeyParams.getQ());
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    public static ECKeyGenerationParameters generateKeyGenerationParameters(byte[] seed) {

        // Generate key generation parameters using the derived seed
        X9ECParameters ecParams = org.bouncycastle.asn1.sec.SECNamedCurves.getByName(CURVE_NAME);
        ECDomainParameters ecDomainParams = new ECDomainParameters(ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());
        return new ECKeyGenerationParameters(ecDomainParams, new DeterministicKeyGenerator(seed));
    }

    public static AsymmetricCipherKeyPair generateKeyPair(ECKeyGenerationParameters keyGenParams) {
        // Generate the key pair using the derived seed
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(keyGenParams);
        return keyPairGenerator.generateKeyPair();
    }


    public static KeyPair generateNewKeyPair() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        keyPairGenerator.initialize(new ECGenParameterSpec(CURVE_NAME), new SecureRandom(importedSeed));
        return keyPairGenerator.generateKeyPair();
    }

    public static String encrypt(String data, PublicKey publicKey)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {

        Cipher iesCipher = Cipher.getInstance(ENCRYPTION_SCHEME, PROVIDER);
        iesCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] ciphertext = iesCipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException,
            BadBlockException {
        byte[] cipher = Base64.getDecoder().decode(cipherText);
        Cipher iesDecipher = Cipher.getInstance(ENCRYPTION_SCHEME, PROVIDER);

        iesDecipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] originalText = iesDecipher.doFinal(cipher);
        return new String(originalText);
    }

    public static KeyPair loadKeyPairFromSeed(byte[] seed) throws CryptoException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // Set up Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        // Create a secure random instance from the seed
        SecureRandom secureRandom = new DeterministicKeyGenerator(seed);

        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        ecKeyGen.initialize(new ECGenParameterSpec(CURVE_NAME), secureRandom);
        KeyPair ecKeyPair = ecKeyGen.generateKeyPair();

        // Get the private key value
        LOGGER.info("[regenerateKeyPairFromSeed] Private Key: " + Hex.toHexString(ecKeyPair.getPrivate().getEncoded()));

        // Get the public key value
        LOGGER.info("[regenerateKeyPairFromSeed] Public Key: " + Hex.toHexString(ecKeyPair.getPublic().getEncoded()));

        return ecKeyPair;
    }
}
