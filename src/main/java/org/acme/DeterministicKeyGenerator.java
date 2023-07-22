package org.acme;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.RandomGenerator;

import java.security.SecureRandom;
import java.util.Arrays;

public  class DeterministicKeyGenerator extends SecureRandom implements RandomGenerator {
    final private byte[] seed;
    final private SHA256Digest digest;
    final private byte[] currentSeed;
    private int generatedBytes;

    public DeterministicKeyGenerator(byte[] seed) {
        this.seed = seed;
        this.digest = new SHA256Digest();
        this.currentSeed = Arrays.copyOf(seed, seed.length);
        this.generatedBytes = 0;
    }

    @Override
    public void addSeedMaterial(byte[] seed) {
        // Not used in deterministic key generation
    }

    @Override
    public void addSeedMaterial(long seed) {
        // Not used in deterministic key generation
    }

    @Override
    public void nextBytes(byte[] bytes) {
        if (generatedBytes + bytes.length > seed.length) {
            throw new IllegalStateException("Insufficient seed material.");
        }

        digest.update(currentSeed, 0, currentSeed.length);
        digest.doFinal(currentSeed, 0);

        System.arraycopy(currentSeed, generatedBytes, bytes, 0, bytes.length);
        generatedBytes += bytes.length;
    }

    @Override
    public void nextBytes(byte[] bytes, int start, int len) {
        byte[] tmp = new byte[len];
        nextBytes(tmp);
        System.arraycopy(tmp, 0, bytes, start, len);
    }
}
