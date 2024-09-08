package com.agus.gpgkeycheck;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.Iterator;

public class GpgKeyValidator {
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static PGPSecretKeyRingCollection readSecretKeyRingCollection(InputStream inputStream) throws IOException, PGPException {
        try (ArmoredInputStream armorInputStream = new ArmoredInputStream(inputStream)) {
            return new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(armorInputStream), new JcaKeyFingerprintCalculator());
        }
    }

    public static boolean validatePassphrase(byte[] secretKeyBytes, String passphrase) {
        try (ByteArrayInputStream secretKeyInputStream = new ByteArrayInputStream(secretKeyBytes)) {
            PGPSecretKeyRingCollection secretKeyRingCollection = readSecretKeyRingCollection(secretKeyInputStream);

            Iterator<PGPSecretKeyRing> keyRings = secretKeyRingCollection.getKeyRings();
            while (keyRings.hasNext()) {
                PGPSecretKeyRing keyRing = keyRings.next();
                Iterator<PGPSecretKey> secretKeys = keyRing.getSecretKeys();

                while (secretKeys.hasNext()) {
                    PGPSecretKey secretKey = secretKeys.next();
                    if (validateKeyWithPassphrase(secretKey, passphrase)) {
                        return true;  // Valid passphrase
                    }
                }
            }
        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }
        return false;  // Invalid passphrase
    }

    private static boolean validateKeyWithPassphrase(PGPSecretKey secretKey, String passphrase) throws PGPException {
        PGPPrivateKey privateKey;

        try {
            privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC")
                    .build(passphrase.toCharArray()));
        } catch (PGPException e) {
            // Invalid passphrase, the exception will be thrown
            return false;
        }

        return privateKey != null;
    }
}
