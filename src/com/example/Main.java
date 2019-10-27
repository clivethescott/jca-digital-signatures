package com.example;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;

public class Main {

    public static void main(String[] args) {

        /*

          1. Generate a keypair for the sender

              keytool -genkeypair -alias senderKeyPair -keyalg RSA -keysize 2048 \
                -dname "CN=Clive" -validity 365 -storetype PKCS12 \
                -keystore sender_keystore.p12 -storepass secretpass

            This will create a private+public key. Public key wrapped in an X.509 self-signed certificate
            which is wrapped in turn into a single-element certificate chain in the file sender_keystore.p12

          2. Export self-signed certificate in PEM (text) format from our keystore for our receivers to verify our messages

              keytool -exportcert -alias senderKeyPair -storetype PKCS12 \
                  -keystore sender_keystore.p12 -file \
                  sender_certificate.cer -rfc -storepass secretpass

              OR if using a CA, a CSR to get a DER(binary) or PEM(text) format...... -rfc is for PEM text format

             keytool -certreq -alias senderKeyPair -storetype PKCS12 \
              -keystore sender_keystore.p12 -file -rfc \
              -storepass secretpass > sender_certificate.csr

          3. Receiver imports our public key into their own key store

             keytool -importcert -alias receiverKeyPair -storetype PKCS12 \
              -keystore receiver_keystore.p12 -file \
              sender_certificate.cer -rfc -storepass myownreceiverpass

         */
        final String keystoreLocation = "/Users/scott/temp/jca-digital-signatures/sender_keystore.p12";

        try (InputStream keystoreInputStream = new FileInputStream(keystoreLocation)) {

            // Load our keystore, private key and public key/certificate

            String keyStoreType = "PKCS12";
            String keyStorePassword = "secretpass";

            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            char[] password = keyStorePassword.toCharArray();
            keyStore.load(keystoreInputStream, password);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("senderKeyPair",
                    new KeyStore.PasswordProtection(password));
            Certificate certificate = privateKeyEntry.getCertificate();

            final var message = "Super secret message that will no longer be acceptable to send without a signature....okay";


            //--------------------- Sender ----------------------------
            // Generate a digital signature
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            String senderAlgorithm = "SHA256withRSA";

            Signature signature = Signature.getInstance(senderAlgorithm);
            signature.initSign(privateKey);

            byte[] messageBytes = message.getBytes();
            signature.update(messageBytes);
            byte[] senderDigitalSignature = signature.sign();
            System.out.println("senderSignature = " + senderDigitalSignature);

            //--------------------- Receiver ----------------------------
            // Verify digital signature, (Load our own keystore and get sender's public key in read world)
            PublicKey publicKey = certificate.getPublicKey();

            byte[] messageBytesReceiver = message.getBytes();
            Signature receiverSignature = Signature.getInstance(senderAlgorithm);
            receiverSignature.initVerify(publicKey);
            receiverSignature.update(messageBytesReceiver);

            System.out.println("Match = " + receiverSignature.verify(senderDigitalSignature));
        } catch (Exception e) {
            System.err.println("Oops got an error");
            e.printStackTrace();
        }
    }

}
