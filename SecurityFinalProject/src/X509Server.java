
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author chrismartin
 */
public class X509Server {
    public static void main(String[] args) throws Exception 
	{
            
            /*
            Generate public/private key
            Store public key in file
            --Wait for Alice to do stuff
            Receive encrypted message from Alice
            Receive encrypted hash(message) from Alice
            Read Alice's public key from file
            Decrypt H(m) using Alice's public key
            Decrypt M using Bob's private key
            Compare Hash H(m) with Hash (M)
            */
            int port = 7999;
            ServerSocket server = new ServerSocket(port);
            
            X509Certificate c = generateCertificate();
            
            //Generate keys, store public key in file
            try {
                
                String decryptedMessage = "";
                final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(1024);
                final KeyPair key = keyGen.generateKeyPair();
                
                ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("BobFile.xx"));
                out.writeObject(key.getPublic());
                out.close();
            
                try(Socket s = server.accept()) {

                    //Read Alice's public key from file
                    ObjectInputStream in = new ObjectInputStream(new FileInputStream("AliceFile.xx"));
                    PublicKey k = (PublicKey)in.readObject();

                    //Get Messages from Alice
                    DataInputStream dIn = new DataInputStream(s.getInputStream());
                    
                    //Read in encrypted message
                    int length = dIn.readInt();
                        if(length>0){
                            byte[] encryptedMessage = new byte[length];
                            dIn.readFully(encryptedMessage, 0, encryptedMessage.length);
                            String decryptedText = decrypt(encryptedMessage, key.getPrivate());
                            decryptedMessage = decryptedText;
                            System.out.println("Decrypted Message: " + decryptedMessage);
                        }
                        
                    //Read in encrypted Hash
                    length = dIn.readInt();
                        if(length>0){
                            byte[] encryptedHash = new byte[length];
                            dIn.readFully(encryptedHash, 0, encryptedHash.length);
                            byte[] decryptedHash = decrypt(encryptedHash, k);
                            
                            MessageDigest md = MessageDigest.getInstance("SHA-256");
                            md.update(decryptedMessage.getBytes());
                            byte[] hashText = md.digest();
                            
                            if(Arrays.equals(decryptedHash,hashText)){
                                System.out.println("Signature verified");
                            }
                            else{
                                System.out.println("Signature not verified");
                            }
                        }

                }
            }
            catch (Exception e) {
                e.printStackTrace();
            }
            

                
        }
    public static String decrypt(byte[] text, PrivateKey key) {
    byte[] dectyptedText = null;
    try {
      // get an RSA cipher object
      final Cipher cipher = Cipher.getInstance("RSA");

      // decrypt the text using the private key
      cipher.init(Cipher.DECRYPT_MODE, key);
      dectyptedText = cipher.doFinal(text);

    } catch (Exception ex) {
      ex.printStackTrace();
    }

    return new String(dectyptedText);
  }
    public static byte[] decrypt(byte[] text, PublicKey key) {
    byte[] decryptedText = null;
    try {
      // get an RSA cipher object
      final Cipher cipher = Cipher.getInstance("RSA");

      // decrypt the text using the public key
      cipher.init(Cipher.DECRYPT_MODE, key);
      decryptedText = cipher.doFinal(text);

    } catch (Exception ex) {
      ex.printStackTrace();
    }

    return decryptedText;
  }
    private static String bytes2String(byte[] bytes) {
    StringBuilder string = new StringBuilder();
    for (byte b : bytes) {
        String hexString = Integer.toHexString(0x00FF & b);
        string.append(hexString.length() == 1 ? "0" + hexString : hexString);
    }
    return string.toString();
}
    static X509Certificate generateCertificate() throws Exception{
        Date validBegin = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date validEnd = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        KeyStore keyStore=KeyStore.getInstance("jks");
        char[] password = "password".toCharArray();
        keyStore.load(null,password);
        
        CertAndKeyGen certGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
        certGen.generate(1024);
        
        long validSecs = (long) 365 * 24 * 60 * 60;
        X509Certificate cert = certGen.getSelfCertificate(new X500Name("CN=My App, O=My Org, L=Pittsburgh, C=US"), validSecs);
        
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;
        
        //Store entry
        keyStore.setKeyEntry("mykey", certGen.getPrivateKey(), password, chain);
        keyStore.store(new FileOutputStream("keyStore.jks"),password);

        return cert;
    }

    
}
