
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.cert.Certificate;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
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
public class X509Client {
    public static void main(String[] args) throws Exception 
        {
            /*
            --Wait for Bob to put public key in file (happens when server runs)
            Generate public/private key
            Read Bob's public key from file
            Encrypt Message M with Bob's public key
            Encrypt Hash H(m) with her private key
            Send M and H(m) to Bob
            */
            String message = "The quick brown fox jumps over the lazy dog.";
            String host = "localhost";
            int port = 7999;
            Boolean isValid = false;
            
            //Reload the keystore
            char[] password = "password".toCharArray();
            KeyStore keyStore2=KeyStore.getInstance("jks");
            keyStore2.load(new FileInputStream("keyStore.jks"),password);
            
            X509Certificate cert = (X509Certificate)keyStore2.getCertificate("mykey");
            System.out.println(cert);
            
            PublicKey pk = cert.getPublicKey();
            try{
                cert.verify(pk);
                cert.checkValidity(new Date());
                System.out.println("Cert verified");
                isValid = true;
            }
            catch(InvalidKeyException e){
                System.out.println("Cert not verified");
            }
            catch(CertificateExpiredException e){
                System.out.println("Date not valid");
            }
            

            try {
                //Generate keys and write public to file
                final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(1024);
                KeyPair key = keyGen.generateKeyPair();
                
                ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("AliceFile.xx"));
                out.writeObject(key.getPublic());
                out.close();
            
                //Read Bob's file
                ObjectInputStream in = new ObjectInputStream(new FileInputStream("BobFile.xx"));
                PublicKey k = (PublicKey)in.readObject();

                //Encrypt message
                final byte[] cipherText = encrypt(message, k);

                //Hash
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(message.getBytes());
                byte hashText[] = md.digest();

                //Encrypt Hash
                final byte encryptedHash[] = encrypt(hashText, key.getPrivate());
                
                //Send both message and hash
                Socket s = new Socket(host, port);
                
                DataOutputStream dOut = new DataOutputStream(s.getOutputStream());
                dOut.writeInt(cipherText.length);
                dOut.write(cipherText);
                dOut.writeInt(encryptedHash.length);
                dOut.write(encryptedHash);
                dOut.close();
            }
            
            catch (Exception e) {
                e.printStackTrace();
            }
            


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
        
        //Reload the keystore
        KeyStore keyStore2=KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream("keyStore.jks"),password);
         
        Key key=keyStore.getKey("mykey", password);
         
        if(key instanceof PrivateKey){
            System.out.println("Get private key : ");
            System.out.println(key.toString());
            
        }else{
            System.out.println("Key is not private key");
        }
        
        return cert;
    }

    
    public static byte[] encrypt(String text, PublicKey key) {
        byte[] cipherText = null;
        try {
          // get an RSA cipher object and print the provider
          final Cipher cipher = Cipher.getInstance("RSA");
          // encrypt the plain text using the public key
          cipher.init(Cipher.ENCRYPT_MODE, key);
          cipherText = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
          e.printStackTrace();
        }
        return cipherText;
    }
    public static byte[] encrypt(byte[] text, PrivateKey key){
        byte[] cipherText = null;
        try {
          // get an RSA cipher object and print the provider
          final Cipher cipher = Cipher.getInstance("RSA");
          // encrypt the plain text using the public key
          cipher.init(Cipher.ENCRYPT_MODE, key);
          cipherText = cipher.doFinal(text);
        } catch (Exception e) {
          e.printStackTrace();
        }
        return cipherText;
    }

}
