
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


/**
 *
 * @author chrismartin
 */
public class RSASender {
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
            
            
            final KeyPair key;
            try {
                //Generate keys and write public to file
                final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(1024);
                key = keyGen.generateKeyPair();
                
                ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("AliceFile.xx"));
                out.writeObject(key.getPublic());
                out.close();
            
                //Read Bob's file
                ObjectInputStream in = new ObjectInputStream(new FileInputStream("BobFile.xx"));
                PublicKey k = (PublicKey)in.readObject();

                //Encrypt message
                final byte[] cipherText = encrypt(message, k);
                System.out.println("Cipher text " + cipherText);

                //Hash
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(cipherText);
                byte hashText[] = md.digest();
                System.out.println("Hash Text " + hashText);

                //Encrypt Hash
                final byte encryptedHash[] = encrypt(hashText, key.getPrivate());
                System.out.println("Encrypted hash " + encryptedHash);
                
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
