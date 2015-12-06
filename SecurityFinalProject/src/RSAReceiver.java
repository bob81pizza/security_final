
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
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
public class RSAReceiver {
    public static void main(String[] args) throws Exception 
	{
            
            /*
            Generate public/private key
            Store public key in file
            --Wait for Alice to do stuff
            Receive message from Alice
            Read Alice's public key from file
            Decrypt H(m) using Alice's public key
            Decrypt M using Bob's private key
            Compare Hash H(m) with Hash (M)
            */
            int port = 7999;
            ServerSocket server = new ServerSocket(port);
            
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

                    //Get Message from Alice
                    DataInputStream dIn = new DataInputStream(s.getInputStream());
                    int length = dIn.readInt();

                        if(length>0){
                            byte[] message = new byte[length];
                            dIn.readFully(message, 0, message.length);
                            String decryptedText = decrypt(message, key.getPrivate());
                            decryptedMessage = decryptedText;
                            System.out.println(decryptedText);
                            System.out.println("decrypted message get bytes " + decryptedMessage.getBytes());
                        }
                        
                    length = dIn.readInt();
                        if(length>0){
                            byte[] hash = new byte[length];
                            dIn.readFully(hash, 0, hash.length);
                            System.out.println("Encrypted Hash " + hash);
                            byte[] decryptedHash = decrypt(hash, k);
                            
                            MessageDigest md = MessageDigest.getInstance("SHA-256");
                            md.update(decryptedMessage.getBytes());
                            System.out.println("decrypted message bytes " + decryptedMessage.getBytes());
                            byte hashText[] = md.digest();
                            System.out.println("decrypted hash" + decryptedHash);
                            System.out.println("hashed thing" + hashText);
                           
                            
                            
                            if(decryptedHash == hashText){
                                System.out.println("Signature verified");
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
}
