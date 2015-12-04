package securityfinalproject;

import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;

public class CipherClient
{
	public static void main(String[] args) throws Exception 
	{
		String message = "The quick brown fox jumps over the lazy dog.";
		String host = "localhost";
		int port = 7999;

		// YOU NEED TO DO THESE STEPS:
		// -Generate a DES key.
		// -Store it in a file.
		// -Use the key to encrypt the message above and send it over socket s to the server.	
                
                //Generate key
                KeyGenerator keyGen = KeyGenerator.getInstance("DES");
                SecretKey myKey = keyGen.generateKey();
                
                //Store key in file
                ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("KeyFile.xx"));
                out.writeObject(myKey);
                out.close();
                
                //Encypher text
                Cipher c;
                
                c = Cipher.getInstance("DES/ECB/PKCS5Padding");
                
                c.init(Cipher.ENCRYPT_MODE, myKey);
                
                byte[] text = message.getBytes();
                byte[] encryptedText = c.doFinal(text);

                //Creat socket
                Socket s = new Socket(host, port);
                
                DataOutputStream dOut = new DataOutputStream(s.getOutputStream());
                dOut.writeInt(encryptedText.length);
                dOut.write(encryptedText);
                dOut.close();
                

                
                
                
                
                
                
                
                
                
                

	}
}