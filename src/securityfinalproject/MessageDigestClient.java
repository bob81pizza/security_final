/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityfinalproject;

import java.security.MessageDigest;
import java.util.Scanner;

/**
 *
 * @author chrismartin
 */
public class MessageDigestClient {
    public static void main(String[] args) throws Exception{
        // TODO code application logic here
        String password = "123456";
        
        Scanner reader = new Scanner(System.in);  // Reading from System.in
        System.out.println("Enter a string to hash: ");
        String entry = reader.next();
    	
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        MessageDigest md2 = MessageDigest.getInstance("MD5");
        md.update(entry.getBytes());
        md2.update(entry.getBytes());
        
        byte byteData[] = md.digest();
        byte byteData2[] = md2.digest();
 
        //convert the byte to hex format
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
         sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }
     
        System.out.println("SHA-256 Hex format: " + sb.toString());
        
        StringBuffer sb2 = new StringBuffer();
        for (int i = 0; i < byteData2.length; i++) {
         sb2.append(Integer.toString((byteData2[i] & 0xff) + 0x100, 16).substring(1));
        }
     
        System.out.println("MD5 Hex format: " + sb2.toString());
        
        
    }
}
