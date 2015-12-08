import java.io.*;
import java.net.*;
import java.security.*;

public class ProtectedServer
{
	public boolean authenticate(InputStream inStream) throws IOException, NoSuchAlgorithmException 
	{
		DataInputStream in = new DataInputStream(inStream);

		// IMPLEMENT THIS FUNCTION.
                String user = in.readUTF();
                long t1 = in.readLong();
                double q1 = in.readDouble();
                long t2 = in.readLong();
                double q2 = in.readDouble();
                
                int length = in.readInt();
                byte[] digest = new byte[length];
                in.readFully(digest, 0, digest.length);
                
                byte[] digest1 = Protection.makeDigest(user, lookupPassword(user), t1, q1);
                byte[] digest2 = Protection.makeDigest(digest1, t2, q2);
                
                if(MessageDigest.isEqual(digest, digest2)){return true;}
                else{return false;}
                
                
                
	}

	protected String lookupPassword(String user) { return "abc123"; }

	public static void main(String[] args) throws Exception 
	{
		int port = 7999;
		ServerSocket s = new ServerSocket(port);
		Socket client = s.accept();

		ProtectedServer server = new ProtectedServer();

		if (server.authenticate(client.getInputStream()))
		  System.out.println("Client logged in.");
		else
		  System.out.println("Client failed to log in.");

		s.close();
	}
}