import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.Scanner;

public class Client {
	static String IP;
	public static int ports;
	private Socket socket;
	private DataInputStream in;
	private DataOutputStream out;
	public static File serverPublicKey;
	public static File clientPrivateKey;

	// constructor to put IP address and port
	public Client(String address, int port, File serverPublicKey, File clientPrivateKey, String text) throws Exception {

		// randomly generate 256 bit numbers as shared-key
		BigInteger AESKey = new BigInteger(256, new Random());
		// read serverPublicKey from file
		byte[] serverPublicKeyF = readContentIntoByteArray(serverPublicKey);
		// read clientPrivateKey from file
		byte[] clientPrivateKeyF = readContentIntoByteArray(clientPrivateKey);
		byte[] encryptAESKey = null;
		byte[] signature = null;
		try {
			// encrypt the keys using the public key
			encryptAESKey = encrypt(AESKey.toByteArray(), serverPublicKeyF);
			// generate signature of the key using private key
			signature = signSHA256RSA(AESKey.toByteArray(), clientPrivateKeyF);

		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}

		try {
			// create socket
			socket = new Socket(address, port);
			System.out.println("Connected");
			// sends output to the socket
			out = new DataOutputStream(socket.getOutputStream());
			// get input from the socket
			in = new DataInputStream(socket.getInputStream());
		} catch (UnknownHostException u) {
			System.out.println(u);
		} catch (IOException i) {
			System.out.println(i);
		}
		// string to read message from input
		String line = "";
		// keep reading until "Over" is input
		while (!line.equals("Over")) {
			try {
				// line = input.readLine();
				// sent out (i) the encrypted AES key
				out.writeUTF(encryptAESKey.toString());
				System.out.println("sending text size : " + encryptAESKey.toString());
				out.flush();
				// sent out (ii) its signature for the plain text AES key.
				out.writeUTF(signature.toString());
				System.out.println("sending text size : " + signature.toString());
				out.flush();
				// get serverSignature from socket
				String serverSignature = in.readUTF();
				System.out.println("get serverSignature : " + serverSignature);
				// verify signature using serverPublicKey ,check match or not
				Boolean bool = verify(serverPublicKeyF, serverSignature.getBytes("UTF-8"));
				if (bool) {
					// output the result (i.e., match or not).
					System.out.println("match");
					// It converts the string received from its user to a byte array.
					byte[] byteText = text.getBytes("UTF-8");
					// It generates a signature of the byte array, using “SHA512withRSA”.
					byte[] signatureText = signSHA256RSA(byteText, clientPrivateKeyF);
					// It encrypts the byte array with the shared AES key and CBC mode, to get
					// cipher-text.
					byte[] encryptbyteText = encrypt(byteText, AESKey.toByteArray());
					// It sends to the server: (i) the size of the string (in the unit of byte)
					out.writeInt(byteText.length);
					System.out.println("sending text size : " + byteText.length);
					out.flush();
					// It sends to the server: (ii) the cipher-text
					out.writeUTF(encryptbyteText.toString());
					System.out.println("sending cipher-text text : " + encryptbyteText.toString());
					out.flush();
					// It sends to the server: (iii) its signature.
					out.writeUTF(signatureText.toString());
					System.out.println("sending signature: " + encryptbyteText.toString());
					out.flush();
				} else {
					System.out.println("not match");
				}
			} catch (IOException i) {
				System.out.println(i);
			}
		}
		// close the connection
		in.close();
		out.close();
		socket.close();
	}
	
	// method read File Content Into Byte Array
	private static byte[] readContentIntoByteArray(File file) {
		FileInputStream fileInputStream = null;
		byte[] bFile = new byte[(int) file.length()];
		try {
			// convert file into array of bytes
			fileInputStream = new FileInputStream(file);
			fileInputStream.read(bFile);
			fileInputStream.close();
			for (int i = 0; i < bFile.length; i++) {
				System.out.print((char) bFile[i]);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return bFile;
	}

	// Method for encrypt using AES/CBC
	public byte[] encrypt(byte[] key, byte[] plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC");
		cipher.init(Cipher.ENCRYPT_MODE, aesKey);
		return cipher.doFinal(plaintext);
	}

	// Method for sign using SHA256RSA
	private static byte[] signSHA256RSA(byte[] input, byte[] bPk) throws Exception {
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bPk);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(kf.generatePrivate(spec));
		privateSignature.update(input);
		byte[] s = privateSignature.sign();
		return s;
	}

	// Method for verify signature with public key
	public static boolean verify(byte[] key, byte[] signature)
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		KeyFactory kf = KeyFactory.getInstance("AES/CBC"); // or "EC" or whatever
		PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(key));
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(publicKey);
		return sig.verify(signature);
	}

	// main
	public static void main(String args[]) throws Exception {
		// user provide text message
		Scanner scan = new Scanner(System.in);
		System.out.println("Enter text: ");
		String text = scan.nextLine();
		scan.close();
		Client client = new Client(IP, ports, serverPublicKey, clientPrivateKey, text);
	}

}
