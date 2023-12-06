import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Server {
	// initialize socket and input stream
	private Socket socket;
	private ServerSocket server;
	private DataInputStream in;
	private DataOutputStream out;
	public static int ports;
	public static String clientPath;
	public static String serverPath;
	static IvParameterSpec iv;
	static byte[] AESKey;

	// constructor with port
	public Server(int port, String clientPublicKeyPath, String serverPrivateKeyPath) {
		// starts server and waits for a connection
		try {
			server = new ServerSocket(port);
			System.out.println("Server started");
			System.out.println("Waiting for a client ...");
			socket = server.accept();
			System.out.println("Client accepted");
			// String[] AESKeyNsignature = new String[2];

			String line = "";
			// reads message from client until "Over" is sent
			while (!line.equals("over")) {
				try {
					// takes input from the client socket
					in = new DataInputStream(socket.getInputStream());
					// output to the client socket
					out = new DataOutputStream(socket.getOutputStream());
					// read AESKey from client
					String AESKey = in.readUTF();
					System.out.println("GET AESKey from client: " + AESKey);
					// read AES Signature from client
					String AESSignature = in.readUTF();
					System.out.println("GET AESSignature from client: " + AESSignature);
					// read serverPrivateKey from path
					byte[] serverPrivateKey = Files.readAllBytes(Paths.get(serverPrivateKeyPath));

					// read clientPublicKey from path
					byte[] clientPublicKey = Files.readAllBytes(Paths.get(clientPublicKeyPath));

					// decrypt AESKey receive from client using private key
					String decryptAESKey = decrypt(AESKey, serverPrivateKey);

					// verify signature
					boolean bool = verify(clientPublicKey, AESSignature.getBytes("UTF-8"));
					if (bool) {
						// output if match or not
						System.out.println("match");
						// generate its own digital signature for the key; and send its digital
						// signature to the client.
						out.write(signSHA256RSA(decryptAESKey.getBytes("UTF-8"), serverPrivateKey));
						System.out.println("sending digital signature");
						out.flush();
					} else {
						// print not match
						System.out.println("not match");
					}

					// get size of a plain text string (in the unit of byte);
					int size = in.readInt();
					System.out.println("GET size of a plaintext from client: " + size);
					// get an AES-encrypted version of the string
					String AESString = in.readUTF();
					System.out.println("GET AESString from client: " + AESString);
					// get an digital signature for the plain text string
					String signatureText = in.readUTF();
					System.out.println("GET signatureText from client: " + signatureText);
					// decrypt cipher text
					String plainText = decrypt(AESString, decryptAESKey.getBytes("UTF-8"));
					System.out.println("GET decrypt plainText: " + plainText);

					// verify signature
					boolean b = verify(clientPublicKey, signatureText.getBytes("UTF-8"));
					if (b) {
						System.out.println("match");
						// generates its digital signature for the plain text and send to client
						out.write(signSHA256RSA(plainText.getBytes("UTF-8"), serverPrivateKey));
						System.out.println("sending digital signature:");
						out.flush();
					} else {
						System.out.println("not match");
					}

				} catch (IOException i) {
					System.out.println(i);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			System.out.println("Closing connection");

			// close connection
			in.close();
			out.close();
			socket.close();
		} catch (IOException i) {
			System.out.println(i);
		}

	}

	// Method for sign using SHA256RSA
	private static byte[] signSHA256RSA(byte[] input, byte[] bPk) throws Exception {
		// byte[] b1 = bPk;
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bPk);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(kf.generatePrivate(spec));
		privateSignature.update(input);
		byte[] s = privateSignature.sign();
		// return Base64.getEncoder().encodeToString(s);
		return s;
	}

	// Method for decrypt using AES/CBC
	public static String decrypt(String cipherText, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC");
		cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
		byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
		return new String(plainText);
	}

	// method for verify signature with public key
	public static boolean verify(byte[] key, byte[] signature)
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		KeyFactory kf = KeyFactory.getInstance("AES/CBC"); // or "EC" or whatever
		PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(key));
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(publicKey);
		return sig.verify(signature);
	}

	public static void main(String args[]) {
		Server server = new Server(ports, clientPath, serverPath);
	}

}
