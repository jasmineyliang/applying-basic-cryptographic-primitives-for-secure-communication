package hw3;

import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.io.*;
import java.security.*;

public class AsymmetricKeyProducer {
	static String publicKeyPath;
	static String privateKeyPath;
	static PublicKey publicKey;
	static PrivateKey privateKey;

	// construct instance for AsymmetricKeyProducer object
	public AsymmetricKeyProducer() {
		Scanner scan = new Scanner(System.in);
		System.out.println("Enter public key save path: ");
		publicKeyPath = scan.nextLine();
		System.out.println("Enter private key save path: ");
		privateKeyPath = scan.nextLine();
		scan.close();
		KeyPair keyPair = genKeyPair();
		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();
		publicKeySaveToFile();
		privateKeySaveToFile();
	}

	// generate key pair
	public static KeyPair genKeyPair() {
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			return keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	// Store Public Key to file
	public static void publicKeySaveToFile() {
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		try {
			FileOutputStream fos = new FileOutputStream(publicKeyPath);
			fos.write(x509EncodedKeySpec.getEncoded());
			fos.close();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	// Store Private Key to file
	public static void privateKeySaveToFile() {
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(privateKey.getEncoded());
		try {
			FileOutputStream fos = new FileOutputStream(privateKeyPath);
			fos.write(x509EncodedKeySpec.getEncoded());
			fos.close();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	// generate AsymmetricKeyProducer object
	public static void main(String[] args) {
		AsymmetricKeyProducer asymmetricKeyProducer = new AsymmetricKeyProducer();
	}
}
