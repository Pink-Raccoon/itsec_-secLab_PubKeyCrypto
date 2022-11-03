package ch.zhaw.init.its.labs.publickey;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;


public class PublicKeyLab {
	private static final String messageFilename = "message-with-signature.bin";
	private static final String keypairFilename = "keypair.rsa";
	private static final String outputFilenamePattern = "exercise_%d_%s";
	
	private static final BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));

	public static void main(String[] args) throws FileNotFoundException, IOException, ClassNotFoundException, BadMessageException, NoSuchAlgorithmException {		
		PublicKeyLab lab = new PublicKeyLab();
		
		lab.generateKeypairIfNotExists();
		
		lab.exercise1();
		lab.exercise3();
		lab.exercise9GenerateSignature();
		lab.exercise9VerifySignature();
	}
	
	private void exercise1() {
		final int workFactorsBits[] = { 128, 256, 384, 512 };
		
		banner("Exercise 1");
		
		for (int wfBits : workFactorsBits) {
			int keyLength = findRSAKeyLengthForWorkFactorInBits(wfBits);
			System.out.format("%4d bits work factor: %6d bits RSA exponent\n", wfBits, keyLength);
		}
	}
	
	/**
	 * 
	 * @throws FileNotFoundException 
	 * @throws IOException
	 * @throws ClassNotFoundException 
	 * @throws BadMessageException 
	 */
	public void exercise3() throws FileNotFoundException, IOException, ClassNotFoundException, BadMessageException {
		
		banner("Exercise 3 (message encryption/decryption)");
		
		System.out.println("Reading message to be encrypted...");
		BigInteger message = readEncodedMessageFromCommandline();
		
		RSA rsa;
		try (ObjectInputStream is = new ObjectInputStream(new FileInputStream(keypairFilename))) {
			rsa = new RSA(is);
		}
		
		String outputFilename = String.format(outputFilenamePattern, 3, "out1");
		
		System.out.println("Writing encrypted message to file...");
		try (ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream(outputFilename))) {
			os.writeObject(rsa.encrypt(message));
		}
		
		System.out.println("Decrypting message from file...");
		try (ObjectInputStream is = new ObjectInputStream(new FileInputStream(outputFilename))) {
			System.out.printf("Decrypted message: %s%n", BigIntegerEncoder.decode(rsa.decrypt((BigInteger) is.readObject())));
		}
	}

	private void exercise9GenerateSignature() throws BadMessageException, FileNotFoundException, IOException, ClassNotFoundException {
		banner("Exercise 11 (signature generation)");
		
		System.out.println("Reading message to be signed...");
		final BigInteger message = readEncodedMessageFromCommandline();
				
		RSA rsa;
		try (ObjectInputStream is = new ObjectInputStream(new FileInputStream(keypairFilename))) {
			rsa = new RSA(is);
		}
		
		System.out.println("Writing message and signature to file...");
		try (ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream(messageFilename))) {
			os.writeObject(message);
			os.writeObject(rsa.sign(message));
		}
	}

	private void exercise9VerifySignature() throws BadMessageException {
		boolean ok = false;

		banner("Exercise 11 (signature verification)");
		
		try (ObjectInputStream key = new ObjectInputStream(new FileInputStream(keypairFilename))) {
			final RSA keypair = new RSA(key);
			
			try (ObjectInputStream is = new ObjectInputStream(new FileInputStream(messageFilename))) {
				BigInteger message = (BigInteger) is.readObject();
				BigInteger signature = (BigInteger) is.readObject();
				
				System.out.println("Verifying signature for provided message...");
				if (keypair.verify(message, signature)) {
					System.out.println("Signature verified successfully");
					System.out.printf("Decoded message: %s%n", BigIntegerEncoder.decode(message));
				} else {
					System.out.println("Signature did not verify successfully");			
				}
			}
		} catch (FileNotFoundException e) {
			System.err.println("Can't find keypair file \"" + keypairFilename + "\"");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	private void generateKeypairIfNotExists() throws FileNotFoundException, IOException {
		// Generate keypair if none exists
		File f = new File(keypairFilename);
		if (!f.canRead()) {
			try (ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream(f))) {
				new RSA().save(os);
			}
		}
	}

	private void banner(String string) {
		System.out.println();
		System.out.println(string);
		
		for (int i = 0; i < string.length(); i++) {
			System.out.print('=');
		}
		
		System.out.println();
		System.out.println();
	}

	private int findRSAKeyLengthForWorkFactorInBits(int wfBits) {
		final double ln2 = Math.log(2.0);	
		int b = 1;
		double powWfBits = wfBits / ln2;

		while(logW(b)<=powWfBits) {
			b++;
		}
		
		return b;	
	}
	
	private BigInteger readEncodedMessageFromCommandline() throws IOException {
		System.out.println("Please write a message: ");
		String messageString = consoleReader.readLine();
		return BigIntegerEncoder.encode(messageString);
	}

	private double logW(int b) {

		return 1.92 * Math.pow(b, 1.0/3.0) * Math.pow(Math.log(b), 2.0/3.0);
	}
}


