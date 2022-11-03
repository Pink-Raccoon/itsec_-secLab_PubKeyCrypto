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

	public static void main(String[] args) throws FileNotFoundException, IOException, ClassNotFoundException, BadMessageException, NoSuchAlgorithmException {
		PublicKeyLab lab = new PublicKeyLab();
		
		lab.generateKeypairIfNotExists();
		
		lab.exercise1();
		lab.exercise3();
		//lab.exercise9GenerateSignature();
		//lab.exercise9VerifySignature();
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
		
		RSA rsa;
		try (ObjectInputStream is = new ObjectInputStream(new FileInputStream(keypairFilename))) {
			rsa = new RSA(is);
		}
		
		BigInteger message;
		try (BufferedReader reader = new BufferedReader (new InputStreamReader(System.in))) {
			System.out.println("Please write a message to be encrypted: ");
			String messageString = reader.readLine();
			message = rsa.encrypt(BigIntegerEncoder.encode(messageString));
		}

		String outputFilename = String.format(outputFilenamePattern, 3, "out1");
		
		try (ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream(outputFilename))) {
			os.writeObject(message);
		}
		
		try (ObjectInputStream is = new ObjectInputStream(new FileInputStream(outputFilename))) {
			BigInteger decryptedMessageAsBigInt = rsa.decrypt((BigInteger) is.readObject());
			
			System.out.println("Decrypted message: " + BigIntegerEncoder.decode(decryptedMessageAsBigInt));
		}
	}

	private void exercise9GenerateSignature() throws BadMessageException, FileNotFoundException, IOException {
		
		final BigInteger message;
		try (BufferedReader reader = new BufferedReader (new InputStreamReader(System.in))) {
			System.out.println("Please write a message to be encrypted: ");
			String messageString = reader.readLine();
			message = BigIntegerEncoder.encode(messageString);;
		}
		
		banner("Exercise 11 (signature generation)");
		
		// --------> Your solution here! <--------
		
		
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

	private void exercise9VerifySignature(String[] args) throws BadMessageException {
		boolean ok = false;

		banner("Exercise 11 (signature verification)");
		
		try (ObjectInputStream key = new ObjectInputStream(new FileInputStream(keypairFilename))) {
			final RSA keypair = new RSA(key);
			
			// --------> Your solution here! <--------
		} catch (FileNotFoundException e) {
			System.err.println("Can't find keypair file \"" + keypairFilename + "\"");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} 	
		
		if (ok) {
			System.out.println("Signature verified successfully");
		} else {
			System.out.println("Signature did not verify successfully");			
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

	private double logW(int b) {

		return 1.92 * Math.pow(b, 1.0/3.0) * Math.pow(Math.log(b), 2.0/3.0);
	}
}


