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

	public static void main(String[] args) throws FileNotFoundException, IOException, ClassNotFoundException, BadMessageException, NoSuchAlgorithmException {
		PublicKeyLab lab = new PublicKeyLab();
		
		lab.generateKeypairIfNotExists();
		
		lab.exercise1();
		lab.exercise3EncryptFromCommandLine();
		//lab.exercise9GenerateSignature(args);
		//lab.exercise9VerifySignature(args);
	}

	private void exercise9GenerateSignature(String[] args) throws BadMessageException, FileNotFoundException, IOException {
		final String messageString = args[0]; 
		final BigInteger message = BigIntegerEncoder.encode(messageString);

		banner("Exercise 11 (signature generation)");
		
		generateKeypairIfNotExists();
		
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
	
	private void exercise1() {
		final int workFactorsBits[] = { 128, 256, 384, 512 };
		
		banner("Exercise 1");
		for (int wfBits : workFactorsBits) {
			int keyLength = findRSAKeyLengthForWorkFactorInBits(wfBits);
			System.out.format("%4d bits work factor: %6d bits RSA exponent\n", wfBits, keyLength);
			
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
		

	/**
	 * 
	 * @throws IOException
	 * @throws NoSuchAlgorithmException 
	 * @throws ClassNotFoundException 
	 * @throws BadMessageException 
	 */
	public void exercise3EncryptFromCommandLine() throws NoSuchAlgorithmException, ClassNotFoundException, BadMessageException, IOException{
		
		RSA rsa;
		try (ObjectInputStream is = new ObjectInputStream(new FileInputStream(keypairFilename))) {
			rsa = new RSA(is);
		}
		
		BigInteger encryptedMessage;
		try (BufferedReader reader = new BufferedReader (new InputStreamReader(System.in))) {
			System.out.println("Please write a message to be encrypted: ");
			String message = reader.readLine();
			encryptedMessage = rsa.encrypt(new BigInteger(message.getBytes(StandardCharsets.US_ASCII)));
		}

		String outputFilename = "excercise3output";
		
		try (ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream(outputFilename))) {
			os.writeObject(encryptedMessage);
		}
		
		try (ObjectInputStream is = new ObjectInputStream(new FileInputStream(outputFilename))) {
			BigInteger decryptedMessageAsBigInt = rsa.decrypt((BigInteger) is.readObject());
			System.out.println("Decrypted message: " + new String(decryptedMessageAsBigInt.toByteArray(), StandardCharsets.US_ASCII));
		}
	}
	
	public void exercise3DecryptFromObjStream() throws FileNotFoundException, IOException, ClassNotFoundException, BadMessageException{
		ObjectInputStream is = new ObjectInputStream(new FileInputStream(messageFilename));
		RSA rsa = new RSA(is);
		byte[] messageInByte = is.toString().getBytes();
		BigInteger message  = new BigInteger(messageInByte);
		BigInteger decryption = rsa.decrypt(message);
		System.out.println(decryption.toString());		
	}
	

	private double logW(int b) {

		return 1.92 * Math.pow(b, 1.0/3.0) * Math.pow(Math.log(b), 2.0/3.0);
	}
}


