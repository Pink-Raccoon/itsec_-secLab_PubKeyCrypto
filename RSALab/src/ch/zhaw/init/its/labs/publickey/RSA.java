package ch.zhaw.init.its.labs.publickey;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OptionalDataException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Random;



public class RSA {
	private BigInteger n;
	private BigInteger e;
	private BigInteger d;
	private KeyPair pair;
	private PublicKey publicKey;
	
	private static final int DEFAULT_MODULUS_LENGTH = 2048;
	private static final int DEFAULT_P_LENGTH = DEFAULT_MODULUS_LENGTH/2 - 9;
	private static final int DEFAULT_Q_LENGTH = DEFAULT_MODULUS_LENGTH/2 + 9;

	private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);
	
	/** Generates a random RSA key pair. 
	 * 
	 * This constructor generates a random RSA key pair of unknown, but substantial,
	 * modulus length. The public exponent is 65537.
	 * @throws NoSuchAlgorithmException 
	 */
	public RSA() throws NoSuchAlgorithmException {

		// Generate random primes
		Random rand = new SecureRandom();
		BigInteger p = BigInteger.probablePrime(DEFAULT_P_LENGTH, rand);
		BigInteger q = BigInteger.probablePrime(DEFAULT_Q_LENGTH , rand);

		//Calculate n and phi
		this.n = p.multiply(q);
		BigInteger phi = p.subtract(BigInteger.ONE)
				.multiply(q.subtract(BigInteger.ONE));

		// Generate public and private exponents
		this.e = PUBLIC_EXPONENT;
		this.d = e.modInverse(phi);


		
		// --------> Your solution here! <--------
	}
	
	/** Reads a public key or a key pair from input stream.
	 * 
	 * @param is the input stream to read the public key or key pair from
	 * 
	 * @throws IOException if either the modulus, public exponent, or private
	 * 					exponent can not be read
	 */
	public RSA(ObjectInputStream is) throws IOException, ClassNotFoundException {
		n = (BigInteger) is.readObject();
		e = (BigInteger) is.readObject();
		
		try {
			d = (BigInteger) is.readObject();
		} catch (OptionalDataException e) {
			if (!e.eof) {
				throw e;
			}
		}
	}
	
	/** Encrypts the plain text with the public key.
	 * 
	 * @param plain the plain text to encrypt
	 * @return the ciphertext
	 * @throws BadMessageException then the plain text is too large or too small
	 */
	public BigInteger encrypt(BigInteger plain) throws BadMessageException {
		if (plain.compareTo(n) > 0) {
			throw new BadMessageException("plaintext too large");
		}
		
		if (plain.compareTo(BigInteger.ZERO) <= 0) {
			throw new BadMessageException("plaintext too small");
		}else {
			BigInteger encrypted =  plain.modPow(PUBLIC_EXPONENT, n);
			return encrypted;
		}
			
		// --------> Your solution here! <--------
		
	}
	
	/** Decrypts the ciphertext with the private key.
	 * 
	 * @param cipher the ciphertext to decrypt
	 * @return
	 * @throws BadMessageException
	 */
	public BigInteger decrypt(BigInteger cipher) throws BadMessageException {
		if (d == null) {
			throw new BadMessageException("don't have private key");
		}

		if (cipher.compareTo(n) > 0) {
			throw new BadMessageException("ciphertext too large");
		}
		
		if (cipher.compareTo(BigInteger.ZERO) <= 0) {
			throw new BadMessageException("ciphertext too small");
		}else {
			
			BigInteger decrypted = cipher.modPow(d, n);
			return decrypted;
		}
		

		
	}
	
	/** Saves the entire key pair.
	 * 
	 * @param os the output stream to which to save the key pair
	 * @throws IOException if saving goes wrong or there is no private key to save
	 */
	public void save(ObjectOutputStream os) throws IOException {
		savePublic(os);
		
		if (d != null) {
			os.writeObject(d);
		} else {
			throw new IOException("don't have private key to save");
		}
	}
	
	/** Saves only the public part of the key pair.
	 * 
	 * @param os the output stream to which to save the public key
	 * @throws IOException if saving goes wrong
	 */
	public void savePublic(ObjectOutputStream os) throws IOException {
		os.writeObject(n);
		os.writeObject(e);		
	}
	
	/** Signs a message with the private key.
	 * 
	 * @param message the message to sign
	 * @return the signature for this message
	 * @throws BadMessageException if something is wrong with this message or there is no private key
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 * @throws NoSuchAlgorithmException 
	 */
	public BigInteger sign(BigInteger message) throws BadMessageException, SignatureException, InvalidKeyException, NoSuchAlgorithmException {
		BigInteger signature = message.modPow(d,n);
		return signature;
		
		

		// --------> Your solution here! <--------

	}

	/** Verifies a signature of a message.
	 * 
	 * @param message the message whose signature to check
	 * @param signature the signature to check
	 * @return true iff the signature was made for this message by this key
	 * @throws BadMessageException if something is wrong with this message
	 */
	public boolean verify(BigInteger message, BigInteger signature) throws BadMessageException {
		if(signature.modPow(e,n) == message){
			return true;
		}return false;

	}
	
	public boolean equals(RSA other) {
		return this.n.equals(other.n)
				&& this.e.equals(other.e)
				&& (this.d == null && other.d == null || this.d.equals(other.d));
	}
}
