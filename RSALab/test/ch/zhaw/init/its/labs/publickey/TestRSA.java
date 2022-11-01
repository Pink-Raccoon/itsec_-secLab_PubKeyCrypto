package ch.zhaw.init.its.labs.publickey;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import org.junit.jupiter.api.Test;

public class TestRSA {

	@Test
	void testGeneration() throws NoSuchAlgorithmException {
		for (int i = 0; i < 100; i++) {
			RSA rsa = new RSA();
		}
	}

	@Test
	void testEncryptDecrypt() throws BadMessageException, NoSuchAlgorithmException {
		RSA rsa = new RSA();
		BigInteger message = BigInteger.ONE;
		
		for (int i = 0; i < 100; i++) {
			BigInteger cipher = rsa.encrypt(message);
			BigInteger decrypted = rsa.decrypt(cipher);
			
			if (!decrypted.equals(message)) {
				fail("Urgs");
			}
			
			message = message.add(BigInteger.ONE);
		}
	}
	
	@Test
	void testSignVerify() throws BadMessageException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		RSA rsa = new RSA();
		BigInteger message = BigInteger.ONE;
		
		for (int i = 0; i < 100; i++) {
			BigInteger signature = rsa.sign(message);
			
			if (!rsa.verify(message,  signature)) {
				fail("Urgs");
			}
			
			message = message.add(BigInteger.ONE);
		}
	}
	
	@Test
	void testSerialize() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
		for (int i = 0; i < 100; i++) {
			RSA rsa = new RSA();
			
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutputStream os = new ObjectOutputStream(bos);
			rsa.save(os);
			
			ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
			ObjectInputStream is = new ObjectInputStream(bis);
			
			RSA rsaNew = new RSA(is);
			
			if (!rsa.equals(rsaNew)) {
				fail("Urgs");
			}
		}
	}
}
