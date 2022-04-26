import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.spec.NamedParameterSpec;

import javax.crypto.KeyAgreement;

public class ECDH {
	/**
    * Convert bytes to Hex
    * @param bytes
    * @return
    */
	public static String bytesToHex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		for (byte temp : bytes) {
			result.append(String.format("%02x", temp));
		}
		return result.toString();
	}
	
	public static byte [] savePublicKey (PublicKey pub) throws Exception {		
		return pub.getEncoded();
	}

	public static byte [] savePrivateKey (PrivateKey priv) throws Exception	{
		return priv.getEncoded();		
	}

	public static void doECDH (String name, PrivateKey priv, PublicKey pub) throws Exception	{
		KeyAgreement ka = KeyAgreement.getInstance("XDH");		
		ka.init(priv);
		ka.doPhase(pub, true);
		byte [] secret = ka.generateSecret();
		System.out.println(name + bytesToHex(secret));
	}

	public static void main (String [] args) throws Exception {		
		// Diffie-Hellman over the curve X448
		KeyPairGenerator kpgen = KeyPairGenerator.getInstance("XDH"); 
		NamedParameterSpec params = new NamedParameterSpec("X448");
		kpgen.initialize(params);

		KeyPair pairA = kpgen.generateKeyPair();	// Generate Alice's key pair
		KeyPair pairB = kpgen.generateKeyPair();	// Generate Bob's key pair

		PrivateKey privA = pairA.getPrivate();
		PublicKey pubA = pairA.getPublic();
		PrivateKey privB = pairB.getPrivate();
		PublicKey pubB = pairB.getPublic();
		
		System.out.println("Alice: " + privA);
		System.out.println("Alice: " + pubA);
		System.out.println("Bob:   " + privB);
		System.out.println("Bob:   " + pubB);
		
		byte [] dataPrvA = savePrivateKey(privA);
		byte [] dataPubA = savePublicKey(pubA);
		byte [] dataPrvB = savePrivateKey(privB);
		byte [] dataPubB = savePublicKey(pubB);
		
		System.out.println("Alice Prv: " + bytesToHex(dataPrvA));
		System.out.println("Alice Pub: " + bytesToHex(dataPubA));
		System.out.println("Bob Prv:   " + bytesToHex(dataPrvB));
		System.out.println("Bob Pub:   " + bytesToHex(dataPubB));

		// The two secret key must be the same
		doECDH("Alice's secret: ", privA, pubB);
		doECDH("Bob's secret:   ", privB, pubA);
	}
}