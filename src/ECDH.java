import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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
	
	public static byte[] savePublicKey (PublicKey pub) {		
		return pub.getEncoded();
	}

	public static PublicKey loadPublicKey (byte[] data) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("XDH");
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(data);
			return keyFactory.generatePublic(x509KeySpec);	
		} catch (Exception e) {
			System.out.println("loadPublicKey: Error has occured: " + e);
			return null;
		}
		
	}

	public static byte [] savePrivateKey (PrivateKey priv){
		return priv.getEncoded();		
	}

	public static PrivateKey loadPrivateKey (byte[] data){		
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("XDH");
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(data);
			return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		} catch (Exception e) {
			System.out.println("loadPrivateKey: Error has occured: " + e);
			return null;
		}
		
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
		byte[] dataPrvA = savePrivateKey(privA);
		byte[] dataPubA = savePublicKey(pubA);
		byte[] dataPrvB = savePrivateKey(privB);
		byte[] dataPubB = savePublicKey(pubB);
		
		System.out.println("Alice: " + privA);
		System.out.println("Alice: " + pubA);
		System.out.println("Bob:   " + privB);
		System.out.println("Bob:   " + pubB);
		
		System.out.println("Alice Prv: " + bytesToHex(dataPrvA));
		System.out.println("Alice Pub: " + bytesToHex(dataPubA));
		System.out.println("Bob Prv:   " + bytesToHex(dataPrvB));
		System.out.println("Bob Pub:   " + bytesToHex(dataPubB));

		// The two secret key must be the same
		doECDH("Alice's secret: ", privA, pubB);
		doECDH("Bob's secret:   ", privB, pubA);
	}
}