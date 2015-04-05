package org.mes3hacklab.RSA;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class RSA {

   private static SecureRandom random =null;
   public static final BigInteger DEFAULT_PUBLIC_E= new BigInteger("65537");
   public static final BigInteger RANDOM_PUBLIC_E=null;
      
   public static RSAKeyPair keyGen(int bits) { return keyGen(bits, DEFAULT_PUBLIC_E ); }
   
   public static RSAKeyPair keyGen(int bits,BigInteger pubExp) {
	   int bits2=bits >> 1;
	   	
	   if (random==null) try {
		   	random =  SecureRandom.getInstance("SHA1PRNG");
	   	} catch(Exception I) {
	   		random =  new SecureRandom();
	   	}
	  
	   if (pubExp==null) pubExp=BigInteger.probablePrime(bits2>>2, random);
	    
	   BigInteger uno = new BigInteger(new byte[] { 1 });
	   BigInteger p =null;
	   BigInteger q=null;
	   BigInteger phi =null;
	   BigInteger test = null;
	   BigInteger modulus = null;
	   BigInteger publicKey = null;
	   
	   while(true) {
		   p=null;
		   q=null;
		   
		   while(true) {
			   if (p==null) p = BigInteger.probablePrime(bits2, random);
			   
			   if (p.bitLength()<bits2) { 
				   	p=null; 
				   	continue; 
				   	}
			   
			   if (q==null) q = BigInteger.probablePrime(bits2, random);
			   
			   if (q.bitLength()<bits2) { 
				   q=null; 
				   continue; 
				   }
			   
			   phi = (p.subtract(uno)).multiply(q.subtract(uno));
		   	   test = phi.remainder(pubExp);
		   	   if ( test.intValue() !=0 ) break;
	
		   }
		   
		   modulus = p.multiply(q);
		   publicKey = new BigInteger(pubExp.toByteArray());
		   if (modulus.bitLength()<bits) continue;

		   test = phi.gcd(publicKey);
		   if (test.longValue()==1) break;
		  
   		}
	   
	   BigInteger privateKey = publicKey.modInverse(phi);
	   
	   RSAKeyPair KP = new RSAKeyPair();
	   KP.publicKey.publicKey = publicKey;
	   KP.publicKey.modulus = modulus;
	   KP.privateKey.privateKey = privateKey;
	   KP.privateKey.modulus = modulus;
	   KP.publicKey.keyBits=bits;
	   KP.privateKey.keyBits=bits;
	   return KP;
   }
   
    public static byte[] encrypt(byte[] data,RSAPublicKey key) throws BadDataException {
    	if (data.length>key.getBlockSize()) throw new BadDataException("Datablock too big "+data.length+" / "+key.getBlockSize());
    	if ((data[0]&0x80)!=0) throw new BadDataException("Negative message: Message must start with 0.");		
    	BigInteger dat = new BigInteger(data);
    	dat = RSA.encrypt(dat, key);
    	return dat.toByteArray();
   }
   
   public static byte[] decrypt(byte[] data,RSAPrivateKey key) {
	   BigInteger dat = new BigInteger(data);
	   dat = RSA.decrypt(dat, key);
	   return dat.toByteArray();
   }

   public static BigInteger encrypt(BigInteger data,RSAPublicKey key) throws BadDataException {
	   
	   if (data.signum()==-1) {
		data=data.negate();
	   	}
	   
	   return data.modPow(key.publicKey, key.modulus);
   }

   public static BigInteger decrypt(BigInteger data, RSAPrivateKey key) {
       if (data.signum()==-1) {
		data=data.negate();
	   	}
       return data.modPow(key.privateKey, key.modulus);
   }
   
   public static byte[] sign(byte[] data, RSAPrivateKey key)  {
	   MessageDigest sha256 = null;
	   try { sha256 = MessageDigest.getInstance("SHA-256"); } catch (NoSuchAlgorithmException i) {}
	   sha256.update(data);
	   byte[] sign = sha256.digest();
	   BigInteger i = new BigInteger(sign);
	   i = RSA.decrypt(i, key);
	   return i.toByteArray();
   }

   public static boolean verify(byte[] data,byte[] sign,RSAPublicKey key) throws BadDataException {
	    MessageDigest sha256 = null;
	   try { sha256 = MessageDigest.getInstance("SHA-256"); } catch (NoSuchAlgorithmException i) {}
	   sha256.update(data);
	   byte[] signv = sha256.digest();
	   BigInteger i = new BigInteger(sign);
	   BigInteger v = new BigInteger(signv);
	   if (v.signum()==-1) v=v.negate();
	   	
	   i = RSA.encrypt(i, key);

	   v=v.subtract(i);
	   return v.longValue()==0;
   }
   
public static void main(String[] args) {
	   try {
	      
		   RSAKeyPair key = RSA.keyGen(1024,RSA.RANDOM_PUBLIC_E);
	            
	      byte[] msg ="Messaggio in chiaro".getBytes();
	      byte[] sig = RSA.sign(msg, key.privateKey);
	      
	      System.out.println(
	    		  "Verifica firma:\t "+
	    		  (RSA.verify(msg, sig, key.publicKey) ? "Ok":"Errore!")
	    		  ) ;
	      
	      byte[] enc = RSA.encrypt(msg, key.publicKey);
	      byte[] out = RSA.decrypt(enc, key.privateKey);
	         
	      System.out.println(key);
	      
	      System.out.println("Messaggio:\t`" + new String(msg)+ "`");
	      System.out.println("Cifrato:\t\t`" + new BigInteger(enc).toString(16)+"`");
	      System.out.println("Decifrato:\t`" + new String(out)+"`");
	      
	   	} catch(BadDataException e) { e.printStackTrace(); }
   }
}