package org.mes3hacklab.RSA;

public class RSAKeyPair {
		public RSAPublicKey publicKey = null;
		public RSAPrivateKey privateKey = null;
		
		public int getBlockSize() { return (publicKey.keyBits>>3) -1; }
		
		RSAKeyPair() {
			publicKey = new RSAPublicKey();
			privateKey = new RSAPrivateKey();
			}
		
		RSAKeyPair(RSAPublicKey p,RSAPrivateKey s) {
			publicKey=p;
			privateKey=s;
		}
		
		public String toString() {
			String x = "RSAKeyPair:\n\t"+publicKey;
			x=x.trim();
			x+="\n\t"+ privateKey;
			x=x.trim()+"\n";
			return x;
		}
		
}
