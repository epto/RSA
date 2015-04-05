package org.mes3hacklab.RSA;
import java.math.BigInteger;


public class RSAPublicKey {
		public int keyBits=0;
		public BigInteger publicKey = null;
		public BigInteger modulus = null;
		
		public int getBlockSize() { return (keyBits>>3) -1; }
				
		public String toString() {
			return
					"RSAPublicKey:\n\t" +
					"Bits: "+Integer.toString(keyBits)+"\n\t"+
					"Modulus: "+modulus.toString(16)+"\n\t"+
					"PublicKey: "+publicKey.toString(16)+"\n\n";
			}
		}
