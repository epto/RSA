package org.mes3hacklab.RSA;
import java.math.BigInteger;


public class RSAPrivateKey {
	public int keyBits=0;
	public BigInteger privateKey = null;
	public BigInteger modulus = null;
	
	public int getBlockSize() { return (keyBits>>3) -1; }
	
	public String toString() {
			return
					"RSAPrivateKey:\n\t" +
					"Bits: "+Integer.toString(keyBits)+"\n\t"+
					"Modulus: "+modulus.toString(16)+"\n\t"+
					"PrivateKey: "+privateKey.toString(16)+"\n\n";
			}
}
