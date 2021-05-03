package CipherLib;

import java.lang.*;
import java.util.*;

public interface IAsymCipher
{
	public abstract void genKeys();

	public abstract byte[] getPubKey();

	public abstract byte[] getPrivKey();

	public abstract void setKeys(byte[] pub, byte[] priv);

	public abstract byte[] encrypt(byte[] rawMsg);

	public abstract byte[] decrypt(byte[] enMsg);

	public static byte[] sign(byte[] msg, byte[] privKey) {return null;}

	public static byte[] unsign(byte[] signedMsg, byte[] pubKey) {return null;}
}
