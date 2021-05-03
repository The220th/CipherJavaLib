package CipherLib;

import java.lang.*;
import java.util.*;

public interface ISymCipher
{
	public abstract void genKey();

	public abstract byte[] getKey();

	public abstract void setKey(byte[] key);

	public abstract byte[] encrypt(byte[] rawMsg);

	public abstract byte[] decrypt(byte[] enMsg);
}
