package CipherLib;

import java.lang.*;
import java.util.*;
import java.io.*;

import CipherLib.ISymCipher;
import CipherLib.Tools;
import CipherLib.ByteWorker;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.spec.SecretKeySpec;


public class AES256 implements ISymCipher
{
	private SecretKey secretKey;
	
	private static final int ifENCRYPT = Cipher.ENCRYPT_MODE;
	private static final int ifDECRYPT = Cipher.DECRYPT_MODE;
	
	public static void main(String[] args)
	{
		AES256 aes;
		byte[] buff;
		String srcMsg;
		String getMsg;
		String s;
		Random r = new Random();

		aes = new AES256();
		for(int gi = 0; gi < 10; ++gi)
		{
			aes = new AES256();
			s = Tools.genRndString(r.nextInt(3048));
			aes.setKey(s);
			buff = aes.getKey();
			for(int j = 0; j < 100; ++j)
			{
				srcMsg = Tools.genRndString(r.nextInt(3048)+1);
				aes = new AES256();
				aes.setKey(s);
				getMsg = new String(aes.decrypt(aes.decrypt(aes.encrypt(aes.encrypt(aes.decrypt( aes.encrypt(srcMsg.getBytes()) ))))));	
				if(Arrays.equals(buff, aes.getKey()) == false)
					throw new IllegalStateException("error");
				if(srcMsg.equals(getMsg) == false)
					throw new IllegalStateException("error");
			}

			String[] srss = new String[100];
			byte[][] reses = new byte[100][];
			byte[][] keys = new byte[100][];
			for(int j = 0; j < 100; ++j)
			{
				aes = new AES256();
				aes.genKey();
				srss[j] = Tools.genRndString(r.nextInt(3048)+1);
				keys[j] = aes.getKey();
				reses[j] = aes.encrypt(srss[j].getBytes());
			}
			for(int j = 0; j < 100; ++j)
			{
				aes = new AES256();
				aes.setKey(keys[j]);
				getMsg = new String(aes.decrypt(reses[j]));
				if(srss[j].equals(getMsg) == false)
					throw new IllegalStateException("error");
			}

		}
		System.out.println("All is OK");
	}
	
	public void setKey(byte[] key)
	{
		try 
		{
			this.secretKey = new SecretKeySpec(key, 0, key.length, "AES");
		}
		catch (Exception e)
		{
			e.printStackTrace();
        }
	}

	public void setKey(String key)
	{
		this.setKey(Tools.SHA256(key.getBytes()));
	}
	
	public byte[] getKey()
	{
		return this.secretKey.getEncoded();
	}
	
	public void genKey()
	{
		KeyGenerator keyGenerator;
		SecretKey key256 = null;
		try 
		{
			keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(256);
			key256 = keyGenerator.generateKey();
		} 
		catch(Exception e)
		{
			e.printStackTrace();
		}
		secretKey = key256;
	}
	
	/**
	* Шифрует rawMsg
	*
	*/
	public byte[] encrypt(byte[] rawMsg)
	{
		return makeAES256_withSalt(rawMsg, AES256.ifENCRYPT);
	}

	/**
	* Дешифрует rawMsg
	*
	*/
	public byte[] decrypt(byte[] enMsg)
	{
		
		return makeAES256_withSalt(enMsg, AES256.ifDECRYPT);
	}
	
	private byte[] makeAES256_withSalt(byte[] rawMessage, int mode) throws IllegalArgumentException
	{
		
		int i, j, k;
		byte[] output;
		byte[] msg;
		byte[] buff;
		Cipher cipher;
		SecureRandom secRND = new SecureRandom();
		if(rawMessage == null || rawMessage.length == 0)
			throw new IllegalArgumentException("rawMessage must be init and len > 0\n");
		try
		{
            cipher = Cipher.getInstance("AES");
            //cipher = Cipher.getInstance("AES/CBC/ZeroBytePadding");
			cipher.init( mode, this.secretKey );
			if(mode == AES256.ifENCRYPT)
			{
				//System.out.println(ByteWorker.forPrint(rawMessage));
				msg = new byte[ rawMessage.length + rawMessage.length]; // 0 S 0 S 0 S 0 S 0 S 0 S 0 S 0 S, где S - соль, а 0 - исходные байты
				buff = new byte[rawMessage.length];
				secRND.nextBytes(buff);

				for(i = 0, j = 0, k = 0; i < msg.length; i++)
				{
					if(i % 2 == 1)
					{
						msg[i] = buff[j];
						j++;
					}
					else
					{
						msg[i] = rawMessage[k];
						k++;
					}
				}
				//System.out.println("\n\n" + ByteArrToStr(msg) + " size: " + msg.length);
				output = cipher.doFinal(msg);
				//System.out.println(ByteArrToStr(output) + " size: " + output.length + "\n\n");
			}
			else if (mode == AES256.ifDECRYPT)
			{
				output = cipher.doFinal(rawMessage); // 0 S 0 S 0 S 0 S 0 S 0 S 0 S 0 S, где S - соль, а 0 - исходные байты
				buff = new byte[output.length/2];

				for(i = 0, j = 0; i < output.length; i++)
					if(i % 2 == 0)
					{
						buff[j] = output[i];
						j++;
					}
				output = buff;
				//System.out.println(ByteWorker.forPrint(buff));
			}
			else
			{
				System.out.println("There is no a such mode: " + mode);
				output = null;
			}
            return output;
		} 
		catch (Exception e)
		{
            e.printStackTrace();
            return null;
        }
	}
}
