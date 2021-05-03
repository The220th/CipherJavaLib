package CipherLib;

import java.lang.*;
import java.util.*;
import java.math.*;

import CipherLib.IAsymCipher;
import CipherLib.Tools;
import CipherLib.ByteWorker;

public class RSA4096 implements IAsymCipher
{
	private static int _4096 = 4096;
	private static int maxBytes = (_4096/8)-5;

	private BigInteger e;
	private BigInteger d;
	private BigInteger ne;
	private BigInteger nd;
	private byte[] pubKey; // {e, n}
	private byte[] privKey; //{d, n}
	//private BigInteger buffI;

	public static void main(String[] args)
	{
		RSA4096 rsaBob, rsaAlice;
		byte[] buff;
		String srcMsg;
		String getMsg;
		Random r = new Random();
		for(int gi = 0; gi < 10; ++gi)
		{
			rsaBob = new RSA4096();
			rsaAlice = new RSA4096();
			rsaBob.genKeys();
			rsaAlice.genKeys();
			buff = rsaAlice.getPubKey();
			rsaAlice.setKeys(rsaBob.getPubKey(), rsaAlice.getPrivKey());
			rsaBob.setKeys(buff, rsaBob.getPrivKey());
			for(int i = 0; i < 100; ++i)
			{
				srcMsg = Tools.genRndString(r.nextInt(3048));
				//System.out.println(srcMsg);

				//Отправим Алисе 10 раз эту строку
				for(int j = 0; j < 10; ++j)
				{
					getMsg = new String(rsaAlice.decrypt(rsaBob.encrypt(srcMsg.getBytes()) ) );
					if(srcMsg.equals(getMsg) == false)
						throw new IllegalStateException("error");
				}

				//Отправим Бобу 10 раз эту строку
				for(int j = 0; j < 10; ++j)
				{
					getMsg = new String(rsaBob.decrypt(rsaAlice.encrypt(srcMsg.getBytes()) ) );
					if(srcMsg.equals(getMsg) == false)
						throw new IllegalStateException("error");
				}

				//Боб подпишет сообщение и отправит 10 раз Алисе, Алиса проверит подпись 10 раз
				for(int j = 0; j < 10; ++j)
				{
					buff = RSA4096.sign(srcMsg.getBytes(), rsaBob.getPrivKey());
					getMsg = new String( RSA4096.unsign(buff, rsaBob.getPubKey()) );
					if(srcMsg.equals(getMsg) == false)
						throw new IllegalStateException("error");
				}

				//Алиса подпишет сообщение и отправит 10 раз Бобу, Боб проверит подпись 10 раз
				for(int j = 0; j < 10; ++j)
				{
					buff = RSA4096.sign(srcMsg.getBytes(), rsaAlice.getPrivKey());
					getMsg = new String( RSA4096.unsign(buff, rsaAlice.getPubKey()) );
					if(srcMsg.equals(getMsg) == false)
						throw new IllegalStateException("error");
				}

				//Боб подпишет сообщение, зашифрует и отправит Алисе. Алиса расшифрует, проверит подпись. Так 10 раз
				for(int j = 0; j < 10; ++j)
				{
					buff = RSA4096.sign(srcMsg.getBytes(), rsaBob.getPrivKey());
					getMsg = new String(RSA4096.unsign(rsaAlice.decrypt(rsaBob.encrypt(buff)), rsaBob.getPubKey()));
					if(srcMsg.equals(getMsg) == false)
						throw new IllegalStateException("error");
				}

				//Алиса подпишет сообщение, зашифрует и отправит Бобу. Боб расшифрует, проверит подпись. Так 10 раз
				for(int j = 0; j < 10; ++j)
				{
					buff = RSA4096.sign(srcMsg.getBytes(), rsaAlice.getPrivKey());
					getMsg = new String(RSA4096.unsign(rsaBob.decrypt(rsaAlice.encrypt(buff)), rsaAlice.getPubKey()));
					if(srcMsg.equals(getMsg) == false)
						throw new IllegalStateException("error");
				}
			}
		}
		System.out.println("All is OK");
	}

	public void genKeys()
	{
		// https://neerc.ifmo.ru/wiki/index.php?title=RSA
		BigInteger p, q, _n, phi, _e, _d;
		Random r = new Random();
		p = Tools.rndPrimeNum(_4096/2);
		q = Tools.rndPrimeNum(_4096/2);
		//4TO-TO MHE nODCKA3blBAET, 4TO JlY4WE uCnOJlb3OBATb 4uCJlA COqpu-)l(EPMEH, HO ETO OOOOO4EHb MEDJlEHHO
		//p = Tools.rndSophieGermainNum(4096);
		//q = Tools.rndSophieGermainNum(4096);
		_n = p.multiply(q);
		p = p.subtract(BigInteger.ONE);
		q = q.subtract(BigInteger.ONE);
		phi = p.multiply(q);
		do
		{
			//_e должно быть больше, чем sqrt(sqrt(n))
			_e = Tools.rndBigInteger(new BigInteger(_4096/4, r), phi.subtract(BigInteger.ONE));
			//_d должно быть больше, чем sqrt(sqrt(n))
			_d = Tools.findInverseMultiplicative(_e, phi);
		}while(_d == null || _d.bitLength() < _4096/4);

		this.e = _e;
		this.d = _d;
		this.ne = _n;
		this.nd = _n;
		//this.buffI = phi;//delete

		byte[][] buffB = new byte[2][];
		buffB[0] = _e.toByteArray();
		buffB[1] = _n.toByteArray();
		this.pubKey = ByteWorker.Arrays2Array(buffB);
		buffB[0] = _d.toByteArray();
		this.privKey = ByteWorker.Arrays2Array(buffB);
	}

	public byte[] getPubKey()
	{
		return ByteWorker.copyAs_byte(this.pubKey);
	}

	public byte[] getPrivKey()
	{
		return ByteWorker.copyAs_byte(this.privKey);
	}

	/**
	 * Устанавливает ключи
	 * 
	 * Предположим, Боб и Алиса обмениваются сообщениями, тогда:
	 * 
	 * Cipher на стороне Боба:
	 * pub - публичный ключ Алисы
	 * priv - приватный ключ Боба
	 *
	 * Cipher на стороне Алисы:
	 * pub - публичный ключ Боба
	 * priv - приватный ключ Алисы
	 */
	public void setKeys(byte[] pub, byte[] priv)
	{
		byte[][] pu = ByteWorker.Array2Arrays(pub);
		byte[][] pr = ByteWorker.Array2Arrays(priv);
		this.ne = new BigInteger(pu[1]);
		this.nd = new BigInteger(pr[1]);
		this.e = new BigInteger(pu[0]);
		this.d = new BigInteger(pr[0]);
	}

	public byte[] encrypt(byte[] rawMsg)
	{
		if (rawMsg.length == 0)
			throw new IllegalArgumentException("rawMsg.length = 0");
		int pieces = rawMsg.length/RSA4096.maxBytes + 1;
		if(rawMsg.length % RSA4096.maxBytes == 0)
			--pieces;
		byte[][] a  = new byte[pieces][];
		int gi, ai, i;
		gi = 0;
		a[0] = new byte[(rawMsg.length-gi) < maxBytes?rawMsg.length-gi:maxBytes];
		for(i = 0, gi = 0, ai = 0; gi < rawMsg.length; ++gi, ++i)
		{
			if(i >= RSA4096.maxBytes)
			{
				++ai;
				i = 0;
				a[ai] = new byte[(rawMsg.length-gi) < maxBytes?rawMsg.length-gi:maxBytes];
			}
			a[ai][i] = rawMsg[gi];
		}

		for(i = 0; i < a.length; ++i)
			a[i] = encrypt1(a[i]);

		return ByteWorker.Arrays2Array(a);




		/*if(Arrays.equals(rawMsg, res) == false || ai != a.length-1)
			throw new IllegalStateException("=(");
		if(Arrays.equals(rawMsg, res) == true)
			throw new IllegalStateException("All is ok");

		return null;*/
	}

	public byte[] decrypt(byte[] enMsg)
	{
		int i, gi, n, ai;
		byte[][] a = ByteWorker.Array2Arrays(enMsg);
		for(i = 0; i < a.length; ++i)
			a[i] = decrypt1(a[i]);

		n = 0;
		for(i = 0; i < a.length; ++i)
			n += a[i].length;
		byte[] res = new byte[n];
		gi = 0;
		for(gi = 0, ai = 0, i = 0; gi < n; ++gi, ++i)
		{
			if(i >= a[ai].length)
			{
				++ai;
				i = 0;
			}
			res[gi] = a[ai][i];
		}
		return res;
	}

	private byte[] encrypt1(byte[] rawMsg)
	{
		BigInteger res;
		BigInteger m = ByteWorker.BytesToNum(rawMsg);
		if(ne.compareTo(m) > 0)
			res = m.modPow(e, ne);
		else
			throw new IllegalArgumentException("rawMsg too big. Max length of rawMsg is " + (ne.toByteArray().length-2));
		return res.toByteArray();
	}

	private byte[] decrypt1(byte[] enMsg)
	{
		BigInteger m = new BigInteger(enMsg);
		BigInteger res = m.modPow(d, nd);
		return ByteWorker.NumToBytes(res);
	}

	/**
	 * Подписывает сообщение
	 * 
	 * @param msg - подписываемое сообщение
	 * @param privKey - приватный ключ того, кто подписывает. Из getPrivKey()
	 * @return [подпись] + [само сообщение]
	 */
	public static byte[] sign(byte[] msg, byte[] privKey)
	{
		byte[] hashMsg = Tools.SHA256(msg);
		//BigInteger h = new BigInteger(hashMsg);
		BigInteger h = ByteWorker.BytesToNum(hashMsg);
		byte[][] buffB = ByteWorker.Array2Arrays(privKey);
		BigInteger n = new BigInteger(buffB[1]);
		BigInteger d = new BigInteger(buffB[0]);
		BigInteger _sign = h.modPow(d, n);
		buffB[0] = _sign.toByteArray();
		buffB[1] = msg;
		return ByteWorker.Arrays2Array(buffB);
	}

	/**
	 * Проверяет подпись сообщения
	 *
	 * @param signedMsg - подписанное сообщение
	 * @param pubKey - публичный ключ того, кто подписал
	 * @return возвращает, если подпись верна, исходное сообщение, которое подписывали, или вернёт null
	 */
	public static byte[] unsign(byte[] signedMsg, byte[] pubKey)
	{
		byte[][] buffB = ByteWorker.Array2Arrays(signedMsg);
		BigInteger _sign = new BigInteger(buffB[0]);
		byte[] msg = buffB[1];
		byte[] hashMsg = Tools.SHA256(msg);
		buffB = ByteWorker.Array2Arrays(pubKey);
		BigInteger e = new BigInteger(buffB[0]);
		BigInteger n = new BigInteger(buffB[1]);

		//byte[] h = _sign.modPow(e, n);
		byte[] h = ByteWorker.NumToBytes(_sign.modPow(e, n));


		if(Arrays.equals(h, hashMsg) == true)
			return msg;
		else
			return null;
	}
}
