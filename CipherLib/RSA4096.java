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

	public static void main(String[] args)
	{
		RSA4096 rsaBob, rsaAlice;
		RSA4096 rsaBuff;
		byte[] buff, buff2, buff3;
		byte[] buffKey;
		byte[] pubKeyBuff, privKeyBuff;
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

			rsaBuff = new RSA4096();
			rsaBuff.genKeys();
			pubKeyBuff = rsaBuff.getPubKey();
			privKeyBuff = rsaBuff.getPrivKey();

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

				//Просто зашифровать и расшифровать с помощью static методов
				for(int j = 0; j < 10; ++j)
				{
					buff = RSA4096.encrypt(srcMsg.getBytes(), pubKeyBuff);

					buff = RSA4096.decrypt(buff, privKeyBuff);

					getMsg = new String(buff);

					if(srcMsg.equals(getMsg) == false)
						throw new IllegalStateException("error");
				}

				//Тестирование слепой подписи
				for(int j = 0; j < 10; ++j)
				{
					buff2 = srcMsg.getBytes();

					buff3 = RSA4096.genClosingMultiplier(pubKeyBuff);

					buff = RSA4096.blind(buff2, buff3, pubKeyBuff);

					buff = RSA4096.blindSign(buff, privKeyBuff);

					buff = RSA4096.unblind(buff2, buff, buff3, pubKeyBuff);

					buff = RSA4096.unsign(buff, pubKeyBuff);

					getMsg = new String(buff);

					if(srcMsg.equals(getMsg) == false)
						throw new IllegalStateException("error");
				}

				System.out.print(gi + "."+ i + " ");
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
		if(pub != null)
		{
			byte[][] pu = ByteWorker.Array2Arrays(pub);
			this.e = new BigInteger(pu[0]);
			this.ne = new BigInteger(pu[1]);
		}
		if(priv != null)
		{
			byte[][] pr = ByteWorker.Array2Arrays(priv);
			this.nd = new BigInteger(pr[1]);
			this.d = new BigInteger(pr[0]);
		}
	}

	public byte[] encrypt(byte[] rawMsg)
	{
		byte[][] a = ByteWorker.cutArray(rawMsg, RSA4096.maxBytes);

		for(int i = 0; i < a.length; ++i)
			a[i] = encrypt1(a[i]);

		return ByteWorker.Arrays2Array(a);
	}

	public byte[] decrypt(byte[] enMsg)
	{
		int i, gi, n, ai;
		byte[][] a = ByteWorker.Array2Arrays(enMsg);
		for(i = 0; i < a.length; ++i)
			a[i] = decrypt1(a[i]);

		return ByteWorker.glueCutedArray(a);
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
	 * Генерирует "закрывающий множитель" closingMultiplier
	 *
	 * Порядок использования функций: genClosingMultiplier, blind, blindSign, unblind. Дальше уже unsign
	 * 
	 * @param pubKey - публичный ключ того, кто будет вслепую подписывать. Для этого ключа и генерируется closingMultiplier
	 * @return закрывающий множитель closingMultiplier
	 */
	public static byte[] genClosingMultiplier(byte[] pubKey)
	{
		byte[][] pu = ByteWorker.Array2Arrays(pubKey);
		BigInteger n = new BigInteger(pu[1]);
		BigInteger r;
		Random rand = new Random();

		do
		{
			r = Tools.rndBigInteger(new BigInteger(_4096/4, rand), n.subtract(BigInteger.ONE));
		}while(Tools.extendedGCD(r, n)[0].equals(BigInteger.ONE) == false);

		return r.toByteArray();
	}

	/**
	 * Скрывает сообщение msg с помощью закрывающего множителя closingMultiplier от того, кто будет подписывать
	 * 
	 * Порядок использования функций: genClosingMultiplier, blind, blindSign, unblind. Дальше уже unsign
	 *
	 * @param msg - Сообщение, которое будет подписываться вслепую
	 * @param closingMultiplier -  закрывающий множитель
	 * @param pubKey - публичный ключ того, кто будет вслепую подписывать
	 * @return скрытое сообщение msg_blind, для слепой подписи
	 */
	public static byte[] blind(byte[] msg, byte[] closingMultiplier, byte[] pubKey)
	{
		//https://ru.wikipedia.org/wiki/%D0%A1%D0%BB%D0%B5%D0%BF%D0%B0%D1%8F_%D0%BF%D0%BE%D0%B4%D0%BF%D0%B8%D1%81%D1%8C#%D0%9F%D1%80%D0%BE%D1%82%D0%BE%D0%BA%D0%BE%D0%BB_RSA
		byte[] hashMsg = Tools.SHA256(msg);
		BigInteger h = ByteWorker.BytesToNum(hashMsg);

		BigInteger r = new BigInteger(closingMultiplier);

		byte[][] buffB = ByteWorker.Array2Arrays(pubKey);
		BigInteger n = new BigInteger(buffB[1]);
		BigInteger e = new BigInteger(buffB[0]);

		BigInteger _m = h.multiply(r.modPow(e, n)).mod(n);
		return _m.toByteArray();
	}

	/**
	 * Слепая подпись. Подписывающий не узнает, что подписывает
	 *
	 * Порядок использования функций: genClosingMultiplier, blind, blindSign, unblind. Дальше уже unsign
	 * 
	 * @param msg_blind - скрытое сообщение, полученное из функции blind
	 * @param privKey - приватный ключ того, кто подписывает
	 * @return подписанное скрытое сообщение signedBlindMsg, теперь нужно снять закрывающий множитель, для этого используйте функцию unblind 
	 */
	public static byte[] blindSign(byte[] msg_blind, byte[] privKey)
	{
		BigInteger _m = new BigInteger(msg_blind);

		byte[][] buffB = ByteWorker.Array2Arrays(privKey);
		BigInteger n = new BigInteger(buffB[1]);
		BigInteger d = new BigInteger(buffB[0]);

		BigInteger _s = _m.modPow(d, n);

		return _s.toByteArray();
	}

	/**
	 * Снять закрывающий множитель closingMultiplier
	 *
	 * Порядок использования функций: genClosingMultiplier, blind, blindSign, unblind. Дальше уже unsign
	 * 
	 * @param msg - исходное сообщение, которое изначально вслепую подписывалось
	 * @param signedBlindMsg - подписанное скрытое сообщение из функции blindSign
	 * @param closingMultiplier - закрывающий множитель
	 * @param pubKey - публичный ключ того, кто подписывал
	 * @return подписанное сообщение msg. Дальше можно проверить подпись с помощью функции unsign
	 */
	public static byte[] unblind(byte[] msg, byte[] signedBlindMsg, byte[] closingMultiplier, byte[] pubKey)
	{
		BigInteger _s = new BigInteger(signedBlindMsg);

		BigInteger r = new BigInteger(closingMultiplier);

		BigInteger n = new BigInteger(ByteWorker.Array2Arrays(pubKey)[1]);

		BigInteger r_inverse = Tools.findInverseMultiplicative(r, n);

		BigInteger h = _s.multiply(r_inverse).mod(n);

		byte[][] buffB = new byte[2][];
		buffB[0] = h.toByteArray();
		buffB[1] = msg;

		return ByteWorker.Arrays2Array(buffB);
	}

	public static byte[] encrypt(byte[] msg, byte[] pubKey)
	{
		RSA4096 rsa = new RSA4096();

		rsa.setKeys(pubKey, null);

		return rsa.encrypt(msg);
	}

	public static byte[] decrypt(byte[] msg, byte[] privKey)
	{
		RSA4096 rsa = new RSA4096();

		rsa.setKeys(null, privKey);

		return rsa.decrypt(msg);
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

		byte[] h = ByteWorker.NumToBytes(_sign.modPow(e, n));

		if(Arrays.equals(h, hashMsg) == true)
			return msg;
		else
			return null;
	}
}
