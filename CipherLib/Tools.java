package CipherLib;

import java.lang.*;
import java.util.*;
import java.math.*;
import java.security.SecureRandom;
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;

public class Tools
{
	public static void main(String[] args)
	{
		Random r = new Random();

		int s = 8, f = 103;
		for(int i = 0; i < 200; ++i)
		{
			System.out.println(s + " <= " + rndBigInteger(BigInteger.valueOf(s), BigInteger.valueOf(f)) + " <= " + f);
		}
	}

	/**
	 * @param n - кол-во бит у генерируемого числа
	 * @return p
	 */
	public static BigInteger rndBigInteger(int n)
	{
		 //rework
		//KAKA9-TO nAPAWA. HADO nEPEDEJlATb 6bl, uCnOJlb3Y9 byte[]
		BigInteger number = new BigInteger(n, new SecureRandom());
		return number.setBit(n-1);
	}

	/**
	 * Генерирует какое-то число на интервале [min; max]. Это число не обязательно простое, скорее наоборот
	 * 
	 * @param min - минимальное число для генерации
	 * @param max - максимальное число для генерации
	 * @return сгенерированное какое-то число
	 */
	public static BigInteger rndBigInteger(BigInteger min, BigInteger max)
	{
		BigInteger a;
		BigInteger dif = max.subtract(min);
		SecureRandom r = new SecureRandom();
		do
		{
			a = new BigInteger(dif.bitLength(), r);
		}while(a.compareTo(dif) > 0);
		return min.add(a);
	}

	/**
	 * Число Софи-Жермен
	 * Может занять ооооочень много времени
	 * Генерирует простое число p, у которого n бит такое, что p*2+1 тоже простое
	 * Вероятность принять составное число за простое будет меньше, чем 1/(4^300)
	 * Скорость генерации почти не зависит от числа k
	 * 
	 * @param n - кол-во бит у генерируемого числа
	 * @return p
	 */
	public static BigInteger rndSophieGermainNum(int n)
	{
		long k = 300; //Кол-во раундов на проверку простоты после нахождения прентендента
		BigInteger res; // Это и есть p
		long minRounds = 30;
		do
		{
			res = rndBigInteger(n);
		}while( !millerRabinTest(res, minRounds) || !millerRabinTest(res.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE), minRounds));

		if( !millerRabinTest(res, k) || !millerRabinTest(res.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE), k))
			res = rndSophieGermainNum(n);
		return res;
	}

	/**
	 * Генерирует простое число p, у которого n бит. Вероятность принять составное число за простое будет меньше, чем 1/(4^300)
	 * Скорость генерации почти не зависит от числа k
	 * 
	 * @param n - кол-во бит у генерируемого числа
	 * @return p
	 */
	public static BigInteger rndPrimeNum(int n)
	{
		BigInteger res; // Это и есть p
		long k = 300; //Кол-во раундов на проверку простоты после нахождения прентендента
		long minRounds = 30;
		do
		{
			res = rndBigInteger(n);
		}while( !millerRabinTest(res, minRounds) );

		if( !millerRabinTest(res, k) )
			res = rndPrimeNum(n);
		return res;
	}

	/**
	 * Тест Миллера — Рабина на простоту числа
	 * Производится rounds раундов проверки числа n на простоту
	 * Из теоремы Рабина следует, что если rounds случайно выбранных чисел оказались свидетелями простоты числа n, то вероятность того, что n составное, не превосходит 4^(-rounds) (или число составное с вероятностью 0.25^rounds)
	 * 
	 * @param n - число, которое проверяется на простоту
	 * @param rounds - кол-во раундов
	 * 
	 * @return true = вероятно простое
	*/
	public static boolean millerRabinTest(BigInteger n, long rounds)
	{
		BigInteger TWO = BigInteger.valueOf(2);
		BigInteger n_MINUS_ONE = n.subtract(BigInteger.ONE);
		// если n == 2 или n == 3 - эти числа простые, возвращаем true
		if (n.compareTo(TWO) == 0 || n.compareTo(BigInteger.valueOf(3)) == 0)
			return true;
	 
		// если n < 2 или n четное - возвращаем false
		if (n.compareTo(TWO) < 0 || n.getLowestSetBit() != 0)
			return false;
	 
		// представим n − 1 в виде (2^s)·t, где t нечётно, это можно сделать последовательным делением n - 1 на 2
		
		BigInteger t = n.subtract( BigInteger.ONE );
	 
		long s = 0;
		while (t.getLowestSetBit() != 0)
		{
			t = t.divide(TWO);
			s += 1;
		}
	 
		// повторить k раз
		for (long i = 0; i < rounds; i++)
		{
			// выберем случайное целое число a в отрезке [2, n − 2]

			BigInteger a = rndBigInteger(TWO, n_MINUS_ONE);
	 
			// x ← a^t mod n, вычислим с помощью возведения в степень по модулю
			BigInteger x = a.modPow(t, n);
	 
			// если x == 1 или x == n − 1, то перейти на следующую итерацию цикла
			if (x.compareTo(BigInteger.ONE) == 0 || x.compareTo(n_MINUS_ONE) == 0)
				continue;
	 
			// повторить s − 1 раз
			for (long r = 1; r < s; r++)
			{
				// x ← x^2 mod n
				x = x.modPow(TWO, n);
	 
				// если x == 1, то вернуть "составное"
				if (x.compareTo(BigInteger.ONE) == 0)
					return false;
	 
				// если x == n − 1, то перейти на следующую итерацию внешнего цикла
				if (x.compareTo( n_MINUS_ONE ) == 0)
					break;
			}
			
			if (x.compareTo( n_MINUS_ONE ) != 0)
				return false;
		}
	 
		// вернуть "вероятно простое"
		return true;
	}


	/**
	 * Расширенный алгоритм Евклида
	 * a*x + b*y = gcd(a, b)
	 * 
	 * @return тройка чисел: return[0]=gcd, return[1]=x, return[2]=y
	*/
	public static BigInteger[] extendedGCD(BigInteger a, BigInteger b)
	{
		//https://neerc.ifmo.ru/wiki/index.php?title=%D0%9D%D0%B0%D0%B8%D0%B1%D0%BE%D0%BB%D1%8C%D1%88%D0%B8%D0%B9_%D0%BE%D0%B1%D1%89%D0%B8%D0%B9_%D0%B4%D0%B5%D0%BB%D0%B8%D1%82%D0%B5%D0%BB%D1%8C
		BigInteger[] res = new BigInteger[3];
		BigInteger x, y;
		if(b.compareTo(BigInteger.ZERO) == 0)
		{
			res[0] = a;
			res[1] = BigInteger.ONE;
			res[2] = BigInteger.ZERO;
			return res;
		}
		res = extendedGCD(b, a.mod(b));
		x = res[2];
		y = a.divide(b).multiply(res[2]);
		y = res[1].subtract(y);
		res[1] = x;
		res[2] = y;
		return res;
	}

	/**
	 * Поиск обратного мультипликативного
	 * a*x = 1 mod(m)
	 * Может вернуть null, если нет решения 
	 *
	 * @return x = a^-1 или null, если нет решения.
	*/
	public static BigInteger findInverseMultiplicative(BigInteger a, BigInteger m)
	{
		 //https://e-maxx.ru/algo/reverse_element
		//a*x = 1 mod(m) <==> a*x + m*y = gcd(a, m)
		BigInteger[] res = extendedGCD(a, m);
		if(res[0].compareTo(BigInteger.ONE) != 0)
			return null;
		else
			return res[1];
	}

	/**
	 * Генерирует рандомную строку
	 *
	 * @param length - длина генерируемой строки
	 * @return случайная строка
	*/
	public static String genRndString(int length)
	{
		String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890 zyxwvutsrqponmlkjihgfedcba";
		Random r = new SecureRandom();
		StringBuilder sb = new StringBuilder(length);
		for (int i = 0; i < length; ++i)
            sb.append( characters.charAt( r.nextInt( characters.length() ) ) );
        return sb.toString();
	}

	/**
	 * Хеш-функция SHA-256
	 *
	 * @param msg - сообщение, хэш которого вычисляется
	 * @return hash of msg
	*/
	public static byte[] SHA256(byte[] msg)
	{
        MessageDigest md = null;
        byte[] res = null;
        try
        {
            md = MessageDigest.getInstance("SHA-256");
            res = md.digest(msg);
            
        }
        catch(Exception e)
        {
            System.out.println("Trouble in Tools.SHA256\n ");
            e.printStackTrace();
        }
        return res;
	}
}
