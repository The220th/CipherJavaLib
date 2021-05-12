package CipherLib;

import java.lang.*;
import java.util.*;

public interface IAsymCipher
{
	public abstract void genKeys();

	public abstract byte[] getPubKey();

	public abstract byte[] getPrivKey();

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
	public abstract void setKeys(byte[] pub, byte[] priv);

	public abstract byte[] encrypt(byte[] rawMsg);

	public abstract byte[] decrypt(byte[] enMsg);


	public static byte[] encrypt(byte[] msg, byte[] pubKey) {return null;}

	public static byte[] decrypt(byte[] msg, byte[] privKey) {return null;}

	/**
	 * Генерирует "закрывающий множитель" closingMultiplier
	 *
	 * Порядок использования функций: genClosingMultiplier, blind, blindSign, unblind. Дальше уже unsign
	 * 
	 * @param pubKey - публичный ключ того, кто будет вслепую подписывать. Для этого ключа и генерируется closingMultiplier
	 * @return закрывающий множитель closingMultiplier
	 */
	public static byte[] genClosingMultiplier(byte[] pubKey) {return null;}

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
	public static byte[] blind(byte[] msg, byte[] closingMultiplier, byte[] pubKey) {return null;}

	/**
	 * Слепая подпись. Подписывающий не узнает, что подписывает
	 *
	 * Порядок использования функций: genClosingMultiplier, blind, blindSign, unblind. Дальше уже unsign
	 * 
	 * @param msg_blind - скрытое сообщение, полученное из функции blind
	 * @param privKey - приватный ключ того, кто подписывает
	 * @return подписанное скрытое сообщение signedBlindMsg, теперь нужно снять закрывающий множитель, для этого используйте функцию unblind 
	 */
	public static byte[] blindSign(byte[] msg_blind, byte[] privKey) {return null;}

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
	public static byte[] unblind(byte[] msg, byte[] signedBlindMsg, byte[] closingMultiplier, byte[] pubKey) {return null;}

	/**
	 * Подписывает сообщение
	 * 
	 * @param msg - подписываемое сообщение
	 * @param privKey - приватный ключ того, кто подписывает. Из getPrivKey()
	 * @return [подпись] + [само сообщение]
	 */
	public static byte[] sign(byte[] msg, byte[] privKey) {return null;}

	/**
	 * Проверяет подпись сообщения
	 *
	 * @param signedMsg - подписанное сообщение
	 * @param pubKey - публичный ключ того, кто подписал
	 * @return возвращает, если подпись верна, исходное сообщение, которое подписывали, или вернёт null
	 */
	public static byte[] unsign(byte[] signedMsg, byte[] pubKey) {return null;}
}
