package CipherLib;

import java.lang.*;
import java.util.*;

import java.security.SecureRandom;

import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;

import java.math.BigInteger;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.*;

/**
 * Класс, позволяющий удобн?о работать с массивом байт. Ни один из методов не "портит" аргументы
 * 
 * @version 0.3
 */
public class ByteWorker
{
    public static final float version = 0.1f;

    public static final byte The8thBit = -128;
    public static final byte The7thBit = 64;
    public static final byte The6thBit = 32;
    public static final byte The5thBit = 16;
    public static final byte The4thBit = 8;
    public static final byte The3thBit = 4;
    public static final byte The2thBit = 2;
    public static final byte The1thBit = 1;

    /**
     * Чисто для тестов
     */
    public static void main(String[] args)
    {
    }

    /**
     * Дополняет массив src до длины n байтами filler
     * Если src.length == n, то ничего не происходит, а просто возвращается копия
     * Если src.length > n, то исходный массив обрезается до длины n
     * 
     * @param src - исходный массив, который дополняется. Он никак не модифицируется
     * @param n - длина, до которой дополняется массив src
     * @param filler - байт, которым дополняется массив src
     * @return изменённый массив
     */
    public static byte[] fill(byte[] src, int n, byte filler)
    {
        byte[] res =  new byte[n];
        int i;
        if(src.length < n)
        {
            for(i = 0; i < src.length; i++)
                res[i] = src[i];
            for(; i < res.length; i++)
                res[i] = filler;
        }
        else
            for(i = 0; i < n; i++)
                res[i] = src[i];
        return res;
    }

    /**
     *  Представляет int в виде 4-х байт
     * 
     * @param x - число, которое представляется в виде 4-х байт
     * @return представление числа x в виде 4-х байт
     */
    public static byte[] Int2Bytes(int x)
    {
        int i, j;
        int n = Integer.BYTES;
        int nBytes = Byte.BYTES * 8;
        byte[] res = new byte[n];
        for(i = 0; i < n; i++, x = x >> 8)
        {
            byte buff = 0;
            byte zipzap = 1;
            for(j = 0; j < nBytes; j++, zipzap = (byte)(zipzap << 1))
            {
                buff = (byte)(buff | (zipzap & x));
            }
            res[i] = buff;
        }
        return res;
    }

    /**
     * Представляет байты в виде int
     * Если x.length != Integer.BYTES, то бросает IllegalArgumentException
     * 
     * @param x - байты представляющие int
     * @return int, который представляют байты x 
     */
    public static int Bytes2Int(byte[] x) throws IllegalArgumentException
    {
        int res = 0;
        int i, j;
        int n = Integer.BYTES;
        int nBytes = Byte.BYTES * 8;
        int zipzap = 1;
        if(x.length != Integer.BYTES)
            throw new IllegalArgumentException("Integer must have " + Integer.BYTES + " bytes");
        for(i = 0; i < n; i++)
        {
            byte buff = 1;
            for(j = 0; j < nBytes; j++, zipzap = zipzap << 1, buff = (byte)(buff << 1))
            {
                res =  res | (zipzap & ((buff & x[i]) != 0?0xFFFFFFFF:0));
            }
        }
        return res;
    }

    /**
     * Сцепляет 2 массива в один: res = [first][second]
     * 
     * @param first - первый массив для сцепления
     * @param second - второй массив для сцепления
     * @return res - сначала массив байт first, затем - second
     */
    public static byte[] concatenateArrays(byte[] first, byte[] second)
    {
        byte[] res = new byte[first.length + second.length];
        int i, j;
        for(i = 0, j = 0; j < first.length; j++, i++)
            res[i] = first[j];
        for(j = 0; j < second.length; j++, i++)
            res[i] = second[j];
        return res;
    }

    /**
     * Добавляет размер массива перед самим массивом байт. Размер представляется в виде числа Integer
     * Посмотрите ByteWorker.Int2Bytes
     * 
     * @param src : Вначале src подставится его размер
     * @return [размер src] + [src]
     */
    public static byte[] addSizeBefore(byte[] src)
    {
        byte[] srcSize = ByteWorker.Int2Bytes(src.length);
        return ByteWorker.concatenateArrays(srcSize, src);
    }

    /**
     * Убирает размер массива перед самим массивом после работы метода ByteWorker.addSizeBefore
     * 
     * @param SizeSrc - [размер src] + [src]
     * @return [src]
     */
    public static byte[] removeSizeBefore(byte[] SizeSrc)
    {
        return ByteWorker.sub(SizeSrc, Integer.BYTES, SizeSrc.length);
    }

    public static int getSizeBefore(byte[] SizeSrc)
    {
        return ByteWorker.Bytes2Int( ByteWorker.sub(SizeSrc, 0, Integer.BYTES) );
    }

    /**
     * Срез массива
     * Если begin >= end, то бросает IllegalArgumentException
     * 
     * @param a - массив, который "режется"
     * @param begin - начало среза
     * @param end - конец среза
     * @return подмассив начиная с элемента begin, заканчивая end (не включительно)
     */
    public static byte[] sub(byte[] a, int begin, int end) throws IllegalArgumentException
    {
        if(begin >= end)
            throw new IllegalArgumentException("begin must be less than end. You have: begin = " + begin + ", end = " + end);
        int i, j;
        byte[] res = new byte[end - begin]; // 0 0 0 0 0 0 0 0
        for(i = 0, j = begin; i < res.length; i++, j++)
            res[i] = a[j];
        return res;
    }

    /**
     * Представление для вывода массива байт
     * Считается, что byte = unsigned byte
     * 
     * @param a - массив, который выводится
     * @return строка, представляющая вывод a
     */
    public static String forPrint(byte[] a)
    {
        StringBuilder res = new StringBuilder();
        res.append("[");
        for(int i = 0; i < a.length; i++)
        {
            res.append(Integer.toString((a[i]&ByteWorker.The8thBit)==0?a[i]:a[i]+256));
            if(i != a.length-1)
                res.append(", ");
        }
        res.append("]");
        return res.toString();
    }

    /**
     * Генерирует массив случайных байт размером n
     * 
     * @param n - размер генерируемого массива
     * @return массив случайных байт размером n
     */
    public static byte[] randomDeArray(int n)
    {
        byte[] res = new byte[n];
        (new Random()).nextBytes(res);
        return res;
    }

    /**
     * Генерирует массив размером n с "безопасных" случайных байт. Используется SecureRandom
     * Для криптографии или подобных вещей лучше использовать именно этот метод
     * 
     * @param n - размер генерируемого массива
     * @return массив случайных байт размером n
     */
    public static byte[] randomSecArray(int n)
    {
        byte[] res = new byte[n];
        (new SecureRandom()).nextBytes(res);
        return res;
    }

    /**
     * Соединяет массивы массивов байт в 1 массив байт
     * 
     * @param a - массивы, которые нужно объединить в один с возможностью восстановления
     * @return массив представляющий объединённые массивы. Далее используйте ByteWorker.Array2Arrays, чтобы всё вернуть как было
     */
    public static byte[] Arrays2Array(byte[][] a)
    {
        int i, j, gi;
        byte[] res;
        int n = 0;
        byte[] buff;
        for(i = 0; i < a.length; i++)
            n += Integer.BYTES + a[i].length;
        n += Integer.BYTES;
        res = new byte[n];

        buff = ByteWorker.Int2Bytes(a.length);
        for(i = 0, gi = 0; i < buff.length; i++, gi++)
            res[gi] = buff[i];


        for(i = 0; i < a.length; i++)
        {
            buff = ByteWorker.addSizeBefore(a[i]);
            for(j = 0; j < buff.length; j++, gi++)
                res[gi] = buff[j];
        }
        return res;
    }

    /**
     * Возвращает исходные массивы из массива полученного из ByteWorker.Arrays2Array
     * 
     * @param a - массив, содержащий исходные массивы
     * @return массив исходных массивов байт
     */
    public static byte[][] Array2Arrays(byte[] a)
    {
        int i, j, gi;
        byte[][] res;
        byte[] buff;
        int buffLen;

        buff = new byte[Integer.BYTES];
        for(i = 0, gi = 0; i < buff.length; i++, gi++)
            buff[i] = a[gi];
        res = new byte[ByteWorker.Bytes2Int(buff)][];
        for(i = 0; i < res.length; i++)
        {
            for(j = 0; j < buff.length; j++, gi++)
                buff[j] = a[gi];
            buffLen = ByteWorker.Bytes2Int(buff);
            res[i] = new byte[buffLen];
            for(j = 0; j < res[i].length; j++, gi++)
                res[i][j] = a[gi];
        }
        return res;
    }

    /**
     * Получает Хэш массива байт a, с помощью SHA-256
     * 
     * @param a - массив байт, хэш которого получается
     * @return массив байт, представляющий хэш массива a
     */
    public static byte[] getHash(byte[] a)
    {
        MessageDigest md = null;
        byte[] res = null;
        try
        {
            md = MessageDigest.getInstance("SHA-256");
            res = md.digest(a);
            
        }
        catch(Exception e)
        {
            System.out.println("WOK in ByteWorker.getHash\n ");
            e.printStackTrace();
        }
        return res;
    }

	/**
	 * Метод, который позволит единственным образом представить байты в виде большого числа
	 * 
	 * @param b - набор байт, который необходимо представить в виде большого числа
	 * @return большое число, которое представляет единственным образом b
	 */
	public static BigInteger BytesToNum(byte[] b)
	{
		byte[] res = new byte[b.length + 1];
		
		for(int i = 0; i < b.length; i++)
			res[i+1] = b[i];
		res[0] = 127;
		return new BigInteger(res);
	}

	/**
	 * Метод, который позволяет представить единственным образом большое число в виде байт
	 * 
	 * @param a - число, которое необходимо представить в виде байт
	 * @return байты, которые представляют число есдинственным образом
	 */
	public static byte[] NumToBytes(BigInteger a)
	{
		byte[] b = a.toByteArray();
		byte[] res = new byte[b.length-1];
		for(int i = 0; i < res.length; i++)
			res[i] = b[i+1];
		return res;
    }
    
    /**
     * Разворачивает массив a
     * 
     * @param a - массив байт, который будет разворачиваться
     * @return развёрнутый массив байт a
     */
    public static byte[] reverse(byte[] a)
    {
        byte[] res = new byte[a.length];
        for(int i = 0; i < res.length; i++)
            res[i] = a[a.length-1-i];
        return res;
    }

    /**
     * Представляет массив байт a в виде строки единственным образом
     * Используется Base64
     * 
     * @param a - массив, который переводится в строку
     * @return строка, представляющая массив байт a. Используйте далее ByteWorker.String2Bytes
     */
    public static String Bytes2String(byte[] a)
    {
        return Base64.getEncoder().encodeToString(a);
    }

    /**
     * Представляет строку, полученную в ByteWorker.Bytes2String, обратно в виде байт
     * 
     * @param S - строка полученная из ByteWorker.Bytes2String
     * @return исходный массив байт
     */
    public static byte[] String2Bytes(String S)
    {
        return Base64.getDecoder().decode(S);
    }

    /**
     * Подсчитывает кол-во вхождений байта x в массиве байт a
     * 
     * @param a - массив байт, где считается кол-во байтов x
     * @param x - байт, количество которого считается в массиве a
     * @return количество вхождений байта x в a
     */
    public static int countX(byte[] a, byte x)
    {
        int res = 0;
        for(int i = 0; i < a.length; i++)
            if(a[i] == x)
                res++;
        return res;
    }

    /**
     * Убирает из массива байт a, все байты x
     * 
     * @param a - массив байт, из которого удаляются все x
     * @param x - байт, который удаляется из a
     * @return массив байт, где нет ни одного байта x
     */
    public static byte[] deleteAllX(byte[] a, byte x)
    {
        byte[] res = new byte[a.length - ByteWorker.countX(a, x)];
        if(res.length == 0)
            return res;
        for(int i = 0, j = 0; i < a.length; i++)
            if(a[i] != x)
            {
                res[j] = a[i];
                j++;
            }
        return res;
    }

    /**
     * Удаляет первый попавшийся x в массиве байт a
     * Если нет в массиве a байта x, то возвращается просто копия a
     * 
     * @param a - массив, из которого удаляется первый попавшийся байт x
     * @param x - байт, который удаляется из a
     * @return массив, где первый попавшийся x удалён
     */
    public static byte[] deleteFirstX(byte[] a, byte x)
    {
        byte[] res;
        boolean f;
        int i, j;
        for(i = 0, f = false; i < a.length && !f; i++)
            if(a[i] == x)
                f = true;
        if(f)
            res = new byte[a.length - 1];
        else
            res = new byte[a.length];
        for(i = 0, j = 0; i < a.length; i++, j++)
        {
            if(!f)
                res[j] = a[i];
            else if (a[i] == x)
            {
                i++;
                f = false;
                if(j != res.length)
                    res[j] = a[i];
            }
            else
                res[j] = a[i];
        }
        return res;
    }

    /**
     * Удаляет первый с конца попавшийся x в массиве байт a
     * Если нет в массиве a байта x, то возвращается просто копия a
     * 
     * @param a - массив, из которого удаляется первый с конца попавшийся байт x
     * @param x - байт, который удаляется из a
     * @return массив, где первый с конца попавшийся x удалён
     */
    public static byte[] deleteLastX(byte[] a, byte x)
    {
        byte[] res;
        boolean f;
        int i, j;
        for(i =  a.length-1, f = false; i >= 0 && !f; i--)
            if(a[i] == x)
                f = true;
        if(f)
            res = new byte[a.length - 1];
        else
            res = new byte[a.length];
        for(i = a.length-1, j = res.length-1; i >= 0; i--, j--)
        {
            if(!f)
                res[j] = a[i];
            else if (a[i] == x)
            {
                i--;
                f = false;
                if(j != -1)
                    res[j] = a[i];
            }
            else
                res[j] = a[i];
        }
        return res;
    }

    /**
     * Удалить элемент из массива байт a, имеющий индекс index
     * Если index < 0 или index >= a.length, то бросает IndexOutOfBoundsException
     * 
     * @param a - массив байт, из которого удаляется элемент с индексом index
     * @param index - индекс удаляемого элемента
     * @return массив без элемента с индексом index
     */
    public static byte[] delete(byte[] a, int index) throws IndexOutOfBoundsException
    {
        if(index < 0 || index >= a.length)
            throw new IndexOutOfBoundsException("index = " + index + ", and length of the array = " + a.length);
        byte[] res = new byte[a.length-1];
        int i, j;
        for(i = 0, j = 0; i < a.length; i++, j++)
            if(i != index)
            {
                res[j] = a[i];
            }
            else
                j--;
        return res;
    }

    /**
     * Копирует массив src
     * 
     * @param src [Type = byte] - исходный массив, который копируется
     * @return [Type = byte] скопированный массив src
     */
    public static byte[] copyAs_byte(byte[] src)
    {
        byte[] res = new byte[src.length];
        for(int i = 0; i < res.length; i++)
            res[i] = src[i];
        return res;
    }

    /**
     * Копирует массив src
     * 
     * @param src [Type = Byte] - исходный массив, который копируется
     * @return [Type = byte] скопированный массив src
     */
    public static byte[] copyAs_byte(Byte[] src)
    {
        byte[] res = new byte[src.length];
        for(int i = 0; i < res.length; i++)
            res[i] = src[i].byteValue();
        return res;
    }

    /**
     * Копирует массив src
     * 
     * @param src [Type = byte] - исходный массив, который копируется
     * @return [Type = Byte] скопированный массив src
     */
    public static Byte[] copyAs_Byte(byte[] src)
    {
        Byte[] res = new Byte[src.length];
        for(int i = 0; i < res.length; i++)
            res[i] = Byte.valueOf(src[i]);
        return res;
    }

    /**
     * Копирует массив src
     * 
     * @param src [Type = Byte] - исходный массив, который копируется
     * @return [Type = Byte] скопированный массив src
     */
    public static Byte[] copyAs_Byte(Byte[] src)
    {
        Byte[] res = new Byte[src.length];
        for(int i = 0; i < res.length; i++)
            res[i] = src[i];
        return res;
    }

    /**
     * Сортировка массива байт с помощью быстрой сортировки O(n*log(n)). Если:
     * mode == 0, сортировка по возрастанию, считая что byte = unsigned byte
     * mode == 1, сортировка по убыванию, считая что byte = unsigned byte
     * mode == 2, сортировка по возрастанию, считая что байты имеют знак
     * mode == 3, сортировка по убыванию, считая что байты имеют знак
     * иначе бросает IllegalArgumentException
     * 
     * @param a - массив байт, который сортируется
     * @param mode - режим сортировки
     * @return отсортированный массив байт
     */
    public static byte[] sort(byte[] src, int mode) throws IllegalArgumentException
    {
        /*Нерабочаямедленнаяпараша, газор-позор. O(n*log(n)), ага*/
        Byte[] res = ByteWorker.copyAs_Byte(src);
        switch(mode)
        {
            case 0:
                Arrays.sort(res, (Byte a, Byte b) -> {int x = a.intValue(), y = b.intValue(); x = (x&ByteWorker.The8thBit)==0?x:x+256; y = (y&ByteWorker.The8thBit)==0?y:y+256; return x - y; } );
                break;
            case 1:
                Arrays.sort(res, (Byte a, Byte b) -> {int x = a.intValue(), y = b.intValue(); x = (x&ByteWorker.The8thBit)==0?x:x+256; y = (y&ByteWorker.The8thBit)==0?y:y+256; return y - x; } );
                break;
            case 2:
                Arrays.sort(res, (Byte a, Byte b) -> { return a.byteValue() - b.byteValue(); } );
                break;
            case 3:
                Arrays.sort(res, (Byte a, Byte b) -> { return b.intValue() - a.intValue(); } );
                break;
            default:
                throw new IllegalArgumentException("Mode is " + mode + ", but allowed only [0, 1, 2, 3]");
        }
        return ByteWorker.copyAs_byte(res);
    }

    /**
     * Переводит byte в unsigned byte, но в виде int
     * 
     * @param x - byte, где восьмой бит единица
     * @return unsigned byte в виде int
     */
    public static int unsignedByte(byte x)
    {
        return (x&ByteWorker.The8thBit)==0?(int)x:(int)x+256;
    }

    /**
     * Переводит unsigned byte, в виде int, в byte 
     * 
     * @param x - byte, где восьмой бит единица
     * @return byte со знаком
     * @throws IllegalArgumentException, если 0 > x или x >= 256
     */
    public static byte signedByte(int x) throws IllegalArgumentException
    {
        if(x < 0 || x >= 256)
            throw new IllegalArgumentException("Byte can be only [0; 255], you gave: " + x);
        return x < 128?(byte)x:(byte)(x-256);
    }

    /**
     * Конструирует байт по заданным битам
     * Пример: число 33 = 00100001. Первый и шестой бит равны единице (true), а остальные нулю (false)
     * 
     * @param bit8 - восьмой бит байта
     * @param bit7 - седьмой бит байта
     * @param bit6 - шестой бит байта
     * @param bit5 - пятый бит байта
     * @param bit4 - четвёртый бит байта
     * @param bit3 - третий бит байта
     * @param bit2 - второй бит байта
     * @param bit1 - первый бит байта
     * @return байт, сконструированный заданными битами
     */
    public static byte makeByte(boolean bit8, boolean bit7, boolean bit6, boolean bit5, boolean bit4, boolean bit3, boolean bit2, boolean bit1)
    {
        byte res = 0;
        res |= bit8?ByteWorker.The8thBit:0;
        res |= bit7?ByteWorker.The7thBit:0;
        res |= bit6?ByteWorker.The6thBit:0;
        res |= bit5?ByteWorker.The5thBit:0;
        res |= bit4?ByteWorker.The4thBit:0;
        res |= bit3?ByteWorker.The3thBit:0;
        res |= bit2?ByteWorker.The2thBit:0;
        res |= bit1?ByteWorker.The1thBit:0;
        return res;
    }

    /**
     * Достаёт num-ый бит из байта x
     * Если num > 8 или num < 1, то бросает IllegalArgumentException
     * 
     * @param x - байт, из которого "достаётся" num-ый бит
     * @param num - номер бита, который нужно получить из байта x
     * @return num-ый бит из байта x
     */
    public static boolean getBit(byte x, int num) throws IllegalArgumentException
    {
        byte anderino = 0;
        switch(num)
        {
            case 1:
                anderino = ByteWorker.The1thBit;
                break;
            case 2:
                anderino = ByteWorker.The2thBit;
                break;
            case 3:
                anderino = ByteWorker.The3thBit;
                break;
            case 4:
                anderino = ByteWorker.The4thBit;
                break;
            case 5:
                anderino = ByteWorker.The5thBit;
                break;
            case 6:
                anderino = ByteWorker.The6thBit;
                break;
            case 7:
                anderino = ByteWorker.The7thBit;
                break;
            case 8:
                anderino = ByteWorker.The8thBit;
                break;
            default:
                throw new IllegalArgumentException("Byte have only 8 bits: 1th, 2th, 3th, 4th, 5th, 6th, 7th, 8th. And you want " + num + "th bit. It is impossible");
        }
        return (x & anderino) != 0;
    }

    /**
     * Представляет байт в двоичной системе счисления
     * Например: x = -97, res = "10011111"
     * Например: x = 113, res = "01110001"
     * 
     * @param x - байт, который представляется в двоичной системе счисления
     * @return строка, представляющая байт x в двоичной системе счисления
     */
    public static String Byte2Bin(byte x)
    {
        String res = "";
        res += (ByteWorker.getBit(x, 8)?"1":"0") + (ByteWorker.getBit(x, 7)?"1":"0") + (ByteWorker.getBit(x, 6)?"1":"0") + (ByteWorker.getBit(x, 5)?"1":"0") + (ByteWorker.getBit(x, 4)?"1":"0") + (ByteWorker.getBit(x, 3)?"1":"0") + (ByteWorker.getBit(x, 2)?"1":"0") + (ByteWorker.getBit(x, 1)?"1":"0");
        return res;
    }

    /**
     * "Делает" байт из строки, представляющей его в двоичной системе счисления
     * Например: S = "10011111", byte = -97
     * Например: S = "01110001", byte = 113
     * Если длина S > 8 или S содержит символи кроме '1' или '0', то бросает IllegalArgumentException
     * 
     * @param S - строкf, представляющая байт в двоичной системе счисления
     * @return байт
     */
    public static byte Bin2Byte(String S) throws IllegalArgumentException
    {
        /*MO)l(ET nOuTu CnATb? He...*/
        if(S.length() > Byte.BYTES*8 || S.length() == 0)
            throw new IllegalArgumentException("Byte have max 8 bit, you have " + S.length() + " bit (" + S + ")");
        for(int i = 0; i < S.length(); i++)
            if(!S.substring(i, i+1).equals("0") && !S.substring(i, i+1).equals("1"))
                throw new IllegalArgumentException("Your string: " + S + " - contains characters other than one or zero");
        if(S.length() < Byte.BYTES*8)
        {
            int bufflen = Byte.BYTES*8 - S.length();
            String buffS = "";
            for(int i = 0; i < bufflen; i++)
                buffS += "0";
            S = buffS + S;
        }
        return ByteWorker.makeByte(S.substring(0, 1).equals("1"), S.substring(1, 2).equals("1"), S.substring(2, 3).equals("1"), S.substring(3, 4).equals("1"), S.substring(4, 5).equals("1"), S.substring(5, 6).equals("1"), S.substring(6, 7).equals("1"), S.substring(7, 8).equals("1"));
    }

    /**
     * Вставляет на позицию where байт x в массив a
     * Если where < 0 или where > a.length, то бросает IndexOutOfBoundsException
     * 
     * @param a - массив, в который вставляется x
     * @param where - позиция, куда вставляется x
     * @param x - байт, который вставляется в массив a
     * @return массив байт, где на позиции where "стоит" байт x
     */
    public static byte[] insert(byte[] a, int where, byte x) throws IndexOutOfBoundsException
    {
        if(where < 0 || where > a.length)
            throw new IndexOutOfBoundsException("Array length is " + a.length + ", but you want to insert on position " + where);
        int i, j;
        byte[] res = new byte[a.length+1];
        for(i = 0, j = 0; j < res.length; i++, j++)
        {
            if(j == where)
            {
                res[j] = x;
                i--;
            }
            else
                res[j] = a[i];
        }
        return res;
    }

    /**
     * Вставляет на позицию where массив байт x в массив a
     * Если where < 0 или where > a.length, то бросает IndexOutOfBoundsException
     * 
     * @param a - массив, в который вставляется x
     * @param where - позиция, куда вставляется x
     * @param x - массив байт, который вставляется в массив a
     * @return массив байт, где с позиции where начинается массив x
     */
    public static byte[] insert(byte[] a, int where, byte[] x) throws IndexOutOfBoundsException
    {
        if(where < 0 || where > a.length)
            throw new IndexOutOfBoundsException("Array length is " + a.length + ", but you want to insert on position " + where);
        if(x.length == 0)
            return ByteWorker.copyAs_byte(a);
        int i, j;
        byte[] res = new byte[a.length + x.length];
        for(i = 0, j = 0; j < res.length; i++, j++)
        {
            if(j == where)
            {
                for(int li = 0; li < x.length; li++, j++)
                    res[j] = x[li];
                j--;
                i--;
            }
            else
                res[j] = a[i];
        }
        return res;
    }

    /**
     * Режет массив байт a на 2 массива. Первый с 0 до endFirst включительно, второй с beginSecond до a.length включительно
     * 
     * @param a - массив байт, который разделяется
     * @param endFirst - конец первого массива
     * @param beginSecond - начало второго массива
     * @return массив массивов байт, где res[0][] - первый массив, а res[1][] - второй
     */
    public static byte[][] cutInto2(byte[] a, int endFirst, int beginSecond)
    {
        byte[][] res = new byte[2][];
        res[0] = new byte[endFirst + 1];
        res[1] = new byte[a.length - beginSecond];
        int i, j;
        for(i = 0, j = 0; j < res[0].length; i++, j++)
            res[0][j] = a[i];
        for(j = 0, i = beginSecond; j < res[1].length; i++, j++)
            res[1][j] = a[i];
        return res;
    }

    /**
     * Записывает в поток out байты из target так, чтобы их можно было восстановить. Используйте метод ByteWorker.readNextBytes
     * 
     * @param out - поток, куда записывается target
     * @param target - массив, байт, который нужно записать в поток
     * @throws IOException, если какая-то проблема с out
     */
    public static void writeNextBytes(OutputStream out, byte[] target) throws IOException
    {
        /*
        Пример как записывать:
        ...
        try(OutputStream fout = new FileOutputStream("res"))
        {
            byte[] test1 = ByteWorker.randomDeArray(13);
            byte[] test2 = ByteWorker.randomDeArray(5);
            byte[] test3 = ByteWorker.randomDeArray(7);
            System.out.println("1: " + ByteWorker.forPrint(test1) + "\n2: " + ByteWorker.forPrint(test2) + "\n3: " + ByteWorker.forPrint(test3) + "\n");
            ByteWorker.writeNextBytes(fout, test1);
            ByteWorker.writeNextBytes(fout, test2);
            ByteWorker.writeNextBytes(fout, test3);
        }
        catch(Throwable  e)
        {
            e.printStackTrace();
        }
        ...
         */
        out.write(ByteWorker.Int2Bytes(target.length));
        out.write(target);
    }

    /**
     * Считывает из потока in следующий массив байт. Записывать в поток массивы байт нужно с помощью метода ByteWorker.writeNextBytes
     * 
     * @param in - поток, из которого считываются байты
     * @return массив байт, которые считались из in
     * @throws IOException, если какая-то проблема с in
     */
    public static byte[] readNextBytes(InputStream in) throws IOException
    {
        /*
        Пример как считывать:
        ... // из потока из примера в методе ByteWorker.writeNextBytes
        try(InputStream fin = new FileInputStream("res"))
        {
            byte[] res1 = ByteWorker.readNextBytes(fin);
            byte[] res2 = ByteWorker.readNextBytes(fin);
            byte[] res3 = ByteWorker.readNextBytes(fin);
            System.out.println("1: " + ByteWorker.forPrint(res1) + "\n2: " + ByteWorker.forPrint(res2) + "\n3: " + ByteWorker.forPrint(res3) + "\n");
        }
        catch(Throwable e)
        {
            e.printStackTrace();
        }
        ...
         */
        int i, j;
        int bufff;
        byte[] buff = new byte[Integer.BYTES];
        for(i = 0; i < buff.length; i++)
        {
            bufff = in.read();
            if(bufff == -1)
                return null;
            buff[i] = ByteWorker.signedByte(bufff);
        }
        byte[] res = new byte[ByteWorker.Bytes2Int(buff)];
        for(i = 0; i < res.length; i++)
            res[i] = ByteWorker.signedByte( in.read() );
        return res;
    }

    /**
     * Проверяет массивы байт на эквивалентность
     *
     * Например:
     *
     * a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], byN = 4, тогда:
     *
     * return[0] = [1, 2, 3, 4], return[1] = [5, 6, 7, 8], return[2] = [9, 10, 11]
     * 
     * @param a - первый массив байт
     * @param b - второй массив байт
     * @return их эквивалентность
     */
    public static boolean equalsByteArrays(byte[] a, byte[] b)
    {
        return Arrays.equals(a, b);
    }

    /**
     * "Режет" массив на кусочки.
     *
     * Например:
     *
     * a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], byN = 4, тогда:
     *
     * return[0] = [1, 2, 3, 4], return[1] = [5, 6, 7, 8], return[2] = [9, 10, 11]
     * 
     * @param a - массив, который режется
     * @param byN - максимальная длина кусочка
     * @return двойной массив байт с кусочками
     */
     public static byte[][] cutArray(byte[] a, int byN)
     {
        if (a.length == 0 || byN == 0)
            throw new IllegalArgumentException("a.length = " + a.length + ", byN = " + byN);
        int pieces = a.length/byN + 1;
        if(a.length % byN == 0)
            --pieces;
        byte[][] res  = new byte[pieces][];
        int gi, ai, i;
        gi = 0;
        res[0] = new byte[(a.length-gi) < byN?a.length-gi:byN];
        for(i = 0, gi = 0, ai = 0; gi < a.length; ++gi, ++i)
        {
            if(i >= byN)
            {
                ++ai;
                i = 0;
                res[ai] = new byte[(a.length-gi) < byN?a.length-gi:byN];
            }
            res[ai][i] = a[gi];
        }

        return res;
     }

    /**
     * "Собирает" порезанный массив на кусочки.
     *
     * Например:
     *
     * a[0] = [1, 2, 3, 4], a[1] = [5, 6, 7, 8], a[2] = [9, 10, 11], тогда:
     *
     * return = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
     * 
     * @param a - разрезанный массив
     * @return склеенный массив
     */
     public static byte[] glueCutedArray(byte[][] a)
     {
        int i, gi, n, ai;
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
}
