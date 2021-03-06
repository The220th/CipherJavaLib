# CipherJavaLib

A small library for Java that will help you encrypt

## Что это?

Небольшая "библиотечка", которая поможет работать с шифрованием.

Код НЕ был просмотрен криптоаналитиками, использование на свой страх и риск)

## Что есть на данный момент?

 - RSA4096

 - AES256 с солью, но слишком пересолённый

## Сборка

Чтобы собрать используйте скрипт `Build.sh` или `Build.bat`:

``` bash
> bash Build.sh
```

или

``` bash
> Build.bat
```

Нужнен jdk минимальной версии 1.8

В дирректории, где запускался скрипт `Build.sh` или `Build.bat`, появится файл `CipherLib-xxx.jar` (вместо `xxx` будет что-то другое)

## Как добавить в проект

[Скачайте](https://github.com/The220th/CipherJavaLib/releases) уже готовый релиз `CipherLib-xxx.jar` или [скомпилируйте](#сборка) заново сами.

Пусть у вас в директории `project` есть файл `test.java`, где и планируется использовать `CipherLib`.

Создайте директорию `project/lib` и перенесите туда файл `CipherLib-xxx.jar` (вместо `xxx` будет что-то другое). Теперь, чтобы скомпилировать и запустить, перейдите в директорию `project` и введите команды:

``` bash
> javac -encoding utf-8 -cp .:./lib/CipherLib-xxx.jar test.java
> java -cp .:./lib/CipherLib-xxx.jar test
```

## Пример использования

Для симметричного шифрования на примере класса AES256:

``` java
import java.lang.*;
import java.util.*;
import CipherLib.*;

public class test
{
	public static void main(String[] args)
	{
		//Создаётся шифровальшик
		ISymCipher aes = new AES256();
		
		//Генерируется ключ
		aes.genKey();
		//Или можно использовать "пароль" для класса AES256
		((AES256)aes).setKey("Super password");

		System.out.println("The key were generated");

		//Получим ключ (в данном случае ключ, сгенерированный паролем "Super password")
		byte[] key = aes.getKey();

		//Пересоздадим шифровальшик (почему бы и нет?)
		aes = new AES256();

		//Установим ключ
		aes.setKey(key);

		//Сам процесс шифрования
		String s = "It is message or file";

		byte[] encryptedMsg = aes.encrypt(s.getBytes());
		byte[] decryptedMsg = aes.decrypt(encryptedMsg);
		System.out.println(new String(decryptedMsg));
	}
}
```

Для асимметричного шифрования на примере класса RSA4096:

``` java
import java.lang.*;
import java.util.*;
import CipherLib.*;

public class test
{
	//Алиса и Боб устанавливают защищённое соединение
	public static void main(String[] args)
	{
		//Создаются шифровальшики
		IAsymCipher rsaBob = new RSA4096();
		IAsymCipher rsaAlice = new RSA4096();

		//Генерируются ключи. Это может занять какое-то время, зато это делается лишь 1 раз
		rsaBob.genKeys();
		rsaAlice.genKeys();
		System.out.println("The keys were generated");

		//Получаются эти ключи. Публичный ключ сообщается всем, а приватный держится в секрете, лучше вообще его зашифровать
		byte[] pubBobKey = rsaBob.getPubKey();
		byte[] pubAliceKey = rsaAlice.getPubKey();
		byte[] privBobKey = rsaBob.getPrivKey();
		byte[] privAliceKey = rsaAlice.getPrivKey();

		//Боб общается с Алисой, поэтому:
		//в шифровальшике Боба публичный ключ - это публичный ключ Алисы,
		//а приватный ключ - это приватный ключ Боба
		//У Алисы анологично
		rsaBob.setKeys(pubAliceKey, privBobKey);
		rsaAlice.setKeys(pubBobKey, privAliceKey);

		//Ассиметричное шифрование сильно медленнее, чем симметричное.
		//Поэтому лучше RSA использовать для того, чтобы обменяться ключами для AES-256 и далее шифровать симметричным шифрованием.
		String s1 = "Bob to Alice: It is AES256 key"; //Сообщение может быть любой длины. Сколько хватит RAM.
		byte[] encryptedMsg1 = rsaBob.encrypt(s1.getBytes());
		byte[] decryptedMsg1 = rsaAlice.decrypt(encryptedMsg1);
		System.out.println(new String(decryptedMsg1));

		String s2 = "Alice to Bob: I got it";
		byte[] encryptedMsg2 = rsaAlice.encrypt(s2.getBytes());
		byte[] decryptedMsg2 = rsaBob.decrypt(encryptedMsg2);
		System.out.println(new String(decryptedMsg2));
	}
}
```

Для подписи на примере класса RSA4096:

``` java
import java.lang.*;
import java.util.*;
import CipherLib.*;

public class test
{
	public static void main(String[] args)
	{
		//Создаются ключ того, кто подписывает
		IAsymCipher rsa = new RSA4096();
		rsa.genKeys();
		byte[] pubKey = rsa.getPubKey();
		byte[] privKey = rsa.getPrivKey();

		//=====Обычная цифровая подпись=====
		System.out.println("Digital signature:");

		String msg = "It message is signed.";
		byte[] srcMsg = msg.getBytes();
		
		//Подписываем
		byte[] signedMsg = RSA4096.sign(srcMsg, privKey);
		
		//Проверяем подпись
		byte[] unsignedMsg = RSA4096.unsign(signedMsg, pubKey);
		System.out.println(new String(unsignedMsg));

		//Если хотябы 1 бит будет другой, то вернёт null
		signedMsg[9]++;
		unsignedMsg = RSA4096.unsign(signedMsg, pubKey);
		System.out.println("The message is changed, so it is \"" + unsignedMsg + "\".");

		//=====Слепая цифровая подпись=====
		System.out.println("\nBlind signature:");

		msg = "It is not known what is being signed.";
		srcMsg = msg.getBytes();
		
		//Подписываем то, не знаем что
		byte[] r = RSA4096.genClosingMultiplier(pubKey);
		byte[] hiddenMsg = RSA4096.blind(srcMsg, r, pubKey);
		byte[] signedHiddenMsg = RSA4096.blindSign(hiddenMsg, privKey);
		signedMsg = RSA4096.unblind(srcMsg, signedHiddenMsg, r, pubKey);
		
		//Проверим подпись
		unsignedMsg = RSA4096.unsign(signedMsg, pubKey);
		System.out.println(new String(unsignedMsg));
	}
}
```