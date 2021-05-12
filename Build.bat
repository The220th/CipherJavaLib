chcp 1251
del /s *.class
javac ./CipherLib/AES256.java
javac ./CipherLib/RSA4096.java
jar cvf0 ./CipherLib-Beta_V0.2.jar .\CipherLib\ByteWorker.class .\CipherLib\Tools.class .\CipherLib\IAsymCipher.class .\CipherLib\ISymCipher.class .\CipherLib\RSA4096.class .\CipherLib\AES256.class
Pause
CMD /Q /K