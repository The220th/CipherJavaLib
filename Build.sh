#!/bin/bash
find . -name "*.class" -delete
javac ./CipherLib/AES256.java
javac ./CipherLib/RSA4096.java
jar cvf0 ./CipherLib-Beta_V0.1.jar $(find . -name "*.class")
