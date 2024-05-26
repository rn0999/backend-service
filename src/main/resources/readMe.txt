RSA:
Angular - https://pieterdlinde.medium.com/angular-rsa-encryption-netcore-decryption-public-private-key-78f2770f955f
Java - https://www.baeldung.com/java-rsa
Java - https://medium.com/@sharadblog/encryption-and-decryption-in-java-60948b8a3613



RSA + AES : https://medium.com/batc/combining-rsa-aes-encryption-to-secure-rest-endpoint-with-sensitive-data-eb3235b0c0cc

AES:
Spring - https://docs.spring.io/spring-security/reference/features/integrations/cryptography.html#_byteskeygenerator
Spring - https://www.baeldung.com/java-aes-encryption-decryption



Encoded key in java
https://stackoverflow.com/questions/35276820/decrypting-an-openssl-pem-encoded-rsa-private-key-with-java
https://stackoverflow.com/questions/66286457/load-an-encrypted-pcks8-pem-private-key-in-java

Bouncy castle
https://www.baeldung.com/java-bouncy-castle

---------------
### Creating Key Pair for RSA without encryption
openssl genrsa -out private1.pem 2048
openssl rsa -in private1.pem  -outform PEM -pubout -out public1.pem

###Creating Key Pair for RSA with encryption
openssl genrsa -aes256 -passout pass:keypass -out private.pem 2048
openssl rsa -in private.pem -passin pass:keypass -outform PEM -pubout -out public.pem

---------------