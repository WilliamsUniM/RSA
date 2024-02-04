package org.example.use.rsa.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class UsarLLaves {

  public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
      InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    // Archivos con las llaves
    File publicKeyFile = new File("public.pem");
    File privateKeyFile = new File("private.pem");

    // Lee las llaves
    RSAPublicKey publicKey = readX509PublicKey(publicKeyFile);
    RSAPrivateKey privateKey = readPKCS8PrivateKey(privateKeyFile);

    // Mensaje a encriptar
    String mensajeSecreto = "Hola mundo";

    // Crea el objeto para encriptar
    Cipher encryptCipher = Cipher.getInstance("RSA");
    encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

    // Encripta el mensaje
    byte[] mensajeSecretoBytes = mensajeSecreto.getBytes(StandardCharsets.UTF_8);
    byte[] mensajeSecretoEncriptado = encryptCipher.doFinal(mensajeSecretoBytes);

    System.out.println("Mensaje encriptado: " + Base64.getEncoder().encodeToString(mensajeSecretoEncriptado));

    // Crea el objeto para desencriptar
    Cipher decryptCipher = Cipher.getInstance("RSA");
    decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

    // Desencripta el mensaje
    byte[] mensajeSecretoDesencriptado = decryptCipher.doFinal(mensajeSecretoEncriptado);

    System.out.println("Mensaje desencriptado: " + new String(mensajeSecretoDesencriptado, StandardCharsets.UTF_8));

    // Verifica que el mensaje desencriptado sea igual al original
    assertEquals(mensajeSecreto, new String(mensajeSecretoDesencriptado, StandardCharsets.UTF_8));
  }

  /**
   * Lee una llave pública de un archivo en formato PEM.
   * @param file Archivo con la llave pública
   * @return Llave pública
   * @throws IOException Si ocurre un error al leer el archivo
   * @throws NoSuchAlgorithmException Si el algoritmo de la llave no es RSA
   * @throws InvalidKeySpecException Si la llave no es válida
   */
  public static RSAPublicKey readX509PublicKey(File file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Lee el archivo
    String key = Files.readString(file.toPath(), Charset.defaultCharset());

    // Extrae la llave del archivo
    String publicKeyPEM = key
        .replace("-----BEGIN RSA PUBLIC KEY-----", "")
        .replaceAll(System.lineSeparator(), "")
        .replace("-----END RSA PUBLIC KEY-----", "");

    // Decodifica la llave
    byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

    // Crea la llave
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    // Crea la especificación de la llave
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
    // Genera la llave
    return (RSAPublicKey) keyFactory.generatePublic(keySpec);
  }

  /**
   * Lee una llave privada de un archivo en formato PEM.
   * @param file Archivo con la llave privada
   * @return Llave privada
   * @throws IOException Si ocurre un error al leer el archivo
   * @throws NoSuchAlgorithmException Si el algoritmo de la llave no es RSA
   * @throws InvalidKeySpecException Si la llave no es válida
   */
  public static RSAPrivateKey readPKCS8PrivateKey(File file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Lee el archivo
    String key = Files.readString(file.toPath(), Charset.defaultCharset());

    // Extrae la llave del archivo
    String privateKeyPEM = key
        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
        .replaceAll(System.lineSeparator(), "")
        .replace("-----END RSA PRIVATE KEY-----", "");

    // Decodifica la llave
    byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

    // Crea la llave
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    // Crea la especificación de la llave
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
    // Genera la llave
    return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
  }
}
