package org.example.generate.rsa.keys;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GeneradorLlaves {
  public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
    /* Para generar un par de llaves RSA se puede realizar facilmente en java con la clase KeyPairGenerator de java.security
    Se obtiene una instancia del generador de llaves RSA */
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    /* Se inicializa el generador con el tamaño de la llave en este caso 2048 bits
    Se puede utilizar 1024, 2048 o 4096 bits
    Mientras mas grande sea la llave mas segura es pero tambien mas lenta
    En general 2048 es suficiente*/
    generator.initialize(2048);
    /* Se genera el par de llaves
    El par de llaves se compone de una llave privada y una llave publica
    Generación de números primos aleatorios que probablemente sean primos
    Se generan dos números primos p y q
    Se calcula n = p * q
    Se calcula la función de Euler φ(n) = (p - 1) * (q - 1)
    Se elige un número e tal que 1 < e < φ(n) y que sea coprimo con φ(n)
    Se calcula d tal que (d * e) % φ(n) = 1
    La llave privada es (d, n)
    La llave publica es (e, n) */
    KeyPair pair = generator.generateKeyPair();
    /* Se obtienen las llaves
    La llave privada se utiliza para firmar y desencriptar
    La llave privada se debe guardar en un lugar seguro y no se debe compartir */
    PrivateKey privateKey = pair.getPrivate();
    /* La llave publica se utiliza para verificar firmas y encriptar
    La llave publica se puede compartir con cualquier persona */
    PublicKey publicKey = pair.getPublic();
    /* Se guardan las llaves en archivos
    Se guardan las llaves en formato PEM
    La llave publica se guarda en un archivo llamado public.pem */
    writePemFile(publicKey, "RSA PUBLIC KEY", "public.pem");
    // La llave privada se guarda en un archivo llamado private.pem
    writePemFile(privateKey, "RSA PRIVATE KEY", "private.pem");
  }

  /**
   * Guarda una llave en un archivo en formato PEM.
   * @param key Llave a guardar
   * @param description Descripción de la llave
   * @param filename Nombre del archivo
   * @throws IOException Si ocurre un error al guardar el archivo
   */
  private static void writePemFile(Key key, String description, String filename) throws IOException {
    PemFile pemFile = new PemFile(key, description);
    pemFile.write(filename);
  }
}