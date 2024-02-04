package org.example.generate.rsa.keys;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.Key;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Clase para guardar una llave en un archivo en formato PEM.
 * La clase utiliza la librería Bouncy Castle.
 */
public class PemFile {

    private final PemObject pemObject;

    /**
     * Constructor de la clase.
     * @param key Llave a guardar
     * @param description Descripción de la llave
     */
    public PemFile (Key key, String description) {
      this.pemObject = new PemObject(description, key.getEncoded());
    }

    /**
     * Guarda la llave en un archivo en formato PEM.
     * @param filename Nombre del archivo
     * @throws IOException Si ocurre un error al guardar el archivo
     */
    public void write(String filename) throws IOException {
      try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)))) {
        pemWriter.writeObject(this.pemObject);
      }
    }
}
