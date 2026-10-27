package com.paintingcompetition.domain.ports.out;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Puerto de Salida para la persistencia, lectura y exportación en Base64
 * del Acta de Resultados y de las llaves criptográficas del Presidente.
 */
public interface GestorArchivosActaPort {

    /**
     * Guarda la clave pública en un archivo de texto codificada en Base64.
     *
     * @param clavePublica Clave pública a persistir.
     * @param rutaArchivo Ruta o nombre de archivo definido por el usuario.
     * @throws IOException Si ocurre un error de E/S.
     */
    void guardarLlavePublicaBase64(PublicKey clavePublica, String rutaArchivo) throws IOException;

    /**
     * Guarda la clave privada en un archivo de texto codificada en Base64.
     *
     * @param clavePrivada Clave privada a persistir.
     * @param rutaArchivo Ruta o nombre de archivo definido por el usuario.
     * @throws IOException Si ocurre un error de E/S.
     */
    void guardarLlavePrivadaBase64(PrivateKey clavePrivada, String rutaArchivo) throws IOException;

    /**
     * Guarda ambas llaves (pública y privada) en archivos de texto separados en Base64.
     *
     * @param parLlaves Par de llaves KeyPair.
     * @param rutaPublica Nombre de archivo para la clave pública.
     * @param rutaPrivada Nombre de archivo para la clave privada.
     * @throws IOException Si ocurre un error de E/S.
     */
    void guardarParLlavesBase64(KeyPair parLlaves, String rutaPublica, String rutaPrivada) throws IOException;

    /**
     * Carga una clave pública RSA desde un archivo de texto en formato Base64.
     *
     * @param rutaArchivo Ruta del archivo con la clave pública.
     * @return PublicKey reconstruida.
     * @throws Exception Si el archivo no existe o el formato es inválido.
     */
    PublicKey cargarLlavePublicaBase64(String rutaArchivo) throws Exception;

    /**
     * Carga una clave privada RSA desde un archivo de texto en formato Base64.
     *
     * @param rutaArchivo Ruta del archivo con la clave privada.
     * @return PrivateKey reconstruida.
     * @throws Exception Si el archivo no existe o el formato es inválido.
     */
    PrivateKey cargarLlavePrivadaBase64(String rutaArchivo) throws Exception;

    /**
     * Lee el documento del Acta de Resultados en texto plano.
     *
     * @param rutaArchivo Ruta del archivo de texto del acta.
     * @return Bytes leídos del documento.
     * @throws IOException Si ocurre un error de lectura.
     */
    byte[] leerDocumentoActa(String rutaArchivo) throws IOException;

    /**
     * Lee el documento del acta desde la ruta especificada, genera la firma RSASSA-PSS
     * con la clave privada provista y retorna la firma resultante en Base64.
     *
     * @param rutaDocumentoActa Ruta del archivo de texto del acta.
     * @param clavePrivada Clave privada del Presidente.
     * @return Firma digital codificada en Base64.
     * @throws IOException Si no es posible leer el archivo.
     */
    String firmarActaYRetornarBase64(String rutaDocumentoActa, PrivateKey clavePrivada) throws IOException;

    /**
     * Verifica la firma digital en Base64 de un acta contra su archivo de texto plano.
     *
     * @param rutaDocumentoActa Ruta del documento en texto plano.
     * @param firmaBase64 Firma digital en Base64.
     * @param clavePublica Clave pública del firmante.
     * @return true si la firma es válida, false en caso contrario.
     * @throws IOException Si no es posible leer el documento.
     */
    boolean verificarFirmaActa(String rutaDocumentoActa, String firmaBase64, PublicKey clavePublica) throws IOException;
}
