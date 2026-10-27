package com.paintingcompetition.domain.ports.out;

public interface MotorCriptograficoPort {

    /**
     * Cifra datos en claro utilizando los parámetros criptográficos
     * correspondientes.
     *
     * @param datos Datos en claro a proteger.
     * @param clave Clave requerida para el algoritmo de cifrado.
     * @return Arreglo de bytes cifrado, o null.
     */
    byte[] cifrar(byte[] datos, Object clave);

    /**
     * Genera una firma digital para garantizar integridad y no repudio.
     *
     * @param datos        Datos o hash a firmar.
     * @param clavePrivada Clave privada del firmante.
     * @return Firma digital generada, o null.
     */
    byte[] firmar(byte[] datos, Object clavePrivada);

    /**
     * Aplica el factor de cegado a un mensaje para el protocolo de firma ciega.
     *
     * @param datos        Mensaje a cegar.
     * @param clavePublica Clave pública de la entidad firmante.
     * @return Mensaje cegado, o null.
     */
    byte[] cegar(byte[] datos, Object clavePublica);

    /**
     * Verifica la autenticidad e integridad de una firma digital.
     *
     * @param datos Datos originales que fueron firmados.
     * @param firma Firma digital a verificar.
     * @param clave Clave pública o parámetros para la verificación.
     * @return true si la firma es válida, false en caso contrario.
     */
    default boolean verificar(byte[] datos, byte[] firma, Object clave) {
        throw new UnsupportedOperationException("La operación de verificación no está soportada por este módulo.");
    }
}
