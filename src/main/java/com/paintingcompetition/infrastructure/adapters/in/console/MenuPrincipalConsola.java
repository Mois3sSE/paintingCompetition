
package com.paintingcompetition.infrastructure.adapters.in.console;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Scanner;
import java.util.UUID;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.paintingcompetition.domain.model.ActaResultados;
import com.paintingcompetition.domain.model.RolUsuario;
import com.paintingcompetition.domain.model.Usuario;
import com.paintingcompetition.domain.ports.out.MotorCriptograficoPort;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloAnonimatoRSA;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloFirmaRSAPSS;
import com.paintingcompetition.infrastructure.adapters.out.io.GestorArchivosActaAdapter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.nio.file.Path;

import com.paintingcompetition.domain.ports.out.RegistroECDSAPort;
import com.paintingcompetition.domain.ports.out.ConfidencialidadAESPort;
import javax.crypto.SecretKey;

public class MenuPrincipalConsola {

    // =========================================================
    // ARREGLOS DE CREDENCIALES SIMULADAS [Nombre de Usuario, Contraseña]
    // =========================================================
    private static final String[][] USUARIOS_JUEZ = {
            { "juez1", "1234" },
            { "juez2", "juez2026" },
            { "juez3", "juezPass" },
            { "carlos", "clave123" }
    };

    private static final String[][] USUARIOS_PRESIDENTE = {
            { "presidente", "admin123" },
    };

    private final Scanner scanner;
    private final MotorCriptograficoPort motorConfidencialidad;
    private final MotorCriptograficoPort motorRegistro;
    private final MotorCriptograficoPort motorAnonimato;
    private final ModuloFirmaRSAPSS moduloPSS;
    private final GestorArchivosActaAdapter gestorActaIO;

    // Llaves criptográficas EC (secp256r1) del sistema en general
    private PublicKey llavePublicaSistema;
    private PrivateKey llavePrivadaSistema;

    // Llaves criptográficas EC (secp256r1) del presidente
    private PublicKey llavePublicaPresidente;
    private PrivateKey llavePrivadaPresidente;

    // Llaves criptográficas EC (secp256r1) del juez autenticado
    private PublicKey llavePublicaJuez;
    private PrivateKey llavePrivadaJuez;

    // Llaves criptográficas EC (secp256r1) del pintor autenticado
    private PublicKey llavePublicaPintor;
    private PrivateKey llavePrivadaPintor;

    // Llave simétrica AES derivada por el pintor mediante ECDH con la llave pública del sistema
    private SecretKey claveAESPintor;

    // Última imagen cifrada del pintor en la sesión
    private byte[] ultimaImagenCifrada;
    private byte[] ultimoIV;
    private Path ultimaRutaImagenCifrada;

    public MenuPrincipalConsola(
            MotorCriptograficoPort motorConfidencialidad,
            MotorCriptograficoPort motorRegistro,
            MotorCriptograficoPort motorAnonimato) {

        this.scanner = new Scanner(System.in);
        this.motorConfidencialidad = motorConfidencialidad;
        this.motorRegistro = motorRegistro;
        this.motorAnonimato = motorAnonimato;
        this.moduloPSS = new ModuloFirmaRSAPSS();
        this.gestorActaIO = new GestorArchivosActaAdapter(this.moduloPSS);
    }

    public void iniciar() {

        System.out.println("========================================================");
        System.out.println(" SISTEMA DE CONCURSO DE PINTURA (CORE CRIPTOGRÁFICO)");
        System.out.println("========================================================");

        // Inicializar llaves EC del sistema (cargar si existen o generar si no existen)
        inicializarLlavesSistema();

        boolean salir = false;

        while (!salir) {

            System.out.println("\n--- Menú Principal: Inicio de Sesión Simulado ---");
            System.out.println("1. Iniciar sesión");
            System.out.println("2. Salir");
            System.out.print("Seleccione una opción: ");

            String opcion = scanner.nextLine().trim();

            switch (opcion) {

                case "1":
                    iniciarSesion();
                    break;

                case "3":
                    System.out.println("\nSaliendo del sistema. ");
                    salir = true;
                    break;

                default:
                    System.out.println("\n[!] Opción no válida. Por favor ingrese 1 o 2.");
            }
        }
    }

    // =========================================================
    // INICIALIZACIÓN DE LLAVES EC DEL SISTEMA
    // =========================================================

    /**
     * Inicializa las llaves EC públicas y privadas del sistema en general.
     * Si ya existen en la carpeta "claves_sistema", se cargan sin volver a
     * generarlas.
     * Si no existen, se genera un nuevo par de llaves EC (secp256r1) y se guardan
     * como
     * "pub_sist.txt" y "priv_sist.txt".
     */
    private void inicializarLlavesSistema() {
        Path dirClaves = Paths.get("claves_sistema");
        Path pathPub = dirClaves.resolve("pub_sist.txt");
        Path pathPriv = dirClaves.resolve("priv_sist.txt");

        if (!(motorRegistro instanceof RegistroECDSAPort registroECDSA)) {
            System.out.println(
                    "[!] El motor de registro ECDSA no está disponible para gestionar las llaves del sistema.");
            return;
        }

        try {
            if (Files.exists(pathPub) && Files.exists(pathPriv)) {
                this.llavePublicaSistema = registroECDSA.cargarLlavePublica(pathPub);
                this.llavePrivadaSistema = registroECDSA.cargarLlavePrivada(pathPriv);
                System.out
                        .println("\n[SISTEMA] Llaves criptográficas EC del sistema detectadas en '" + dirClaves + "'.");
                System.out.println("          -> Llave pública cargada: " + pathPub);
                System.out.println("          -> Llave privada cargada: " + pathPriv);
            } else {
                System.out.println("\n[SISTEMA] No se encontraron llaves previas del sistema.");
                System.out.println("[SISTEMA] Generando nuevo par de llaves EC (secp256r1) para el sistema...");
                KeyPair parLlaves = registroECDSA.generarParLlavesECDSA();
                this.llavePublicaSistema = parLlaves.getPublic();
                this.llavePrivadaSistema = parLlaves.getPrivate();

                registroECDSA.guardarLlavePublica(this.llavePublicaSistema, pathPub);
                registroECDSA.guardarLlavePrivada(this.llavePrivadaSistema, pathPriv);

                System.out.println("[SISTEMA] Llaves del sistema generadas y guardadas exitosamente:");
                System.out.println("          -> Llave pública: " + pathPub);
                System.out.println("          -> Llave privada: " + pathPriv);
            }
        } catch (Exception e) {
            System.out.println("[!] Error al gestionar las llaves del sistema: " + e.getMessage());
        }
    }

    public PublicKey getLlavePublicaSistema() {
        return llavePublicaSistema;
    }

    public PrivateKey getLlavePrivadaSistema() {
        return llavePrivadaSistema;
    }

    // =========================================================
    // INICIALIZACIÓN DE LLAVES EC DEL PRESIDENTE
    // =========================================================

    /**
     * Inicializa las llaves EC públicas y privadas del presidente.
     * Si ya existen en la carpeta "claves_usuario/presidente", se cargan sin volver
     * a generarlas.
     * Si no existen, se genera un nuevo par de llaves EC (secp256r1) y se guardan
     * como
     * "pub_presidente.txt" y "priv_presidente.txt".
     */
    public void inicializarLlavesPresidente() {
        Path dirClaves = Paths.get("claves_usuario", "presidente");
        Path pathPub = dirClaves.resolve("pub_presidente.txt");
        Path pathPriv = dirClaves.resolve("priv_presidente.txt");

        if (!(motorRegistro instanceof RegistroECDSAPort registroECDSA)) {
            System.out.println(
                    "[!] El motor de registro ECDSA no está disponible para gestionar las llaves del presidente.");
            return;
        }

        try {
            if (Files.exists(pathPub) && Files.exists(pathPriv)) {
                try {
                    this.llavePublicaPresidente = registroECDSA.cargarLlavePublica(pathPub);
                    this.llavePrivadaPresidente = registroECDSA.cargarLlavePrivada(pathPriv);
                    System.out.println("\n[PRESIDENTE] Llaves criptográficas EC del presidente detectadas en '"
                            + dirClaves + "'.");
                    System.out.println("             -> Llave pública cargada: " + pathPub);
                    System.out.println("             -> Llave privada cargada: " + pathPriv);
                    return;
                } catch (Exception ex) {
                    System.out.println("\n[PRESIDENTE] Las llaves en '" + dirClaves
                            + "' no son de tipo EC válidas o están dañadas: " + ex.getMessage());
                    System.out.println("[PRESIDENTE] Regenerando llaves EC para el presidente...");
                }
            } else {
                System.out.println("\n[PRESIDENTE] No se encontraron llaves previas del presidente.");
                System.out.println("[PRESIDENTE] Generando nuevo par de llaves EC (secp256r1) para el presidente...");
            }

            KeyPair parLlaves = registroECDSA.generarParLlavesECDSA();
            this.llavePublicaPresidente = parLlaves.getPublic();
            this.llavePrivadaPresidente = parLlaves.getPrivate();

            registroECDSA.guardarLlavePublica(this.llavePublicaPresidente, pathPub);
            registroECDSA.guardarLlavePrivada(this.llavePrivadaPresidente, pathPriv);

            System.out.println("[PRESIDENTE] Llaves del presidente generadas y guardadas exitosamente:");
            System.out.println("             -> Llave pública: " + pathPub);
            System.out.println("             -> Llave privada: " + pathPriv);

        } catch (Exception e) {
            System.out.println("[!] Error al gestionar las llaves del presidente: " + e.getMessage());
        }
    }

    public PublicKey getLlavePublicaPresidente() {
        return llavePublicaPresidente;
    }

    public PrivateKey getLlavePrivadaPresidente() {
        return llavePrivadaPresidente;
    }

    // =========================================================
    // INICIALIZACIÓN DE LLAVES EC DEL JUEZ
    // =========================================================

    /**
     * Inicializa las llaves EC públicas y privadas del juez que acaba de ingresar.
     * Se guardan en la carpeta "claves_usuario/jueces/<nombreUsuario>".
     * Si ya existen en dicha carpeta, se cargan sin volver a generarlas.
     * Si no existen, se genera un nuevo par de llaves EC (secp256r1) y se guardan
     * como
     * "pub_<nombreUsuario>.txt" y "priv_<nombreUsuario>.txt".
     */
    public void inicializarLlavesJuez(Usuario juez) {
        if (juez != null) {
            inicializarLlavesJuez(juez.getNombreUsuario());
        }
    }

    public void inicializarLlavesJuez(String nombreUsuario) {
        Path dirClaves = Paths.get("claves_usuario", "jueces", nombreUsuario);
        Path pathPub = dirClaves.resolve("pub_" + nombreUsuario + ".txt");
        Path pathPriv = dirClaves.resolve("priv_" + nombreUsuario + ".txt");

        // Soporte por si ya existían con o sin extensión .txt
        if (!Files.exists(pathPub) && Files.exists(dirClaves.resolve("pub_" + nombreUsuario))) {
            pathPub = dirClaves.resolve("pub_" + nombreUsuario);
        }
        if (!Files.exists(pathPriv) && Files.exists(dirClaves.resolve("priv_" + nombreUsuario))) {
            pathPriv = dirClaves.resolve("priv_" + nombreUsuario);
        }

        if (!(motorRegistro instanceof RegistroECDSAPort registroECDSA)) {
            System.out.println(
                    "[!] El motor de registro ECDSA no está disponible para gestionar las llaves del juez.");
            return;
        }

        try {
            if (Files.exists(pathPub) && Files.exists(pathPriv)) {
                try {
                    this.llavePublicaJuez = registroECDSA.cargarLlavePublica(pathPub);
                    this.llavePrivadaJuez = registroECDSA.cargarLlavePrivada(pathPriv);
                    System.out.println("\n[JUEZ: " + nombreUsuario + "] Llaves criptográficas EC detectadas en '"
                            + dirClaves + "'.");
                    System.out.println("                   -> Llave pública cargada: " + pathPub);
                    System.out.println("                   -> Llave privada cargada: " + pathPriv);
                    return;
                } catch (Exception ex) {
                    System.out.println("\n[JUEZ: " + nombreUsuario + "] Las llaves en '" + dirClaves
                            + "' no son de tipo EC válidas o están dañadas: " + ex.getMessage());
                    System.out.println("[JUEZ: " + nombreUsuario + "] Regenerando llaves EC para el juez...");
                }
            } else {
                System.out.println("\n[JUEZ: " + nombreUsuario + "] No se encontraron llaves previas del juez.");
                System.out.println("[JUEZ: " + nombreUsuario + "] Generando nuevo par de llaves EC (secp256r1) para "
                        + nombreUsuario + "...");
            }

            KeyPair parLlaves = registroECDSA.generarParLlavesECDSA();
            this.llavePublicaJuez = parLlaves.getPublic();
            this.llavePrivadaJuez = parLlaves.getPrivate();

            registroECDSA.guardarLlavePublica(this.llavePublicaJuez, pathPub);
            registroECDSA.guardarLlavePrivada(this.llavePrivadaJuez, pathPriv);

            System.out.println("[JUEZ: " + nombreUsuario + "] Llaves del juez generadas y guardadas exitosamente:");
            System.out.println("                   -> Llave pública: " + pathPub);
            System.out.println("                   -> Llave privada: " + pathPriv);

        } catch (Exception e) {
            System.out.println("[!] Error al gestionar las llaves del juez (" + nombreUsuario + "): " + e.getMessage());
        }
    }

    public PublicKey getLlavePublicaJuez() {
        return llavePublicaJuez;
    }

    public PrivateKey getLlavePrivadaJuez() {
        return llavePrivadaJuez;
    }

    // =========================================================
    // INICIALIZACIÓN DE LLAVES EC DEL PINTOR
    // =========================================================

    /**
     * Inicializa las llaves EC públicas y privadas del pintor que acaba de
     * ingresar.
     * Se guardan en la carpeta "claves_usuario/pintores/<nombreUsuario>".
     * Si dicha carpeta no existe, se crea automáticamente.
     * Si ya existen las llaves en dicha carpeta, se cargan sin volver a generarlas.
     * Si no existen, se genera un nuevo par de llaves EC (secp256r1) y se guardan
     * como
     * "pub_<nombreUsuario>.txt" y "priv_<nombreUsuario>.txt".
     */
    public void inicializarLlavesPintor(Usuario pintor) {
        if (pintor != null) {
            inicializarLlavesPintor(pintor.getNombreUsuario());
        }
    }

    public void inicializarLlavesPintor(String nombreUsuario) {
        Path dirClaves = Paths.get("claves_usuario", "pintores", nombreUsuario);
        Path pathPub = dirClaves.resolve("pub_" + nombreUsuario + ".txt");
        Path pathPriv = dirClaves.resolve("priv_" + nombreUsuario + ".txt");

        // Soporte por si ya existían con o sin extensión .txt
        if (!Files.exists(pathPub) && Files.exists(dirClaves.resolve("pub_" + nombreUsuario))) {
            pathPub = dirClaves.resolve("pub_" + nombreUsuario);
        }
        if (!Files.exists(pathPriv) && Files.exists(dirClaves.resolve("priv_" + nombreUsuario))) {
            pathPriv = dirClaves.resolve("priv_" + nombreUsuario);
        }

        if (!(motorRegistro instanceof RegistroECDSAPort registroECDSA)) {
            System.out.println(
                    "[!] El motor de registro ECDSA no está disponible para gestionar las llaves del pintor.");
            return;
        }

        try {
            if (Files.exists(pathPub) && Files.exists(pathPriv)) {
                try {
                    this.llavePublicaPintor = registroECDSA.cargarLlavePublica(pathPub);
                    this.llavePrivadaPintor = registroECDSA.cargarLlavePrivada(pathPriv);
                    System.out.println("\n[PINTOR: " + nombreUsuario + "] Llaves criptográficas EC detectadas en '"
                            + dirClaves + "'.");
                    System.out.println("                     -> Llave pública cargada: " + pathPub);
                    System.out.println("                     -> Llave privada cargada: " + pathPriv);
                    return;
                } catch (Exception ex) {
                    System.out.println("\n[PINTOR: " + nombreUsuario + "] Las llaves en '" + dirClaves
                            + "' no son de tipo EC válidas o están dañadas: " + ex.getMessage());
                    System.out.println("[PINTOR: " + nombreUsuario + "] Regenerando llaves EC para el pintor...");
                }
            } else {
                System.out.println("\n[PINTOR: " + nombreUsuario + "] No se encontraron llaves previas del pintor.");
                System.out.println("[PINTOR: " + nombreUsuario + "] Generando nuevo par de llaves EC (secp256r1) para "
                        + nombreUsuario + "...");
            }

            // Asegurar que la nueva carpeta exista
            Files.createDirectories(dirClaves);

            KeyPair parLlaves = registroECDSA.generarParLlavesECDSA();
            this.llavePublicaPintor = parLlaves.getPublic();
            this.llavePrivadaPintor = parLlaves.getPrivate();

            registroECDSA.guardarLlavePublica(this.llavePublicaPintor, pathPub);
            registroECDSA.guardarLlavePrivada(this.llavePrivadaPintor, pathPriv);

            System.out.println("[PINTOR: " + nombreUsuario
                    + "] Llaves del pintor generadas y guardadas exitosamente en '" + dirClaves + "':");
            System.out.println("                     -> Llave pública: " + pathPub);
            System.out.println("                     -> Llave privada: " + pathPriv);

        } catch (Exception e) {
            System.out
                    .println("[!] Error al gestionar las llaves del pintor (" + nombreUsuario + "): " + e.getMessage());
        }
    }

    public PublicKey getLlavePublicaPintor() {
        return llavePublicaPintor;
    }

    public PrivateKey getLlavePrivadaPintor() {
        return llavePrivadaPintor;
    }

    public SecretKey getClaveAESPintor() {
        return claveAESPintor;
    }

    // =========================================================
    // GENERACIÓN DE LLAVE SIMÉTRICA AES (ECDH CON SISTEMA)
    // =========================================================

    /**
     * Permite al pintor ingresar la ruta de su llave privada (con ruta base
     * sugerida claves_usuario/pintores/<NombreUsuario> o claves_usuario/pintor/<NombreUsuario>),
     * multiplicarla por la llave pública EC del sistema (claves_sistema/pub_sist.txt)
     * mediante ECDH y generar la llave simétrica AES resultante.
     */
    public SecretKey generarLlaveAESPintor(Usuario pintor) {
        String nombreUsuario = pintor.getNombreUsuario();
        Path dirBase = Paths.get("claves_usuario", "pintores", nombreUsuario);
        if (!Files.exists(dirBase) && Files.exists(Paths.get("claves_usuario", "pintor", nombreUsuario))) {
            dirBase = Paths.get("claves_usuario", "pintor", nombreUsuario);
        }

        String nombreArchivoDefecto = "priv_" + nombreUsuario + ".txt";
        Path pathDefecto = dirBase.resolve(nombreArchivoDefecto);

        System.out.println("\n==============================================================");
        System.out.println(" GENERACIÓN DE LLAVE AES (ACUERDO DE CLAVES ECDH CON EL SISTEMA)");
        System.out.println("==============================================================");
        System.out.println("Pintor autenticado:   " + nombreUsuario);
        System.out.println("Ruta base del pintor: " + dirBase);
        System.out.print("Ingrese la ruta o archivo de su LLAVE PRIVADA (ENTER para '" + pathDefecto + "'): ");

        String entrada = scanner.nextLine().trim();
        Path pathPriv;
        if (entrada.isEmpty()) {
            pathPriv = pathDefecto;
        } else {
            Path p = Paths.get(entrada);
            if (!Files.exists(p) && Files.exists(dirBase.resolve(entrada))) {
                pathPriv = dirBase.resolve(entrada);
            } else {
                pathPriv = p;
            }
        }

        return generarLlaveAESPintor(pintor, pathPriv);
    }

    public SecretKey generarLlaveAESPintor(Usuario pintor, Path pathPrivPintor) {
        String nombreUsuario = pintor.getNombreUsuario();

        if (!Files.exists(pathPrivPintor)) {
            System.out.println("\n[!] No se encontró el archivo de la llave privada del pintor en: " + pathPrivPintor);
            return null;
        }

        if (!(motorRegistro instanceof RegistroECDSAPort registroECDSA)) {
            System.out.println("[!] El motor de registro ECDSA no está disponible para cargar llaves.");
            return null;
        }

        if (!(motorConfidencialidad instanceof ConfidencialidadAESPort moduloAES)) {
            System.out.println("[!] El módulo de confidencialidad AES no está disponible para derivar la clave.");
            return null;
        }

        try {
            // 1. Cargar llave privada del pintor
            PrivateKey privPintor = registroECDSA.cargarLlavePrivada(pathPrivPintor);

            // 2. Cargar llave pública del sistema desde claves_sistema/pub_sist.txt
            Path pathPubSistema = Paths.get("claves_sistema", "pub_sist.txt");
            if (!Files.exists(pathPubSistema)) {
                System.out.println("[!] No se encontró la llave pública del sistema en: " + pathPubSistema);
                return null;
            }
            PublicKey pubSistema = registroECDSA.cargarLlavePublica(pathPubSistema);

            // 3. Multiplicar la llave privada del pintor por la pública del sistema mediante ECDH
            SecretKey claveAES = moduloAES.derivarClaveAES(privPintor, pubSistema);
            this.claveAESPintor = claveAES;

            // 4. Imprimir en consola la llave AES generada (Hexadecimal y Base64)
            String claveBase64 = Base64.getEncoder().encodeToString(claveAES.getEncoded());
            StringBuilder hexString = new StringBuilder();
            for (byte b : claveAES.getEncoded()) {
                hexString.append(String.format("%02X", b));
            }

            System.out.println("\n==============================================================");
            System.out.println(" LLAVE SIMÉTRICA AES GENERADA EXITOSAMENTE (ECDH)");
            System.out.println("==============================================================");
            System.out.println("Pintor:                        " + nombreUsuario);
            System.out.println("Algoritmo derivado:            " + claveAES.getAlgorithm() + " (" + (claveAES.getEncoded().length * 8) + " bits)");
            System.out.println("Llave privada cargada (Pintor): " + pathPrivPintor);
            System.out.println("Llave pública multiplicada:    " + pathPubSistema);
            System.out.println("Operación Criptográfica:       d_pintor * Q_sistema -> Derivación SHA-256");
            System.out.println("--------------------------------------------------------------");
            System.out.println("LLAVE AES (Hexadecimal): " + hexString);
            System.out.println("LLAVE AES (Base64):      " + claveBase64);
            System.out.println("==============================================================\n");

            return claveAES;

        } catch (Exception e) {
            System.out.println("\n[!] Error al generar la llave AES compartida: " + e.getMessage());
            return null;
        }
    }

    // =========================================================
    // CIFRADO DE IMAGEN CON AES-GCM
    // =========================================================

    /**
     * Solicita al pintor la ruta de la imagen ubicada en "imagenes/",
     * y la cifra utilizando el modo AES-GCM con la llave AES previamente calculada.
     */
    public byte[] cifrarImagenPintor(Usuario pintor, SecretKey claveAES) {
        Path dirImagenes = Paths.get("imagenes");
        try {
            if (!Files.exists(dirImagenes)) {
                Files.createDirectories(dirImagenes);
            }
        } catch (Exception ignored) {
        }

        String sugerenciaDefecto = "imagen.png";
        Path pathSugerido = dirImagenes.resolve(sugerenciaDefecto);

        System.out.println("==============================================================");
        System.out.println(" CIFRADO AUTENTICADO DE IMAGEN / OBRA (AES-GCM)");
        System.out.println("==============================================================");
        System.out.println("Directorio base de imágenes: " + dirImagenes);
        System.out.print("Ingrese la ruta o nombre de la imagen (ENTER para '" + pathSugerido + "'): ");

        String entrada = scanner.nextLine().trim();
        Path pathImagen;
        if (entrada.isEmpty()) {
            pathImagen = pathSugerido;
        } else {
            Path p = Paths.get(entrada);
            if (!Files.exists(p) && Files.exists(dirImagenes.resolve(entrada))) {
                pathImagen = dirImagenes.resolve(entrada);
            } else {
                pathImagen = p;
            }
        }

        return cifrarImagenPintor(pintor, claveAES, pathImagen);
    }

    public byte[] cifrarImagenPintor(Usuario pintor, SecretKey claveAES, Path pathImagen) {
        if (!Files.exists(pathImagen)) {
            System.out.println("\n[!] No se encontró el archivo de la imagen en: " + pathImagen);
            return null;
        }

        if (!(motorConfidencialidad instanceof ConfidencialidadAESPort moduloAES)) {
            System.out.println("[!] El mÃ³dulo de confidencialidad AES no estÃ¡ disponible para cifrar.");
            return null;
        }

        try {
            // 1. Leer los bytes de la imagen original
            byte[] bytesImagen = Files.readAllBytes(pathImagen);

            // 2. Generar Vector de InicializaciÃ³n (IV) de 12 bytes (96 bits) para GCM
            byte[] iv = moduloAES.generarIV(12);

            // 3. Cifrar con AES-GCM (cifrado autenticado con tag de 128 bits)
            byte[] datosCifrados = moduloAES.cifrarAES_GCM(bytesImagen, claveAES, iv);

            // 4. Empaquetar IV + Datos Cifrados [IV (12 bytes) + CIFRADO + TAG (16 bytes)]
            byte[] resultadoConIV = new byte[iv.length + datosCifrados.length];
            System.arraycopy(iv, 0, resultadoConIV, 0, iv.length);
            System.arraycopy(datosCifrados, 0, resultadoConIV, iv.length, datosCifrados.length);

            this.ultimaImagenCifrada = resultadoConIV;
            this.ultimoIV = iv;

            // 5. Guardar la imagen cifrada en la carpeta imagenes/ con extensiÃ³n .enc
            String nombreSalida = pathImagen.getFileName().toString() + ".enc";
            Path pathSalida = pathImagen.getParent() != null
                    ? pathImagen.getParent().resolve(nombreSalida)
                    : Paths.get("imagenes", nombreSalida);

            Files.write(pathSalida, resultadoConIV);
            this.ultimaRutaImagenCifrada = pathSalida;

            // 6. Imprimir informaciÃ³n de la imagen cifrada
            String ivHex = bytesToHex(iv);
            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            String muestraCifradaBase64 = Base64.getEncoder().encodeToString(datosCifrados);
            if (muestraCifradaBase64.length() > 64) {
                muestraCifradaBase64 = muestraCifradaBase64.substring(0, 64) + "...";
            }

            // Descifrado de prueba para verificar integridad y tag de autenticaciÃ³n
            byte[] descifradoVerif = moduloAES.descifrarAES_GCM(datosCifrados, claveAES, iv);
            boolean verificacionValida = java.util.Arrays.equals(bytesImagen, descifradoVerif);

            System.out.println("\n==============================================================");
            System.out.println(" IMAGEN CIFRADA CON ÉXITO (AES-GCM - INTEGRANTE 1)");
            System.out.println("==============================================================");
            System.out.println("Pintor emisor:               " + pintor.getNombreUsuario());
            System.out.println("Archivo de imagen original:  " + pathImagen);
            System.out.println("Tamaño imagen original:      " + bytesImagen.length + " bytes");
            System.out.println("Algoritmo de cifrado:        AES/GCM/NoPadding");
            System.out.println("IV generado (12 bytes):      " + ivHex + " (Base64: " + ivBase64 + ")");
            System.out.println("Tag de autenticación:        128 bits");
            System.out.println("Tamaño de payload cifrado:   " + datosCifrados.length + " bytes");
            System.out.println("Muestra cifrada (Base64):    " + muestraCifradaBase64);
            System.out.println("Archivo cifrado exportado:   " + pathSalida + " (total: " + resultadoConIV.length + " bytes)");
            System.out.println("VerificaciÃ³n de Integridad:  " + (verificacionValida ? "VÃLIDA [OK]" : "INVÃLIDA [ERROR]"));
            System.out.println("==============================================================\n");

            return resultadoConIV;

        } catch (Exception e) {
            System.out.println("\n[!] Error durante el cifrado AES-GCM de la imagen: " + e.getMessage());
            return null;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public byte[] getUltimaImagenCifrada() {
        return ultimaImagenCifrada;
    }

    public byte[] getUltimoIV() {
        return ultimoIV;
    }

    public Path getUltimaRutaImagenCifrada() {
        return ultimaRutaImagenCifrada;
    }

    // =========================================================
    // CIFRADO DE IMAGEN CON AES-GCM
    // =========================================================

    /**
     * Solicita al pintor la ruta de la imagen ubicada en "imagenes/",
     * y la cifra utilizando el modo AES-GCM con la llave AES previamente calculada.
     */
    public byte[] cifrarImagenPintor(Usuario pintor, SecretKey claveAES) {
        Path dirImagenes = Paths.get("imagenes");
        try {
            if (!Files.exists(dirImagenes)) {
                Files.createDirectories(dirImagenes);
            }
        } catch (Exception ignored) {
        }

        String sugerenciaDefecto = "imagen.png";
        Path pathSugerido = dirImagenes.resolve(sugerenciaDefecto);

        System.out.println("==============================================================");
        System.out.println(" CIFRADO AUTENTICADO DE IMAGEN / OBRA (AES-GCM)");
        System.out.println("==============================================================");
        System.out.println("Directorio base de imágenes: " + dirImagenes);
        System.out.print("Ingrese la ruta o nombre de la imagen (ENTER para '" + pathSugerido + "'): ");

        String entrada = scanner.nextLine().trim();
        Path pathImagen;
        if (entrada.isEmpty()) {
            pathImagen = pathSugerido;
        } else {
            Path p = Paths.get(entrada);
            if (!Files.exists(p) && Files.exists(dirImagenes.resolve(entrada))) {
                pathImagen = dirImagenes.resolve(entrada);
            } else {
                pathImagen = p;
            }
        }

        return cifrarImagenPintor(pintor, claveAES, pathImagen);
    }

    public byte[] cifrarImagenPintor(Usuario pintor, SecretKey claveAES, Path pathImagen) {
        if (!Files.exists(pathImagen)) {
            System.out.println("\n[!] No se encontró el archivo de la imagen en: " + pathImagen);
            return null;
        }

        if (!(motorConfidencialidad instanceof ConfidencialidadAESPort moduloAES)) {
            System.out.println("[!] El mÃ³dulo de confidencialidad AES no estÃ¡ disponible para cifrar.");
            return null;
        }

        try {
            // 1. Leer los bytes de la imagen original
            byte[] bytesImagen = Files.readAllBytes(pathImagen);

            // 2. Generar Vector de InicializaciÃ³n (IV) de 12 bytes (96 bits) para GCM
            byte[] iv = moduloAES.generarIV(12);

            // 3. Cifrar con AES-GCM (cifrado autenticado con tag de 128 bits)
            byte[] datosCifrados = moduloAES.cifrarAES_GCM(bytesImagen, claveAES, iv);

            // 4. Empaquetar IV + Datos Cifrados [IV (12 bytes) + CIFRADO + TAG (16 bytes)]
            byte[] resultadoConIV = new byte[iv.length + datosCifrados.length];
            System.arraycopy(iv, 0, resultadoConIV, 0, iv.length);
            System.arraycopy(datosCifrados, 0, resultadoConIV, iv.length, datosCifrados.length);

            this.ultimaImagenCifrada = resultadoConIV;
            this.ultimoIV = iv;

            // 5. Guardar la imagen cifrada en la carpeta imagenes/ con extensiÃ³n .enc
            String nombreSalida = pathImagen.getFileName().toString() + ".enc";
            Path pathSalida = pathImagen.getParent() != null
                    ? pathImagen.getParent().resolve(nombreSalida)
                    : Paths.get("imagenes", nombreSalida);

            Files.write(pathSalida, resultadoConIV);
            this.ultimaRutaImagenCifrada = pathSalida;

            // 6. Imprimir informaciÃ³n de la imagen cifrada
            String ivHex = bytesToHex(iv);
            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            String muestraCifradaBase64 = Base64.getEncoder().encodeToString(datosCifrados);
            if (muestraCifradaBase64.length() > 64) {
                muestraCifradaBase64 = muestraCifradaBase64.substring(0, 64) + "...";
            }

            // Descifrado de prueba para verificar integridad y tag de autenticaciÃ³n
            byte[] descifradoVerif = moduloAES.descifrarAES_GCM(datosCifrados, claveAES, iv);
            boolean verificacionValida = java.util.Arrays.equals(bytesImagen, descifradoVerif);

            System.out.println("\n==============================================================");
            System.out.println(" IMAGEN CIFRADA CON ÉXITO (AES-GCM - INTEGRANTE 1)");
            System.out.println("==============================================================");
            System.out.println("Pintor emisor:               " + pintor.getNombreUsuario());
            System.out.println("Archivo de imagen original:  " + pathImagen);
            System.out.println("Tamaño imagen original:      " + bytesImagen.length + " bytes");
            System.out.println("Algoritmo de cifrado:        AES/GCM/NoPadding");
            System.out.println("IV generado (12 bytes):      " + ivHex + " (Base64: " + ivBase64 + ")");
            System.out.println("Tag de autenticación:        128 bits");
            System.out.println("Tamaño de payload cifrado:   " + datosCifrados.length + " bytes");
            System.out.println("Muestra cifrada (Base64):    " + muestraCifradaBase64);
            System.out.println("Archivo cifrado exportado:   " + pathSalida + " (total: " + resultadoConIV.length + " bytes)");
            System.out.println("VerificaciÃ³n de Integridad:  " + (verificacionValida ? "VÃLIDA âœ“" : "INVÃLIDA âœ—"));
            System.out.println("==============================================================\n");

            return resultadoConIV;

        } catch (Exception e) {
            System.out.println("\n[!] Error durante el cifrado AES-GCM de la imagen: " + e.getMessage());
            return null;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public byte[] getUltimaImagenCifrada() {
        return ultimaImagenCifrada;
    }

    public byte[] getUltimoIV() {
        return ultimoIV;
    }

    public Path getUltimaRutaImagenCifrada() {
        return ultimaRutaImagenCifrada;
    }

    // =========================================================
    // INICIO DE SESIÓN SIMULADO Y ASIGNACIÓN DE ROL
    // =========================================================

    private void iniciarSesion() {

        System.out.println("\n--- Simulación de LogIn ---");
        System.out.print("Ingrese su nombre de usuario: ");
        String nombre = scanner.nextLine().trim();

        if (nombre.isEmpty()) {
            System.out.println("[!] El nombre de usuario no puede estar vacío.");
            return;
        }

        System.out.print("Ingrese su contraseña: ");
        String contrasena = scanner.nextLine().trim();

        // 1. Verificar si el usuario está en el arreglo de JUEZ
        for (String[] juez : USUARIOS_JUEZ) {
            if (juez[0].equalsIgnoreCase(nombre)) {
                if (juez[1].equals(contrasena)) {
                    Usuario usuarioJuez = new Usuario(
                            UUID.randomUUID().toString(),
                            juez[0],
                            RolUsuario.JUEZ);

                    System.out.println("\n>> [AUTORIDAD DETECTADA] Acceso concedido como JUEZ.");
                    System.out.println(">> Sesión iniciada con éxito como: "
                            + usuarioJuez.getNombreUsuario()
                            + " (Rol: " + usuarioJuez.getRol() + ")");

                    menuJuez(usuarioJuez);
                } else {
                    System.out.println("\n[!] Contraseña incorrecta para el usuario JUEZ: " + nombre);
                }
                return;
            }
        }

        // 2. Verificar si el usuario está en el arreglo de PRESIDENTE
        for (String[] presi : USUARIOS_PRESIDENTE) {
            if (presi[0].equalsIgnoreCase(nombre)) {
                if (presi[1].equals(contrasena)) {
                    Usuario usuarioPresidente = new Usuario(
                            UUID.randomUUID().toString(),
                            presi[0],
                            RolUsuario.PRESIDENTE);

                    System.out.println("\n>> [AUTORIDAD DETECTADA] Acceso concedido como PRESIDENTE.");
                    System.out.println(">> Sesión iniciada con éxito como: "
                            + usuarioPresidente.getNombreUsuario()
                            + " (Rol: " + usuarioPresidente.getRol() + ")");

                    menuPresidente(usuarioPresidente);
                } else {
                    System.out.println("\n[!] Contraseña incorrecta para el usuario PRESIDENTE: " + nombre);
                }
                return;
            }
        }

        // 3. Si no está en ninguno de los arreglos se considerará que es un pintor
        Usuario pintor = new Usuario(
                UUID.randomUUID().toString(),
                nombre,
                RolUsuario.PINTOR);

        System.out.println("\n>> Usuario no encontrado en los registros de JUEZ ni PRESIDENTE.");
        System.out.println(">> Se le ha asignado automáticamente el rol: PINTOR");
        System.out.println(">> Sesión iniciada con éxito como: "
                + pintor.getNombreUsuario()
                + " (Rol: " + pintor.getRol() + ")");

        menuPintor(pintor);
    }

    // =========================================================
    // MENU DEL PINTOR
    // =========================================================

    private void menuPintor(Usuario pintor) {

        // Inicializar llaves EC del pintor que acaba de ingresar
        inicializarLlavesPintor(pintor);

        boolean regresar = false;

        while (!regresar) {

            System.out.println(
                    "\n--- Panel del Pintor ("
                            + pintor.getNombreUsuario() + ") ---");

            System.out.println("1. Registrar y proteger obra (Generar llave AES con el Sistema - ECDH)");
            System.out.println("2. Demostración de autenticidad ECDSA de obra");
            System.out.println("3. Consultar mis obras registradas");
            System.out.println("4. Regresar al menú de inicio");
            System.out.print("Seleccione una opción: ");

            String op = scanner.nextLine().trim();

            switch (op) {

                case "1":
                    // Generar llave simétrica AES compartida con el sistema mediante ECDH
                    SecretKey claveAES = generarLlaveAESPintor(pintor);
                    if (claveAES != null) {
                        cifrarImagenPintor(pintor, claveAES);
                    }
                    break;

                case "2":
                    demostrarRegistroECDSA(pintor);
                    break;

                case "3":
                    System.out.println(
                            "\n[Simulación]: No hay obras registradas en memoria en este momento.");
                    break;

                case "4":
                    regresar = true;
                    break;

                default:
                    System.out.println("\n[!] Opción no válida.");
            }
        }
    }

    // =========================================================
    // INTEGRANTE 2 - DEMOSTRACION REAL DE ECDSA
    // =========================================================

    /**
     * Demuestra la generacion de llaves, firma digital
     * y verificacion de un registro de obra.
     *
     * Esta demostracion no cifra ni almacena archivos.
     * Los modulos AES y RSA se integraran posteriormente.
     */
    private void demostrarRegistroECDSA(Usuario pintor) {

        System.out.println(
                "\n[Integración parcial]: Demostración real de autenticidad ECDSA.");

        System.out.println(
                "- Módulo AES: "
                        + (motorConfidencialidad != null
                                ? "Configurado; su cifrado no se ejecuta en esta demostración."
                                : "No configurado."));

        System.out.println(
                "- Módulo RSA: "
                        + (motorAnonimato != null
                                ? "Configurado; su firma ciega no se ejecuta en esta demostración."
                                : "No configurado."));

        // Comprobar disponibilidad del puerto ECDSA.
        if (!(motorRegistro instanceof RegistroECDSAPort registroECDSA)) {

            System.out.println(
                    "[!] El puerto de autenticidad ECDSA no está configurado.");

            return;
        }

        // 1. Solicitar los datos del registro.
        System.out.print(
                "Ingrese el título de la obra para la prueba: ");

        String titulo = scanner.nextLine().trim();

        if (titulo.isEmpty()) {

            System.out.println(
                    "[!] Debe indicar el título de la obra.");

            return;
        }

        // Crear un registro de prueba unico.
        String registro = "PINTOR:" + pintor.getNombreUsuario()
                + "|OBRA:" + titulo
                + "|ID_REGISTRO:" + UUID.randomUUID();

        byte[] datos = registro.getBytes(
                StandardCharsets.UTF_8);

        try {

            // 2. Generar par de llaves ECDSA.
            // Usar llaves EC del pintor cargadas de claves_usuario/pintores
            KeyPair llaves;
            if (this.llavePrivadaPintor != null && this.llavePublicaPintor != null) {
                llaves = new KeyPair(this.llavePublicaPintor, this.llavePrivadaPintor);
            } else {
                llaves = registroECDSA.generarParLlavesECDSA();
            }

            // 3. Firmar con la llave privada.
            byte[] firma = registroECDSA.firmar(
                    datos,
                    llaves.getPrivate());

            // 4. Verificar con la llave publica.
            boolean valida = registroECDSA.verificarFirmaECDSA(
                    datos,
                    firma,
                    llaves.getPublic());

            // 5. Alterar una copia del registro.
            byte[] datosAlterados = datos.clone();

            datosAlterados[0] ^= 0x01;

            // 6. Verificar el registro modificado.
            boolean validaAlterada = registroECDSA.verificarFirmaECDSA(
                    datosAlterados,
                    firma,
                    llaves.getPublic());

            // 7. Mostrar resultados.
            System.out.println(
                    "\n--- Resultado de autenticidad ECDSA ---");

            System.out.println(
                    "Curva: secp256r1 | Firma: SHA256withECDSA");

            System.out.println(
                    "Registro original: " + registro);

            System.out.println(
                    "Firma digital generada: "
                            + firma.length + " bytes");

            System.out.println(
                    "Verificación del registro original: "
                            + valida);

            System.out.println(
                    "Verificación del registro alterado: "
                            + validaAlterada);

            if (valida && !validaAlterada) {

                System.out.println(
                        "[OK] Prueba ECDSA completada correctamente.");

            } else {

                System.out.println(
                        "[!] La prueba ECDSA no produjo los resultados esperados.");
            }

            System.out.println(
                    "[Aviso] Esta prueba no cifra ni guarda la obra o las llaves.");

        } catch (RuntimeException e) {

            System.out.println(
                    "[!] No fue posible ejecutar ECDSA: "
                            + e.getMessage());
        }
    }

    // =========================================================
    // MENU DEL JUEZ (SIN MODIFICACIONES FUNCIONALES)
    // =========================================================

    private void menuJuez(Usuario juez) {

        // Inicializar llaves EC del juez que acaba de ingresar
        inicializarLlavesJuez(juez);

        boolean regresar = false;

        while (!regresar) {

            System.out.println(
                    "\n--- Panel del Juez ("
                            + juez.getNombreUsuario() + ") ---");

            System.out.println("1. Validar firma ciega de obra anónima");
            System.out.println("2. Calificar obra");
            System.out.println("3. Regresar al menú de inicio");
            System.out.print("Seleccione una opción: ");

            String op = scanner.nextLine().trim();

            switch (op) {

                case "1":
                    System.out.println(
                            "\n[Simulación]: Verificación con ModuloAnonimatoRSA...");
                    break;

                case "3":
                    System.out.println(
                            "\n[Simulación]: Asignación de puntaje a obra anónima...");
                    break;

                case "4":
                    regresar = true;
                    break;

                default:
                    System.out.println("\n[!] Opción no válida.");
            }
        }
    }

    // =========================================================
    // MENU DEL PRESIDENTE (SIN MODIFICACIONES FUNCIONALES)
    // =========================================================

    private void menuPresidente(Usuario presidente) {

        // Inicializar llaves EC del presidente (cargar existentes o generar nuevas)
        inicializarLlavesPresidente();

        boolean regresar = false;

        while (!regresar) {

            System.out.println(
                    "\n--- Panel del Presidente ("
                            + presidente.getNombreUsuario() + ") ---");

            System.out.println("1. Realizar firma ciega de los votos (Simulación RSA)");
            System.out.println("2. Emitir y firmar Acta de Resultados (RSASSA-PSS - FIPS 186-5)");
            System.out.println("3. Verificar firma de un Acta de Resultados existente");
            System.out.println("4. Regresar al menú de inicio");
            System.out.print("Seleccione una opción: ");

            String op = scanner.nextLine().trim();

            switch (op) {

                case "1":
                    System.out.println(
                            "\n[Simulación]: Realizar firma ciega.");
                    simulacionPresidente();
                    break;

                case "2":
                    emitirYFirmarActaResultados(presidente);
                    break;

                case "3":
                    verificarFirmaActaExistente();
                    break;

                case "4":
                    regresar = true;
                    break;

                default:
                    System.out.println("\n[!] Opción no válida.");
            }
        }
    }

    private void emitirYFirmarActaResultados(Usuario presidente) {
        System.out.println("\n==============================================================");
        System.out.println(" EMISIÓN Y FIRMA DE ACTA DE RESULTADOS (RSASSA-PSS - FIPS 186-5)");
        System.out.println("==============================================================");

        try {
            // 1. Gestión de Llaves: Cargar existentes o generar nuevas
            PublicKey pubKey = null;
            PrivateKey privKey = null;

            System.out.println("1. Cargar llaves existentes desde archivos de texto (.txt)");
            System.out.println("2. Generar un nuevo par de llaves (3072 bits - Bouncy Castle)");
            System.out.print("Seleccione una opción (1 o 2, ENTER para 1 si existen): ");
            String opcionLlave = scanner.nextLine().trim();

            if ("1".equals(opcionLlave) || opcionLlave.isEmpty()) {
                System.out.print(
                        "Ingrese la ruta de la LLAVE PRIVADA : ");
                String rutaPriv = scanner.nextLine().trim();
                if (rutaPriv.isEmpty()) {
                    if (Files.exists(Paths.get("priv_presidente.txt"))) {
                        rutaPriv = "priv_presidente.txt";
                    } else {
                        rutaPriv = "clave_privada_presidente.txt";
                    }
                }

                System.out.print(
                        "Ingrese la ruta de la LLAVE PÚBLICA : ");
                String rutaPub = scanner.nextLine().trim();
                if (rutaPub.isEmpty()) {
                    if (Files.exists(Paths.get("pub_presidente.txt"))) {
                        rutaPub = "pub_presidente.txt";
                    } else {
                        rutaPub = "clave_publica_presidente.txt";
                    }
                }

                if (Files.exists(Paths.get(rutaPriv)) && Files.exists(Paths.get(rutaPub))) {
                    try {
                        privKey = gestorActaIO.cargarLlavePrivadaBase64(rutaPriv);
                        pubKey = gestorActaIO.cargarLlavePublicaBase64(rutaPub);
                        System.out.println(" Llave privada cargada de: " + rutaPriv);
                        System.out.println("  Llave pública cargada de: " + rutaPub);
                    } catch (Exception ex) {
                        System.out.println("  [!] Error al cargar las llaves: " + ex.getMessage());
                    }
                } else {
                    System.out.println("  [!] No se encontraron los archivos especificados.");
                }
            }

            // Si no se cargaron llaves existentes, generar un par nuevo
            if (privKey == null || pubKey == null) {
                System.out.println("\nGenerando nuevo par de llaves RSA-PSS de 3072 bits con Bouncy Castle...");
                KeyPair parLlaves = moduloPSS.generarParLlaves();
                pubKey = parLlaves.getPublic();
                privKey = parLlaves.getPrivate();

                RSAPublicKey rsaPub = (RSAPublicKey) pubKey;
                System.out.println(
                        "  Algoritmo: " + rsaPub.getAlgorithm() + " (" + rsaPub.getModulus().bitLength() + " bits)");
                System.out.println("  Exponente Público e: " + rsaPub.getPublicExponent());

                System.out.println("\nExportación de llaves en Base64 a archivos de texto:");
                System.out.print("Ingrese el nombre/ruta para la LLAVE PÚBLICA : ");
                String rutaPub = scanner.nextLine().trim();
                if (rutaPub.isEmpty()) {
                    rutaPub = "pub_presidente.txt";
                }

                System.out.print("Ingrese el nombre/ruta para la LLAVE PRIVADA : ");
                String rutaPriv = scanner.nextLine().trim();
                if (rutaPriv.isEmpty()) {
                    rutaPriv = "priv_presidente.txt";
                }

                gestorActaIO.guardarParLlavesBase64(parLlaves, rutaPub, rutaPriv);
                System.out.println("  Llave pública exportada exitosamente a: " + rutaPub);
                System.out.println("  Llave privada exportada exitosamente a: " + rutaPriv);
            }

            // 2. Documento del Acta de Resultados en texto plano
            System.out.println("\nDocumento del Acta de Resultados:");
            System.out.print(
                    "Ingrese la ruta del archivo de texto del acta : ");
            String rutaActa = scanner.nextLine().trim();
            if (rutaActa.isEmpty()) {
                rutaActa = "acta_resultados_oficial.txt";
            }

            if (!Files.exists(Paths.get(rutaActa))) {
                String plantillaActa = "====================================================\n"
                        + " ACTA OFICIAL DE RESULTADOS - CONCURSO DE PINTURA 2026\n"
                        + " EMISOR: Presidente (" + presidente.getNombreUsuario() + ")\n"
                        + "====================================================\n"
                        + "1er Lugar: 'Amanecer en el Valle' - Promedio: 3★\n"
                        + "2do Lugar: 'Sombras de Otoño'     - Promedio: 2★\n"
                        + "3er Lugar: 'Horizonte Azul'      - Promedio: 1★\n\n"
                        + "Certificación oficial: Se declaran los resultados válidos, inalterables\n"
                        + "y respaldados bajo el esquema de firma digital FIPS 186-5.\n"
                        + "====================================================\n";
                Files.writeString(Paths.get(rutaActa), plantillaActa, StandardCharsets.UTF_8);
                System.out.println("  Archivo de texto plano generado: " + rutaActa);
            } else {
                System.out.println("  Archivo de acta detectado y cargado: " + rutaActa);
            }

            String rutaFirma = "firma_acta_presidente.txt";
            String firmaAnteriorBase64 = null;
            if (Files.exists(Paths.get(rutaFirma))) {
                try {
                    firmaAnteriorBase64 = Files.readString(Paths.get(rutaFirma), StandardCharsets.UTF_8).trim();
                } catch (Exception ignored) {
                }
            }

            System.out.println("\n Firmando documento con ModuloFirmaRSAPSS (usando la clave privada)...");
            String nuevaFirmaBase64 = gestorActaIO.firmarActaYRetornarBase64(rutaActa, privKey);

            Files.writeString(Paths.get(rutaFirma), nuevaFirmaBase64, StandardCharsets.UTF_8);

            System.out.println("\n==============================================================");
            System.out.println(" SALIDA CRIPTOGRÁFICA - FIRMA DIGITAL RSASSA-PSS (FIPS 186-5)");
            System.out.println("==============================================================");
            System.out.println("Documento firmado: " + rutaActa);
            System.out.println("Emisor oficial: PRESIDENTE (" + presidente.getNombreUsuario() + ")");
            System.out.println("Algoritmo de firma: " + ModuloFirmaRSAPSS.ALGORITMO_FIRMA);
            System.out.println("Proveedor: " + ModuloFirmaRSAPSS.PROVEEDOR_BC + " (Bouncy Castle)");
            System.out.println("Función Hash: " + ModuloFirmaRSAPSS.HASH_ALGORITMO);
            System.out.println("Función MGF: " + ModuloFirmaRSAPSS.MGF_ALGORITMO + " con SHA-256");
            System.out.println("Longitud de Salt (sLen): " + ModuloFirmaRSAPSS.LONGITUD_SALT_BYTES + " bytes");
            System.out.println("Archivo de firma guardado en: " + rutaFirma);
            System.out.println("\nFirma Digital Generada (Base64):\n" + nuevaFirmaBase64);
            System.out.println("==============================================================");

            if (firmaAnteriorBase64 != null && opcionLlave.equals("1")) {
                System.out.println("\n--- Comparacion entre firmas  ---");
                System.out.println("Firma anterior (primeros 60 caracteres):  "
                        + firmaAnteriorBase64.substring(0, Math.min(60, firmaAnteriorBase64.length())) + "...");
                System.out.println("Nueva firma generada (primeros 60 chars): "
                        + nuevaFirmaBase64.substring(0, Math.min(60, nuevaFirmaBase64.length())) + "...");
            }

            boolean esValida = gestorActaIO.verificarFirmaActa(rutaActa, nuevaFirmaBase64, pubKey);
            System.out.println("\n Verificación de la firma generada: "
                    + (esValida ? "VÁLIDA " : "INVÁLIDA "));

            System.out.print("\n¿Desea probar la detección de fraude simulando una alteración al acta? (s/n): ");
            String probar = scanner.nextLine().trim();
            if (probar.equalsIgnoreCase("s")) {
                byte[] contenidoOriginal = Files.readAllBytes(Paths.get(rutaActa));
                byte[] contenidoAlterado = contenidoOriginal.clone();
                contenidoAlterado[contenidoAlterado.length - 1] ^= 0x01;
                Path pathAlterado = Paths.get("acta_temporal_alterada.txt");
                Files.write(pathAlterado, contenidoAlterado);

                boolean verificacionAlterada = gestorActaIO.verificarFirmaActa(
                        pathAlterado.toString(), nuevaFirmaBase64, pubKey);
                Files.deleteIfExists(pathAlterado);

                System.out.println("Resultado de verificación con documento alterado: " + verificacionAlterada);
                if (!verificacionAlterada) {
                    System.out
                            .println("RSASSA-PSS detectó la modificación y rechazó la firma.");
                }
            }

        } catch (Exception e) {
            System.out.println("[!] Ocurrió un error al emitir el acta: " + e.getMessage());
        }
    }

    /**
     * Permite verificar la firma digital de un Acta de Resultados existente
     * utilizando su documento en texto plano, archivo de firma y llave pública.
     */
    private void verificarFirmaActaExistente() {
        System.out.println("\n==============================================================");
        System.out.println(" VERIFICACIÓN DE FIRMA DIGITAL DE ACTA (RSASSA-PSS)");
        System.out.println("==============================================================");

        try {
            System.out
                    .print("Ingrese ruta del documento de texto del acta (ENTER para 'acta_resultados_oficial.txt'): ");
            String rutaActa = scanner.nextLine().trim();
            if (rutaActa.isEmpty()) {
                rutaActa = "acta_resultados_oficial.txt";
            }

            System.out.print(
                    "Ingrese ruta del archivo con la firma en Base64 (ENTER para 'firma_acta_presidente.txt'): ");
            String rutaFirma = scanner.nextLine().trim();
            if (rutaFirma.isEmpty()) {
                rutaFirma = "firma_acta_presidente.txt";
            }

            System.out.print(
                    "Ingrese ruta del archivo de la llave pública (ENTER para 'clave_publica_presidente.txt'): ");
            String rutaPub = scanner.nextLine().trim();
            if (rutaPub.isEmpty()) {
                rutaPub = "clave_publica_presidente.txt";
            }

            if (!Files.exists(Paths.get(rutaActa))) {
                System.out.println("[!] El archivo del acta no existe: " + rutaActa);
                return;
            }
            if (!Files.exists(Paths.get(rutaFirma))) {
                System.out.println("[!] El archivo de firma no existe: " + rutaFirma);
                return;
            }
            if (!Files.exists(Paths.get(rutaPub))) {
                System.out.println("[!] El archivo de clave pública no existe: " + rutaPub);
                return;
            }

            PublicKey pubKey = gestorActaIO.cargarLlavePublicaBase64(rutaPub);
            String firmaBase64 = Files.readString(Paths.get(rutaFirma), StandardCharsets.UTF_8).trim();

            boolean valida = gestorActaIO.verificarFirmaActa(rutaActa, firmaBase64, pubKey);

            System.out.println("\n--- RESULTADO DE LA VERIFICACIÓN ---");
            System.out.println("Documento: " + rutaActa);
            System.out.println("Clave pública: " + rutaPub);
            if (valida) {
                System.out.println(">> ESTADO: [FIRMA DIGITAL VÁLIDA] ✓");
                System.out.println(
                        "El documento es auténtico, fue firmado por el Presidente y no ha sufrido alteraciones.");
            } else {
                System.out.println(">> ESTADO: [!] FIRMA INVÁLIDA O DOCUMENTO MODIFICADO ✗");
            }

        } catch (Exception e) {
            System.out.println("[!] Error en la verificación: " + e.getMessage());
        }
    }

    private void simulacionPresidente() {
        try {
            System.out.println("========== INICIANDO LA SIMULACION ==========");
            ModuloAnonimatoRSA modulo = new ModuloAnonimatoRSA();

            System.out.println("(SISTEMA) Generacion de llaves TSA con 3072 para presidente");
            KeyPair llavesPresidente = modulo.generarParLlavesRSA();
            RSAPublicKey llavePublica = (RSAPublicKey) llavesPresidente.getPublic();
            RSAPrivateKey llavePrivada = (RSAPrivateKey) llavesPresidente.getPrivate();

            int[] votosDejueces = { 2, 1, 3 };
            String[] comentariosDejueces = { "Fue un buen trabajo pero le falta trabajar mas las sombras",
                    "Le falta mucha tecnica por conocer", "De los mejores trabajos que he visto"
            };
            byte[][] votoByte = new byte[3][];

            for (int i = 0; i < votosDejueces.length; i++) {
                int numerojuez = i + 1;
                int voto = votosDejueces[i];
                String comentario = comentariosDejueces[i];
                String paqueteVoto = "ESTRELLAS:" + voto + "|COMENTARIO:" + comentario;
                votoByte[i] = paqueteVoto.getBytes(StandardCharsets.UTF_8);

                BigInteger factorCegado = modulo.generarFactorCegado(llavePublica);
                byte[] votoCegado = modulo.cegarMensaje(votoByte[i], factorCegado, llavePublica);
                byte[] firmaCegada = modulo.firmarCegadoRSA(votoCegado, llavePrivada);

                byte[] firmaReal = modulo.descegarFirmaRSA(firmaCegada, factorCegado, llavePublica);
                System.out.println("(SISTEMA) Exportando el archivo ");
                String rutaArchivo = "firma_voto_juez_" + numerojuez + ".txt";
                String firmaBase64 = Base64.getEncoder().encodeToString(firmaReal);
                Files.writeString(Paths.get(rutaArchivo), firmaBase64);

            }

            System.out.println("===== Verificacion de archivos ===== ");
            this.scanner.nextLine();
            for (int i = 0; i < votosDejueces.length; i++) {
                int numerojuez = i + 1;
                String rutaArchivo = "firma_voto_juez_" + numerojuez + ".txt";
                try {
                    String firmaLeidaBase64 = Files.readString(Paths.get(rutaArchivo));
                    byte[] firmaParaVerificar = Base64.getDecoder().decode(firmaLeidaBase64);
                    boolean esValido = modulo.verificarFirmaRSA(votoByte[i], firmaParaVerificar, llavePublica);
                    if (esValido)
                        System.out.println("Firma del juez " + numerojuez + " valida");
                    else
                        System.out.println("Firma del juez " + numerojuez + "  NO valida");
                } catch (Exception e) {
                    System.out.println("Firma ilegible");
                }
            }

        } catch (Exception e) {
            System.out.println("Ocurrio un error en la simulacion ");
        }
    }
}
