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
import java.security.MessageDigest;
import java.nio.file.Path;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Collections;

import com.paintingcompetition.domain.ports.out.RegistroECDSAPort;
import com.paintingcompetition.domain.ports.out.ConfidencialidadAESPort;
import javax.crypto.SecretKey;
import java.awt.image.BufferedImage;
import java.awt.Graphics2D;
import java.awt.Color;
import java.awt.Font;
import java.awt.BasicStroke;
import java.awt.Desktop;
import java.awt.GraphicsEnvironment;
import javax.imageio.ImageIO;

public class MenuPrincipalConsola {

    // =========================================================
    // ARREGLOS DE CREDENCIALES SIMULADAS [Nombre de Usuario, Contraseña]
    // =========================================================
    private static final String[][] USUARIOS_JUEZ = {
            { "juez1", "1234" },
            { "juez2", "juez2026" },
            { "juez3", "juezPass" },
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

    // Llaves RSA (3072 bits) del presidente para la firma ciega de Chaum
    // (ModuloAnonimatoRSA)
    private RSAPublicKey llavePublicaRSAPresidente;
    private RSAPrivateKey llavePrivadaRSAPresidente;

    // Llaves criptográficas EC (secp256r1) del juez autenticado
    private PublicKey llavePublicaJuez;
    private PrivateKey llavePrivadaJuez;
    private Usuario juezAutenticado;

    // Llaves criptográficas EC (secp256r1) del pintor autenticado
    private PublicKey llavePublicaPintor;
    private PrivateKey llavePrivadaPintor;

    // Llave simétrica AES derivada por el pintor mediante ECDH con la llave pública
    // del sistema
    private SecretKey claveAESPintor;

    // Última imagen cifrada del pintor en la sesión
    private byte[] ultimaImagenCifrada;
    private byte[] ultimoIV;
    private Path ultimaRutaImagenCifrada;

    // Última firma digital ECDSA y hash de la obra cifrada
    private byte[] ultimoHashObraCifrada;
    private byte[] ultimaFirmaDigitalPintor;
    private Path ultimaRutaFirmaPintor;

    // Llave simétrica AES recuperada por el sistema para una obra verificada
    private SecretKey ultimaClaveAESRecuperada;

    // Última imagen descifrada por el juez/sistema
    private Path ultimaRutaImagenDescifrada;

    // Última acta de calificación y veredicto emitido por un juez
    private Path ultimaRutaActaCalificacion;
    private int ultimoVeredictoEstrellas;
    private String ultimoVeredictoComentario;

    // Cegado de voto/calificación con ModuloAnonimatoRSA
    private byte[] ultimoVotoCegado;
    private BigInteger ultimoFactorCegado;
    private Path ultimaRutaVotoCegado;
    private Map<String, BigInteger> factoresCegado = new LinkedHashMap<>();

    // Última firma ciega emitida por el presidente sobre un voto
    private Path ultimaRutaFirmaCegadaPresidente;

    // Última firma descegada por el juez
    private byte[] ultimaFirmaDescegada;
    private Path ultimaRutaFirmaDescegada;

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
            System.out.println("2. Mostrar resultados");
            System.out.println("3. Salir");
            System.out.print("Seleccione una opción: ");

            String opcion = scanner.nextLine().trim();

            switch (opcion) {

                case "1":
                    iniciarSesion();
                    break;

                case "2":
                    mostrarResultadosConcurso();
                    break;

                case "3":
                    System.out.println("\nSaliendo del sistema. Hasta pronto.");
                    salir = true;
                    break;

                default:
                    System.out.println("\n[!] Opción no válida. Por favor ingrese 1, 2 o 3.");
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
     * como "pub_sist.txt" y "priv_sist.txt".
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
     * como "pub_presidente.txt" y "priv_presidente.txt".
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
    // INICIALIZACIÓN DE LLAVES RSA (FIRMA CIEGA CHAUM) DEL PRESIDENTE
    // =========================================================

    /**
     * Genera e inicializa las llaves RSA exclusivas para el presidente utilizando
     * ModuloAnonimatoRSA.
     * Solo el presidente genera estas llaves y se guardan en
     * "claves_usuario/presidente"
     * con los nombres "nombrePresidente_RSA_pub.txt" y
     * "nombrePresidente_RSA_priv.txt".
     *
     * @param presidente Usuario presidente autenticado
     * @return Par de llaves RSA del presidente
     */
    public KeyPair inicializarOGenerarLlavesRSAPresidente(Usuario presidente) {
        String nombrePresidente = (presidente != null && presidente.getNombreUsuario() != null)
                ? presidente.getNombreUsuario()
                : "presidente";

        if (!(motorAnonimato instanceof ModuloAnonimatoRSA moduloRSA)) {
            System.out.println("[!] El módulo de anonimato RSA no está disponible para gestionar las llaves.");
            return null;
        }

        Path dirPresidente = Paths.get("claves_usuario", "presidente");
        Path pathPub = dirPresidente.resolve(nombrePresidente + "_RSA_pub.txt");
        Path pathPriv = dirPresidente.resolve(nombrePresidente + "_RSA_priv.txt");

        try {
            Files.createDirectories(dirPresidente);

            if (Files.exists(pathPub) && Files.exists(pathPriv)) {
                try {
                    this.llavePublicaRSAPresidente = moduloRSA.cargarLlavePublica(pathPub);
                    this.llavePrivadaRSAPresidente = moduloRSA.cargarLlavePrivada(pathPriv);

                    System.out.println("\n[PRESIDENTE] Llaves RSA (Firma Ciega de Chaum) detectadas en '"
                            + dirPresidente + "':");
                    System.out.println("             -> Llave pública cargada: " + pathPub);
                    System.out.println("             -> Llave privada cargada: " + pathPriv);

                    return new KeyPair(this.llavePublicaRSAPresidente, this.llavePrivadaRSAPresidente);
                } catch (Exception ex) {
                    System.out.println("\n[PRESIDENTE] Las llaves RSA existentes están dañadas: " + ex.getMessage());
                    System.out.println("[PRESIDENTE] Regenerando llaves RSA para el presidente...");
                }
            } else {
                System.out.println("\n[PRESIDENTE] No se encontraron llaves RSA previas para la firma ciega.");
                System.out.println(
                        "[PRESIDENTE] Generando nuevo par de llaves RSA (3072 bits) con ModuloAnonimatoRSA...");
            }

            KeyPair parRSA = moduloRSA.generarParLlavesRSA();
            this.llavePublicaRSAPresidente = (RSAPublicKey) parRSA.getPublic();
            this.llavePrivadaRSAPresidente = (RSAPrivateKey) parRSA.getPrivate();

            moduloRSA.guardarParLlavesRSA(parRSA, pathPub, pathPriv);

            System.out.println("==============================================================");
            System.out.println(" LLAVES RSA GENERADAS PARA EL PRESIDENTE (FIRMA CIEGA CHAUM)");
            System.out.println("==============================================================");
            System.out.println("Presidente:                  " + nombrePresidente);
            System.out.println("Algoritmo:                   RSA (3072 bits)");
            System.out.println("Módulo Criptográfico:        ModuloAnonimatoRSA");
            System.out.println("Directorio de guardado:      " + dirPresidente);
            System.out.println("Llave pública guardada:      " + pathPub.getFileName() + " (" + pathPub + ")");
            System.out.println("Llave privada guardada:      " + pathPriv.getFileName() + " (" + pathPriv + ")");
            System.out.println("==============================================================\n");

            return parRSA;

        } catch (Exception e) {
            System.out.println("\n[!] Error al generar/guardar las llaves RSA del presidente: " + e.getMessage());
            return null;
        }
    }

    public RSAPublicKey getLlavePublicaRSAPresidente() {
        return llavePublicaRSAPresidente;
    }

    public RSAPrivateKey getLlavePrivadaRSAPresidente() {
        return llavePrivadaRSAPresidente;
    }

    // =========================================================
    // INICIALIZACIÓN DE LLAVES EC DEL JUEZ
    // =========================================================

    /**
     * Inicializa las llaves EC públicas y privadas del juez que acaba de ingresar.
     * Se guardan en la carpeta "claves_usuario/jueces/<nombreUsuario>".
     * Si ya existen en dicha carpeta, se cargan sin volver a generarlas.
     * Si no existen, se genera un nuevo par de llaves EC (secp256r1) y se guardan
     * como "pub_<nombreUsuario>.txt" y "priv_<nombreUsuario>.txt".
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
     * como "pub_<nombreUsuario>.txt" y "priv_<nombreUsuario>.txt".
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
     * sugerida claves_usuario/pintores/<NombreUsuario> o
     * claves_usuario/pintor/<NombreUsuario>),
     * multiplicarla por la llave pública EC del sistema
     * (claves_sistema/pub_sist.txt)
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

            // 3. Multiplicar la llave privada del pintor por la pública del sistema
            // mediante ECDH
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
            System.out.println("Algoritmo derivado:            " + claveAES.getAlgorithm() + " ("
                    + (claveAES.getEncoded().length * 8) + " bits)");
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
            System.out.println("[!] El módulo de confidencialidad AES no está disponible para cifrar.");
            return null;
        }

        try {
            // 1. Leer los bytes de la imagen original
            byte[] bytesImagen = Files.readAllBytes(pathImagen);

            // 2. Generar Vector de Inicialización (IV) de 12 bytes (96 bits) para GCM
            byte[] iv = moduloAES.generarIV(12);

            // 3. Cifrar con AES-GCM (cifrado autenticado con tag de 128 bits)
            byte[] datosCifrados = moduloAES.cifrarAES_GCM(bytesImagen, claveAES, iv);

            // 4. Empaquetar IV + Datos Cifrados [IV (12 bytes) + CIFRADO + TAG (16 bytes)]
            byte[] resultadoConIV = new byte[iv.length + datosCifrados.length];
            System.arraycopy(iv, 0, resultadoConIV, 0, iv.length);
            System.arraycopy(datosCifrados, 0, resultadoConIV, iv.length, datosCifrados.length);

            this.ultimaImagenCifrada = resultadoConIV;
            this.ultimoIV = iv;

            // 5. Guardar la imagen cifrada en la carpeta imagenes/ con formato:
            // nombreBase_Cifrado_NombreAutor.<ext>
            String nombreOriginal = pathImagen.getFileName().toString();
            int puntoIdx = nombreOriginal.lastIndexOf('.');
            String nombreBase = (puntoIdx > 0) ? nombreOriginal.substring(0, puntoIdx) : nombreOriginal;
            String extension = (puntoIdx > 0) ? nombreOriginal.substring(puntoIdx) : "";
            String nombreSalida = nombreBase + "_Cifrado_" + pintor.getNombreUsuario() + extension;

            Path pathSalida = pathImagen.getParent() != null
                    ? pathImagen.getParent().resolve(nombreSalida)
                    : Paths.get("imagenes", nombreSalida);

            Files.write(pathSalida, resultadoConIV);
            this.ultimaRutaImagenCifrada = pathSalida;

            // 6. Imprimir información de la imagen cifrada
            String ivHex = bytesToHex(iv);
            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            String muestraCifradaBase64 = Base64.getEncoder().encodeToString(datosCifrados);
            if (muestraCifradaBase64.length() > 64) {
                muestraCifradaBase64 = muestraCifradaBase64.substring(0, 64) + "...";
            }

            // Descifrado de prueba para verificar integridad y tag de autenticación
            byte[] descifradoVerif = moduloAES.descifrarAES_GCM(datosCifrados, claveAES, iv);
            boolean verificacionValida = java.util.Arrays.equals(bytesImagen, descifradoVerif);

            System.out.println("\n==============================================================");
            System.out.println(" IMAGEN CIFRADA CON ÉXITO (AES-GCM - INTEGRANTE 1)");
            System.out.println("==============================================================");
            System.out.println("Pintor emisor:               " + pintor.getNombreUsuario());
            System.out.println("Archivo de imagen original:  " + pathImagen);
            System.out.println("Extensión conservada:        "
                    + (puntoIdx > 0 ? nombreOriginal.substring(puntoIdx) : "(sin extensión)"));
            System.out.println("Tamaño imagen original:      " + bytesImagen.length + " bytes");
            System.out.println("Algoritmo de cifrado:        AES/GCM/NoPadding");
            System.out.println("IV generado (12 bytes):      " + ivHex + " (Base64: " + ivBase64 + ")");
            System.out.println("Tag de autenticación:        128 bits");
            System.out.println("Tamaño de payload cifrado:   " + datosCifrados.length + " bytes");
            System.out.println("Muestra cifrada (Base64):    " + muestraCifradaBase64);
            System.out.println(
                    "Archivo cifrado exportado:   " + pathSalida + " (total: " + resultadoConIV.length + " bytes)");
            System.out.println(
                    "Verificación de Integridad:  " + (verificacionValida ? "VÁLIDA [OK]" : "INVÁLIDA [ERROR]"));
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
    // FIRMA DIGITAL ECDSA DE LA OBRA CIFRADA (INTEGRANTE 2)
    // =========================================================

    /**
     * Obtiene el hash matemático (SHA-256) de la obra cifrada,
     * carga la llave privada del pintor desde
     * claves_usuario/pintores/<NombreUsuario>/
     * y genera la firma digital con ECDSA (curva secp256r1, SHA256withECDSA).
     * Imprime en pantalla la firma digital generada.
     */
    public byte[] firmarObraCifradaPintor(Usuario pintor, byte[] datosObraCifrada) {
        return firmarObraCifradaPintor(pintor, datosObraCifrada, this.ultimaRutaImagenCifrada);
    }

    public byte[] firmarObraCifradaPintor(Usuario pintor, byte[] datosObraCifrada, Path rutaObraCifrada) {
        String nombreUsuario = pintor.getNombreUsuario();

        if (datosObraCifrada == null || datosObraCifrada.length == 0) {
            System.out.println("\n[!] No hay datos de obra cifrada para firmar.");
            return null;
        }

        if (!(motorRegistro instanceof RegistroECDSAPort registroECDSA)) {
            System.out.println("[!] El motor de registro ECDSA no está disponible para firmar la obra.");
            return null;
        }

        // Determinar ruta de la llave privada del pintor
        Path dirBase = Paths.get("claves_usuario", "pintores", nombreUsuario);
        if (!Files.exists(dirBase) && Files.exists(Paths.get("claves_usuario", "pintor", nombreUsuario))) {
            dirBase = Paths.get("claves_usuario", "pintor", nombreUsuario);
        }
        Path pathPriv = dirBase.resolve("priv_" + nombreUsuario + ".txt");

        if (!Files.exists(pathPriv)) {
            System.out.println("\n[!] No se encontró la llave privada del pintor en: " + pathPriv);
            return null;
        }

        try {
            // 1. Cargar la llave privada del pintor desde
            // claves_usuario/pintores/<NombreUsuario>
            PrivateKey privPintor = registroECDSA.cargarLlavePrivada(pathPriv);

            // 2. Obtener el hash matemático (SHA-256) de la obra cifrada
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashObra = md.digest(datosObraCifrada);
            this.ultimoHashObraCifrada = hashObra;

            // 3. Generar la firma digital ECDSA usando la llave privada del pintor
            byte[] firmaDigital = registroECDSA.firmarECDSA(datosObraCifrada, privPintor);
            this.ultimaFirmaDigitalPintor = firmaDigital;

            // 4. Formatear hash y firma en Hexadecimal y Base64
            String hashHex = bytesToHex(hashObra);
            String hashBase64 = Base64.getEncoder().encodeToString(hashObra);

            String firmaHex = bytesToHex(firmaDigital);
            String firmaBase64 = Base64.getEncoder().encodeToString(firmaDigital);

            // 5. Verificar la firma con la llave pública del pintor para certificar
            // autenticidad
            Path pathPub = dirBase.resolve("pub_" + nombreUsuario + ".txt");
            boolean firmaVerificada = false;
            if (Files.exists(pathPub)) {
                PublicKey pubPintor = registroECDSA.cargarLlavePublica(pathPub);
                firmaVerificada = registroECDSA.verificarFirmaECDSA(datosObraCifrada, firmaDigital, pubPintor);
            }

            // 6. Exportar la firma digital a un archivo .txt en
            // claves_usuario/pintores/<NombreUsuario>/
            // Nombre del archivo: "firma_<NombreUsuario>.txt"
            Path rutaArchivoFirma = dirBase.resolve("firma_" + nombreUsuario + ".txt");
            registroECDSA.guardarFirmaDigital(firmaDigital, rutaArchivoFirma);
            this.ultimaRutaFirmaPintor = rutaArchivoFirma;

            // 7. Imprimir en pantalla la firma digital y los detalles criptográficos
            System.out.println("==============================================================");
            System.out.println(" FIRMA DIGITAL ECDSA DE LA OBRA CIFRADA (INTEGRANTE 2)");
            System.out.println("==============================================================");
            System.out.println("Pintor firmante:                " + nombreUsuario);
            System.out.println(
                    "Archivo de obra cifrada:        " + (rutaObraCifrada != null ? rutaObraCifrada : "En memoria"));
            System.out.println("Tamaño de obra cifrada:         " + datosObraCifrada.length + " bytes");
            System.out.println("Algoritmo de firma digital:     SHA256withECDSA (Curva secp256r1)");
            System.out.println("Llave privada utilizada:        " + pathPriv);
            System.out.println("--------------------------------------------------------------");
            System.out.println("HASH MATEMÁTICO DE LA OBRA CIFRADA (SHA-256):");
            System.out.println("-> Hexadecimal: " + hashHex);
            System.out.println("-> Base64:      " + hashBase64);
            System.out.println("--------------------------------------------------------------");
            System.out.println("FIRMA DIGITAL RESULTANTE (ECDSA):");
            System.out.println("-> Longitud:    " + firmaDigital.length + " bytes");
            System.out.println("-> Hexadecimal: " + firmaHex);
            System.out.println("-> Base64:      " + firmaBase64);
            System.out.println("--------------------------------------------------------------");
            System.out.println("Verificación con Llave Pública: "
                    + (firmaVerificada ? "VÁLIDA [OK]" : "PENDIENTE / NO VERIFICADA"));
            System.out.println("Archivo de firma exportado:     " + rutaArchivoFirma);
            System.out.println("==============================================================\n");

            return firmaDigital;

        } catch (Exception e) {
            System.out.println("\n[!] Error al generar la firma digital ECDSA: " + e.getMessage());
            return null;
        }
    }

    public byte[] getUltimaFirmaDigitalPintor() {
        return ultimaFirmaDigitalPintor;
    }

    public byte[] getUltimoHashObraCifrada() {
        return ultimoHashObraCifrada;
    }

    public Path getUltimaRutaFirmaPintor() {
        return ultimaRutaFirmaPintor;
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

            System.out.println("1. [USO] Registrar y proteger obra (Generar llave AES con el Sistema - ECDH)");
            System.out.println("2. Demostración de autenticidad ECDSA de obra");
            System.out.println("3. Consultar mis obras registradas");
            System.out.println("4. Regresar al menú de inicio");
            System.out.print("Seleccione una opción: ");

            String op = scanner.nextLine().trim();

            switch (op) {

                case "1":
                    // 1. Generar llave simétrica AES compartida con el sistema mediante ECDH
                    SecretKey claveAES = generarLlaveAESPintor(pintor);
                    if (claveAES != null) {
                        // 2. Cifrar imagen con AES-GCM (conservando extensión original - Opción A)
                        byte[] obraCifrada = cifrarImagenPintor(pintor, claveAES);
                        if (obraCifrada != null) {
                            // 3. Obtener hash y firmar digitalmente la obra cifrada con la llave privada
                            // del pintor
                            firmarObraCifradaPintor(pintor, obraCifrada, ultimaRutaImagenCifrada);
                        }
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
    // MENU DEL JUEZ
    // =========================================================

    private void menuJuez(Usuario juez) {
        this.juezAutenticado = juez;

        // Inicializar llaves EC del juez que acaba de ingresar
        inicializarLlavesJuez(juez);

        boolean regresar = false;

        while (!regresar) {

            System.out.println(
                    "\n--- Panel del Juez ("
                            + juez.getNombreUsuario() + ") ---");

            System.out.println("1. [USO] Ver imágenes y calificar obra");
            System.out.println("2. [USO] Descegar firma de calificación (Recuperar voto firmado por el Presidente)");
            System.out.println("3. Calificar obra");
            System.out.println("4. Regresar al menú de inicio");
            System.out.print("Seleccione una opción: ");

            String op = scanner.nextLine().trim();

            switch (op) {

                case "1":
                    verImagenesJuez(juez);
                    break;

                case "2":
                    descegarFirmaInteractivo(juez);
                    break;

                case "3":
                    verImagenesJuez(juez);
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
    // CONSULTA Y LISTADO DE IMÁGENES / OBRAS (JUEZ)
    // =========================================================

    /**
     * Lista los nombres de las obras que se encuentran en la carpeta "imagenes/".
     * Si existen tanto la imagen normal como la cifrada (o solo la cifrada con
     * "_cifrada"),
     * remueve el texto "_cifrada" para mostrar únicamente el nombre de la imagen
     * sin duplicados.
     *
     * @return Lista ordenada con los nombres limpios de las imágenes disponibles.
     */
    public static class InfoObraJuez {
        private final String nombreObra;
        private final String autor;
        private final Path rutaArchivoCifrado;

        public InfoObraJuez(String nombreObra, String autor, Path rutaArchivoCifrado) {
            this.nombreObra = nombreObra;
            this.autor = autor;
            this.rutaArchivoCifrado = rutaArchivoCifrado;
        }

        public String getNombreObra() {
            return nombreObra;
        }

        public String getAutor() {
            return autor;
        }

        public Path getRutaArchivoCifrado() {
            return rutaArchivoCifrado;
        }

        @Override
        public String toString() {
            return "Obra: " + nombreObra + " | Autor: " + autor;
        }
    }

    /**
     * Construye el catálogo de obras disponibles analizando los archivos en
     * "imagenes/".
     * Extrae el nombre de la obra y el autor a partir del formato:
     * "nombreBase_Cifrado_NombreAutor.<ext>"
     *
     * @return Lista con la información de las obras y sus autores.
     */
    public List<InfoObraJuez> obtenerCatalogoObrasJuez() {
        Path dirImagenes = Paths.get("imagenes");
        if (!Files.exists(dirImagenes) || !Files.isDirectory(dirImagenes)) {
            return new ArrayList<>();
        }

        Map<String, InfoObraJuez> catalogo = new LinkedHashMap<>();

        try (Stream<Path> stream = Files.list(dirImagenes)) {
            List<Path> archivos = stream.filter(Files::isRegularFile).sorted().toList();

            // 1. Procesar obras cifradas con formato nuevo:
            // nombreBase_Cifrado_NombreAutor.<ext>
            for (Path p : archivos) {
                String nombre = p.getFileName().toString();
                int idx = nombre.toLowerCase().indexOf("_cifrado_");
                if (idx != -1) {
                    String nombreBase = nombre.substring(0, idx);
                    String resto = nombre.substring(idx + "_cifrado_".length());
                    int dotIdx = resto.lastIndexOf('.');
                    String autor;
                    String ext;
                    if (dotIdx > 0) {
                        autor = resto.substring(0, dotIdx);
                        ext = resto.substring(dotIdx);
                    } else {
                        autor = resto;
                        ext = "";
                    }
                    String nombreObra = nombreBase + ext;
                    catalogo.put(nombreObra.toLowerCase(), new InfoObraJuez(nombreObra, autor, p));
                }
            }

            // 2. Procesar obras con formato anterior (_cifrada) si existieran
            for (Path p : archivos) {
                String nombre = p.getFileName().toString();
                if (nombre.toLowerCase().contains("_cifrada")) {
                    String nombreObra = nombre.replace("_cifrada", "");
                    if (!catalogo.containsKey(nombreObra.toLowerCase())) {
                        catalogo.put(nombreObra.toLowerCase(), new InfoObraJuez(nombreObra, "Desconocido", p));
                    }
                }
            }

            // 3. Añadir imágenes sin cifrar que no estén ya en el catálogo
            for (Path p : archivos) {
                String nombre = p.getFileName().toString();
                if (!nombre.toLowerCase().contains("_cifrado_") && !nombre.toLowerCase().contains("_cifrada")) {
                    String key = nombre.toLowerCase();
                    if (!catalogo.containsKey(key)) {
                        catalogo.put(key, new InfoObraJuez(nombre, "Sin registrar", null));
                    }
                }
            }

        } catch (Exception e) {
            System.out.println("[!] Error al leer el catálogo de imágenes: " + e.getMessage());
        }

        return new ArrayList<>(catalogo.values());
    }

    public List<String> obtenerNombresImagenes() {
        return obtenerCatalogoObrasJuez().stream()
                .map(InfoObraJuez::getNombreObra)
                .toList();
    }

    /**
     * Muestra en pantalla el catálogo de imágenes para el Juez indicando el nombre
     * de la obra
     * y el nombre del pintor autor (extraído del formato
     * nombreBase_Cifrado_NombreAutor).
     * El Juez solo debe seleccionar el número de la obra y el sistema identifica al
     * autor
     * automáticamente para realizar la verificación criptográfica.
     */
    public void verImagenesJuez() {
        Usuario juez = (this.juezAutenticado != null) ? this.juezAutenticado
                : new Usuario(UUID.randomUUID().toString(), "juez1", RolUsuario.JUEZ);
        verImagenesJuez(juez);
    }

    public void verImagenesJuez(Usuario juez) {
        this.juezAutenticado = juez;
        System.out.println("\n==============================================================");
        System.out.println(" CATÁLOGO DE IMÁGENES / OBRAS REGISTRADAS (PANEL DEL JUEZ)");
        System.out.println("==============================================================");
        System.out.println("Directorio de imágenes: imagenes/");

        List<InfoObraJuez> catalogo = obtenerCatalogoObrasJuez();

        if (catalogo.isEmpty()) {
            System.out.println("\n[!] No se encontraron imágenes en la carpeta 'imagenes/'.");
            System.out.println("==============================================================\n");
            return;
        }

        System.out.println("\nTotal de obras registradas: " + catalogo.size());
        System.out.println("--------------------------------------------------------------");
        for (int i = 0; i < catalogo.size(); i++) {
            InfoObraJuez obra = catalogo.get(i);
            System.out.printf("  [%d] Obra: %s | Autor: %s%n", (i + 1), obra.getNombreObra(), obra.getAutor());
        }
        System.out.println("--------------------------------------------------------------");

        System.out.print("Seleccione el número de la obra a analizar (ENTER o 0 para volver): ");
        String seleccion = scanner.nextLine().trim();

        if (seleccion.isEmpty() || seleccion.equals("0")) {
            return;
        }

        int index;
        try {
            index = Integer.parseInt(seleccion);
        } catch (NumberFormatException e) {
            System.out.println("\n[!] Entrada no válida. Debe ingresar un número de la lista.");
            return;
        }

        if (index < 1 || index > catalogo.size()) {
            System.out.println("\n[!] Número de obra fuera de rango.");
            return;
        }

        // Se toma la obra seleccionada y su autor detectado automáticamente
        InfoObraJuez obraElegida = catalogo.get(index - 1);
        System.out.println("\n>> Obra seleccionada:  " + obraElegida.getNombreObra());
        System.out.println(">> Autor identificado: " + obraElegida.getAutor());

        if (obraElegida.getAutor().equalsIgnoreCase("Sin registrar")
                || obraElegida.getAutor().equalsIgnoreCase("Desconocido")) {
            System.out.println("\n[!] Esta obra no cuenta con un autor identificado o no ha sido cifrada/firmada.");
            System.out.println("INVALIDA");
            return;
        }

        boolean esValida = verificarFirmaObraPintor(obraElegida.getNombreObra(), obraElegida.getAutor());

        // Si la firma es válida, después de recuperar la llave AES y descifrar la
        // imagen,
        // el juez emite su veredicto (estrellas 1 a 3 y comentarios)
        if (esValida) {
            solicitarVeredictoJuez(juez, obraElegida.getNombreObra(), obraElegida.getAutor());
        }
    }

    /**
     * Verifica la autenticidad e integridad de la firma digital de una obra
     * seleccionada.
     * Carga la llave pública del pintor en
     * "claves_usuario/pintores/<NombreUsuario>/pub_<NombreUsuario>"
     * y la firma en
     * "claves_usuario/pintores/<NombreUsuario>/firma_<NombreUsuario>".
     * Imprime en consola "VALIDA" si no hubo cambios o "INVALIDA" si hubo
     * modificaciones.
     *
     * @param nombreObra   Nombre de la obra elegida (ej. "bandera.bmp" o
     *                     "mona_lisa_Cifrado_davinci.bmp").
     * @param nombrePintor Nombre de usuario del pintor (ej. "moi", "davinci").
     * @return true si la firma es válida, false en caso contrario.
     */
    public boolean verificarFirmaObraPintor(String nombreObra, String nombrePintor) {
        if (!(motorRegistro instanceof RegistroECDSAPort registroECDSA)) {
            System.out.println("[!] El motor de registro ECDSA no está disponible.");
            System.out.println("INVALIDA");
            return false;
        }

        Path dirPintor = Paths.get("claves_usuario", "pintores", nombrePintor);
        if (!Files.exists(dirPintor) && Files.exists(Paths.get("claves_usuario", "pintor", nombrePintor))) {
            dirPintor = Paths.get("claves_usuario", "pintor", nombrePintor);
        }

        Path pathPub = dirPintor.resolve("pub_" + nombrePintor + ".txt");
        if (!Files.exists(pathPub)) {
            pathPub = dirPintor.resolve("pub_" + nombrePintor);
        }

        if (!Files.exists(pathPub)) {
            System.out.println("\n[!] No se encontró la llave pública del pintor en: " + pathPub);
            System.out.println("INVALIDA");
            return false;
        }

        Path pathFirma = dirPintor.resolve("firma_" + nombrePintor + ".txt");
        if (!Files.exists(pathFirma)) {
            pathFirma = dirPintor.resolve("firma_" + nombrePintor);
        }

        if (!Files.exists(pathFirma)) {
            System.out.println("\n[!] No se encontró el archivo de firma del pintor en: " + pathFirma);
            System.out.println("INVALIDA");
            return false;
        }

        // Localizar el archivo cifrado de la obra en imagenes/
        int puntoIdx = nombreObra.lastIndexOf('.');
        String nombreBase = (puntoIdx > 0) ? nombreObra.substring(0, puntoIdx) : nombreObra;
        String extension = (puntoIdx > 0) ? nombreObra.substring(puntoIdx) : "";

        Path pathObra = Paths.get("imagenes", nombreBase + "_Cifrado_" + nombrePintor + extension);
        if (!Files.exists(pathObra)) {
            pathObra = Paths.get("imagenes", nombreObra);
        }
        if (!Files.exists(pathObra)) {
            pathObra = Paths.get("imagenes", nombreBase + "_cifrada" + extension);
        }
        if (!Files.exists(pathObra)) {
            System.out.println("\n[!] No se encontró el archivo de la obra en: " + pathObra);
            System.out.println("INVALIDA");
            return false;
        }

        try {
            byte[] datosObra = Files.readAllBytes(pathObra);
            PublicKey pubPintor = registroECDSA.cargarLlavePublica(pathPub);
            byte[] firma = registroECDSA.cargarFirmaDigital(pathFirma);

            boolean esValida = registroECDSA.verificarFirmaECDSA(datosObra, firma, pubPintor);

            System.out.println("\n==============================================================");
            System.out.println(" ANÁLISIS DE AUTENTICIDAD E INTEGRIDAD DE LA OBRA (ECDSA)");
            System.out.println("==============================================================");
            System.out.println("Obra seleccionada:        " + pathObra);
            System.out.println("Pintor / Autor:           " + nombrePintor);
            System.out.println("Llave pública utilizada:  " + pathPub);
            System.out.println("Archivo de firma:         " + pathFirma);
            System.out.println("Algoritmo de firma:       SHA256withECDSA (Curva secp256r1)");

            if (esValida) {
                System.out.println("\n>> RESULTADO: VALIDA");
                System.out.println(">> La obra es auténtica y no sufrió ninguna modificación.");

                // Si la firma es válida, el sistema toma su llave privada en
                // "claves_sistema/piv_sist.txt"
                // y se multiplica por la llave pública del pintor para recuperar e imprimir la
                // llave AES
                SecretKey claveRecuperada = recuperarLlaveAESSistema(nombrePintor);

                // Después de recuperar la llave AES, se descifra la imagen cifrada seleccionada
                // por el juez
                if (claveRecuperada != null) {
                    descifrarImagenObra(pathObra, nombreObra, nombrePintor, claveRecuperada);
                }
            } else {
                System.out.println("\n>> RESULTADO: INVALIDA");
                System.out.println(
                        ">> [ALERTA] La firma no coincide o la obra fue alterada. No se descifrará la imagen.");
            }
            System.out.println("==============================================================\n");

            return esValida;
        } catch (Exception e) {
            System.out.println("\n[!] Error durante la verificación criptográfica: " + e.getMessage());
            System.out.println("INVALIDA");
            return false;
        }
    }

    /**
     * Recupera la llave simétrica AES cuando la firma digital es válida.
     * El sistema toma su llave privada en "claves_sistema/piv_sist.txt" (o
     * "claves_sistema/priv_sist.txt")
     * y se multiplica por la llave pública del pintor guardada en
     * "claves_usuario/pintores/<nombreUsuario>/pub_<nombreUsuario>"
     * mediante ECDH (d_sistema * Q_pintor) para recuperar la llave AES compartida.
     * Imprime en consola la llave AES recuperada.
     *
     * @param nombrePintor Nombre de usuario autor de la obra.
     * @return SecretKey AES recuperada, o null si falla.
     */
    public SecretKey recuperarLlaveAESSistema(String nombrePintor) {
        if (!(motorRegistro instanceof RegistroECDSAPort registroECDSA)) {
            System.out.println("[!] El motor de registro ECDSA no está disponible para cargar llaves.");
            return null;
        }

        if (!(motorConfidencialidad instanceof ConfidencialidadAESPort moduloAES)) {
            System.out.println("[!] El módulo de confidencialidad AES no está disponible para derivar la clave.");
            return null;
        }

        try {
            // 1. Tomar llave privada del sistema desde "claves_sistema/piv_sist.txt" (o
            // "claves_sistema/priv_sist.txt")
            Path pathPrivSistema = Paths.get("claves_sistema", "piv_sist.txt");
            if (!Files.exists(pathPrivSistema)) {
                pathPrivSistema = Paths.get("claves_sistema", "priv_sist.txt");
            }
            if (!Files.exists(pathPrivSistema)) {
                pathPrivSistema = Paths.get("claves_sistema", "piv_sist");
            }
            if (!Files.exists(pathPrivSistema)) {
                pathPrivSistema = Paths.get("claves_sistema", "priv_sist");
            }

            if (!Files.exists(pathPrivSistema)) {
                System.out
                        .println("\n[!] No se encontró la llave privada del sistema en 'claves_sistema/piv_sist.txt'");
                return null;
            }

            PrivateKey privSistema = registroECDSA.cargarLlavePrivada(pathPrivSistema);

            // 2. Tomar llave pública del pintor guardada en
            // "claves_usuario/pintores/<nombreUsuario>/pub_<nombreUsuario>"
            Path dirPintor = Paths.get("claves_usuario", "pintores", nombrePintor);
            if (!Files.exists(dirPintor) && Files.exists(Paths.get("claves_usuario", "pintor", nombrePintor))) {
                dirPintor = Paths.get("claves_usuario", "pintor", nombrePintor);
            }

            Path pathPubPintor = dirPintor.resolve("pub_" + nombrePintor);
            if (!Files.exists(pathPubPintor)) {
                pathPubPintor = dirPintor.resolve("pub_" + nombrePintor + ".txt");
            }

            if (!Files.exists(pathPubPintor)) {
                System.out.println("\n[!] No se encontró la llave pública del pintor en: " + pathPubPintor);
                return null;
            }

            PublicKey pubPintor = registroECDSA.cargarLlavePublica(pathPubPintor);

            // 3. Multiplicar la llave privada del sistema por la llave pública del pintor
            // mediante ECDH
            SecretKey claveAES = moduloAES.derivarClaveAES(privSistema, pubPintor);
            this.ultimaClaveAESRecuperada = claveAES;

            // 4. Imprimir en consola la llave AES generada/recuperada
            String claveBase64 = Base64.getEncoder().encodeToString(claveAES.getEncoded());
            StringBuilder hexString = new StringBuilder();
            for (byte b : claveAES.getEncoded()) {
                hexString.append(String.format("%02X", b));
            }

            System.out.println("\n==============================================================");
            System.out.println(" LLAVE AES RECUPERADA POR EL SISTEMA (ECDH: d_sistema * Q_pintor)");
            System.out.println("==============================================================");
            System.out.println("Autor / Pintor:                " + nombrePintor);
            System.out.println("Llave privada del sistema:     " + pathPrivSistema);
            System.out.println("Llave pública del pintor:      " + pathPubPintor);
            System.out.println("Operación Criptográfica:       d_sistema * Q_pintor -> Derivación SHA-256 (ECDH)");
            System.out.println("Algoritmo derivado:            " + claveAES.getAlgorithm() + " ("
                    + (claveAES.getEncoded().length * 8) + " bits)");
            System.out.println("--------------------------------------------------------------");
            System.out.println("LLAVE AES RECUPERADA (Hex):    " + hexString);
            System.out.println("LLAVE AES RECUPERADA (Base64): " + claveBase64);
            System.out.println("==============================================================\n");

            return claveAES;

        } catch (Exception e) {
            System.out.println("\n[!] Error al recuperar la llave AES del sistema: " + e.getMessage());
            return null;
        }
    }

    public SecretKey getUltimaClaveAESRecuperada() {
        return ultimaClaveAESRecuperada;
    }

    /**
     * Descifra la imagen cifrada seleccionada por el juez utilizando la llave AES
     * recuperada.
     * Guarda la imagen descifrada en la carpeta "imagenes" con el formato:
     * "nombreBase_descifrada_nombreUsuario.<ext>"
     *
     * @param pathObraCifrada Ruta física del archivo cifrado en imagenes/
     * @param nombreObra      Nombre de la obra elegida
     * @param nombrePintor    Nombre de usuario autor de la obra
     * @param claveAES        Llave simétrica AES recuperada mediante ECDH
     * @return Path del archivo descifrado guardado en imagenes/, o null en caso de
     *         error.
     */
    public Path descifrarImagenObra(Path pathObraCifrada, String nombreObra, String nombrePintor, SecretKey claveAES) {
        if (!(motorConfidencialidad instanceof ConfidencialidadAESPort moduloAES)) {
            System.out.println("[!] El módulo de confidencialidad AES no está disponible para descifrar.");
            return null;
        }

        try {
            // 1. Leer el archivo cifrado completo [IV (12 bytes) + CIFRADO + TAG (16
            // bytes)]
            byte[] contenidoCifrado = Files.readAllBytes(pathObraCifrada);
            if (contenidoCifrado.length < 28) {
                System.out.println("[!] El archivo cifrado no contiene la longitud mínima necesaria (IV + Tag).");
                return null;
            }

            // 2. Extraer el IV (primeros 12 bytes) y los datos cifrados con el tag
            byte[] iv = new byte[12];
            System.arraycopy(contenidoCifrado, 0, iv, 0, 12);

            byte[] datosCifrados = new byte[contenidoCifrado.length - 12];
            System.arraycopy(contenidoCifrado, 12, datosCifrados, 0, datosCifrados.length);

            // 3. Descifrar con AES-GCM usando la llave AES recuperada
            byte[] datosDescifrados = moduloAES.descifrarAES_GCM(datosCifrados, claveAES, iv);

            // 4. Determinar nombre de salida en imagenes/:
            // "nombreBase_descifrada_nombreUsuario.<ext>"
            String nombreArchivo = pathObraCifrada.getFileName().toString();
            String extension = "";
            int puntoIdx = nombreArchivo.lastIndexOf('.');
            if (puntoIdx > 0) {
                extension = nombreArchivo.substring(puntoIdx);
                nombreArchivo = nombreArchivo.substring(0, puntoIdx);
            }

            // Quitar sufijos como _Cifrado_<autor> o _cifrada si estuvieran presentes
            int idxCifrado = nombreArchivo.toLowerCase().indexOf("_cifrad");
            String nombreBase = (idxCifrado > 0) ? nombreArchivo.substring(0, idxCifrado) : nombreArchivo;

            String nombreArchivoDescifrado = nombreBase + "_descifrada_" + nombrePintor + extension;
            Path dirImagenes = Paths.get("imagenes");
            Files.createDirectories(dirImagenes);
            Path pathDescifrado = dirImagenes.resolve(nombreArchivoDescifrado);

            // 5. Guardar la imagen descifrada en disco
            Files.write(pathDescifrado, datosDescifrados);
            this.ultimaRutaImagenDescifrada = pathDescifrado;

            // 6. Imprimir información del descifrado en consola
            System.out.println("==============================================================");
            System.out.println(" IMAGEN DESCIFRADA CON ÉXITO (AES-GCM - INTEGRANTE 1)");
            System.out.println("==============================================================");
            System.out.println("Archivo cifrado procesado:     " + pathObraCifrada);
            System.out.println("Autor / Pintor:                " + nombrePintor);
            System.out.println("Algoritmo de descifrado:       AES/GCM/NoPadding (256 bits)");
            System.out.println("IV utilizado (12 bytes Hex):   " + bytesToHex(iv));
            System.out.println("Tamaño de imagen descifrada:   " + datosDescifrados.length + " bytes");
            System.out.println("Archivo descifrado guardado:   " + pathDescifrado);
            System.out.println("==============================================================\n");

            return pathDescifrado;

        } catch (Exception e) {
            System.out.println("\n[!] Error al descifrar la obra con AES-GCM: " + e.getMessage());
            return null;
        }
    }

    public Path getUltimaRutaImagenDescifrada() {
        return ultimaRutaImagenDescifrada;
    }

    // =========================================================
    // VEREDICTO Y ACTA DE CALIFICACIÓN DEL JUEZ
    // =========================================================

    /**
     * Extrae el nombre base de la obra limpiando extensiones y sufijos como
     * _Cifrado o _descifrada.
     * Ejemplo: "mona_lisa.bmp" -> "mona_lisa", "mona_lisa_descifrada_davinci.bmp"
     * -> "mona_lisa".
     *
     * @param nombreObra Nombre o ruta de la obra
     * @return Nombre base de la obra
     */
    public static String extraerNombreBaseObra(String nombreObra) {
        if (nombreObra == null || nombreObra.isEmpty()) {
            return "obra";
        }
        String s = Paths.get(nombreObra).getFileName().toString();
        int punto = s.lastIndexOf('.');
        if (punto > 0) {
            s = s.substring(0, punto);
        }
        int idxDesc = s.toLowerCase().indexOf("_descifrad");
        if (idxDesc > 0) {
            s = s.substring(0, idxDesc);
        }
        int idxCif = s.toLowerCase().indexOf("_cifrad");
        if (idxCif > 0) {
            s = s.substring(0, idxCif);
        }
        return s;
    }

    /**
     * Solicita interactivamente por consola el veredicto del juez (1 a 3 estrellas
     * y comentario)
     * y registra el acta correspondiente.
     *
     * @param juez       Usuario juez que realiza la evaluación
     * @param nombreObra Nombre de la obra evaluada
     * @param autor      Nombre del autor/pintor de la obra
     * @return Path del archivo txt generado, o null si ocurre un error
     */
    public Path solicitarVeredictoJuez(Usuario juez, String nombreObra, String autor) {
        String nombreJuez = (juez != null && juez.getNombreUsuario() != null)
                ? juez.getNombreUsuario()
                : (this.juezAutenticado != null ? this.juezAutenticado.getNombreUsuario() : "juez1");
        String nombreBase = extraerNombreBaseObra(nombreObra);

        System.out.println("==============================================================");
        System.out.println(" EMISIÓN DE VEREDICTO DEL JUEZ SOBRE LA OBRA");
        System.out.println("==============================================================");
        System.out.println("Juez evaluador:        " + nombreJuez);
        System.out.println("Obra evaluada:         " + nombreBase);
        System.out.println("Autor / Pintor:        " + autor);
        System.out.println("--------------------------------------------------------------");

        int estrellas = 0;
        while (estrellas < 1 || estrellas > 3) {
            System.out.print("Ingrese calificación en estrellas (1 a 3): ");
            String entrada = scanner.nextLine().trim();
            try {
                int val = Integer.parseInt(entrada);
                if (val >= 1 && val <= 3) {
                    estrellas = val;
                } else {
                    System.out.println("[!] Debe ingresar un valor entre 1 y 3 estrellas.");
                }
            } catch (NumberFormatException e) {
                System.out.println("[!] Entrada inválida. Ingrese un número entero (1, 2 o 3).");
            }
        }

        System.out.print("Ingrese un comentario sobre la obra: ");
        String comentario = scanner.nextLine().trim();
        if (comentario.isEmpty()) {
            comentario = "Sin comentarios adicionales.";
        }

        Path pathActa = registrarVeredictoJuez(nombreJuez, nombreObra, autor, estrellas, comentario);
        if (pathActa != null) {
            // Antes de enviarlo al presidente para que este lo firme, el juez ciega su
            // calificación
            cegarCalificacionJuez(nombreJuez, autor);
        }
        return pathActa;
    }

    /**
     * Guarda el veredicto del juez en
     * "calificaciones_jueces/nombreJuez_acta_nombreBase_autor.txt".
     *
     * @param nombreJuez Nombre del juez que emite la calificación
     * @param nombreObra Nombre o ruta de la obra evaluada
     * @param autor      Nombre del autor/pintor de la obra
     * @param estrellas  Calificación en estrellas (1 a 3)
     * @param comentario Comentario de la obra proporcionado por el juez
     * @return Path del archivo txt generado en calificaciones_jueces/
     */
    public Path registrarVeredictoJuez(String nombreJuez, String nombreObra, String autor, int estrellas,
            String comentario) {
        if (estrellas < 1 || estrellas > 3) {
            throw new IllegalArgumentException("La calificación en estrellas debe ser un valor de 1 a 3.");
        }

        String nombreBase = extraerNombreBaseObra(nombreObra);
        String nombreArchivo = nombreJuez + "_acta_" + nombreBase + "_" + autor + ".txt";

        Path dirCalificaciones = Paths.get("calificaciones_jueces");
        try {
            Files.createDirectories(dirCalificaciones);
            Path pathActa = dirCalificaciones.resolve(nombreArchivo);

            String contenido = "====================================================\n"
                    + " ACTA DE CALIFICACIÓN DE OBRA - CONCURSO DE PINTURA\n"
                    + "====================================================\n"
                    + "Juez Evaluador:       " + nombreJuez + "\n"
                    + "Obra Evaluada:        " + nombreBase + "\n"
                    + "Autor / Pintor:       " + autor + "\n"
                    + "Estrellas:            " + estrellas + "\n"
                    + "Comentario de la obra:\n"
                    + comentario + "\n"
                    + "====================================================\n";

            Files.writeString(pathActa, contenido, StandardCharsets.UTF_8);

            this.ultimaRutaActaCalificacion = pathActa;
            this.ultimoVeredictoEstrellas = estrellas;
            this.ultimoVeredictoComentario = comentario;

            System.out.println("==============================================================");
            System.out.println(" ACTA DE CALIFICACIÓN REGISTRADA CON ÉXITO");
            System.out.println("==============================================================");
            System.out.println("Juez evaluador:        " + nombreJuez);
            System.out.println("Obra evaluada:         " + nombreBase);
            System.out.println("Autor / Pintor:        " + autor);
            System.out.println("Estrellas:             " + estrellas);
            System.out.println("Comentarios:           " + comentario);
            System.out.println("Archivo guardado en:   " + pathActa);
            System.out.println("==============================================================\n");

            return pathActa;

        } catch (Exception e) {
            System.out.println("\n[!] Error al guardar el acta de calificación: " + e.getMessage());
            return null;
        }
    }

    public Path getUltimaRutaActaCalificacion() {
        return ultimaRutaActaCalificacion;
    }

    public int getUltimoVeredictoEstrellas() {
        return ultimoVeredictoEstrellas;
    }

    public String getUltimoVeredictoComentario() {
        return ultimoVeredictoComentario;
    }

    public Usuario getJuezAutenticado() {
        return juezAutenticado;
    }

    public void setJuezAutenticado(Usuario juez) {
        this.juezAutenticado = juez;
    }

    // =========================================================
    // CEGADO DE CALIFICACIÓN / VOTO (FIRMA CIEGA DE CHAUM)
    // =========================================================

    /**
     * Realiza el cegado de la calificación del juez utilizando la llave pública RSA
     * del presidente
     * localizada en "claves_usuario/presidente/presidente_RSA_pub.txt" y el método
     * cegar() de ModuloAnonimatoRSA.
     * Guarda el archivo cegado en "calificaciones_jueces" con el nombre
     * "nombrejuez_cegado_autorDeObra.txt".
     *
     * @param nombreJuez Nombre del juez que realizó la votación
     * @param autorObra  Nombre del autor de la obra que se está firmando
     * @return Path del archivo cegado guardado en calificaciones_jueces/
     */
    public Path cegarCalificacionJuez(String nombreJuez, String autorObra) {
        return cegarCalificacionJuez(nombreJuez, autorObra, null);
    }

    /**
     * Realiza el cegado de los datos de la calificación utilizando la llave pública
     * RSA del presidente
     * y el método cegar() de ModuloAnonimatoRSA.
     *
     * @param nombreJuez        Nombre del juez que realizó la votación
     * @param autorObra         Nombre del autor de la obra que se está firmando
     * @param datosCalificacion Bytes de la calificación (si es null, busca y lee el
     *                          acta correspondiente)
     * @return Path del archivo cegado guardado
     */
    public Path cegarCalificacionJuez(String nombreJuez, String autorObra, byte[] datosCalificacion) {
        if (!(motorAnonimato instanceof ModuloAnonimatoRSA moduloRSA)) {
            System.out.println("[!] El módulo de anonimato RSA no está disponible para cegar la calificación.");
            return null;
        }

        try {
            // 1. Cargar la llave pública RSA del presidente desde
            // "claves_usuario/presidente/presidente_RSA_pub.txt"
            Path pathPubPresidente = Paths.get("claves_usuario", "presidente", "presidente_RSA_pub.txt");
            if (!Files.exists(pathPubPresidente)) {
                try (Stream<Path> s = Files.list(Paths.get("claves_usuario", "presidente"))) {
                    pathPubPresidente = s.filter(p -> p.getFileName().toString().endsWith("_RSA_pub.txt"))
                            .findFirst()
                            .orElse(pathPubPresidente);
                } catch (Exception ignored) {
                }
            }

            if (!Files.exists(pathPubPresidente)) {
                System.out.println("\n[!] No se encontró la llave pública RSA del presidente en: " + pathPubPresidente);
                System.out.println("[!] Generando par de llaves RSA para el presidente...");
                moduloRSA.generarYGuardarLlavesRSAPresidente("presidente");
            }

            RSAPublicKey pubPresidente = moduloRSA.cargarLlavePublica(pathPubPresidente);

            // 2. Obtener los datos de la calificación a cegar
            byte[] datosACegar = datosCalificacion;
            if (datosACegar == null || datosACegar.length == 0) {
                Path dirCalificaciones = Paths.get("calificaciones_jueces");
                if (Files.exists(dirCalificaciones)) {
                    try (Stream<Path> s = Files.list(dirCalificaciones)) {
                        Path archivoActa = s.filter(p -> {
                            String f = p.getFileName().toString().toLowerCase();
                            return f.startsWith(nombreJuez.toLowerCase() + "_acta_")
                                    && f.endsWith("_" + autorObra.toLowerCase() + ".txt");
                        }).findFirst().orElse(null);

                        if (archivoActa != null && Files.exists(archivoActa)) {
                            datosACegar = Files.readAllBytes(archivoActa);
                        }
                    }
                }
            }

            if (datosACegar == null || datosACegar.length == 0) {
                String paquete = "JUEZ:" + nombreJuez + "|AUTOR:" + autorObra + "|ESTRELLAS:3";
                datosACegar = paquete.getBytes(StandardCharsets.UTF_8);
            } else if (datosACegar.length > 380) {
                // Si el acta excede la capacidad de bloque de RSA 3072, usar paquete compacto
                // de voto
                int est = (this.ultimoVeredictoEstrellas >= 1 && this.ultimoVeredictoEstrellas <= 3)
                        ? this.ultimoVeredictoEstrellas
                        : 3;
                String paquete = "JUEZ:" + nombreJuez + "|AUTOR:" + autorObra + "|ESTRELLAS:" + est;
                datosACegar = paquete.getBytes(StandardCharsets.UTF_8);
            }

            // 3. Aplicar el método cegar de ModuloAnonimatoRSA
            byte[] votoCegado = moduloRSA.cegar(datosACegar, pubPresidente);

            this.ultimoVotoCegado = votoCegado;
            this.ultimoFactorCegado = moduloRSA.getUltimoFactorCegado();
            if (this.factoresCegado == null) {
                this.factoresCegado = new LinkedHashMap<>();
            }
            this.factoresCegado.put(nombreJuez + "_" + autorObra, this.ultimoFactorCegado);

            // Persistir factor de cegado del juez para permitir descegado entre sesiones
            try {
                Path dirJuez = Paths.get("claves_usuario", "jueces", nombreJuez);
                Files.createDirectories(dirJuez);
                Path pathFactor = dirJuez.resolve("factor_cegado_" + autorObra + ".txt");
                Files.writeString(pathFactor, this.ultimoFactorCegado.toString(), StandardCharsets.UTF_8);
            } catch (Exception ignored) {
            }

            // 4. Guardar archivo cegado en "calificaciones_jueces"
            // con el nombre: "nombrejuez_cegado_autorDeObra.txt"
            String nombreConExt = nombreJuez + "_cegado_" + autorObra + ".txt";
            String votoCegadoBase64 = Base64.getEncoder().encodeToString(votoCegado);

            Path dirJueces = Paths.get("calificaciones_jueces");
            Files.createDirectories(dirJueces);
            Path pathJuecesTxt = dirJueces.resolve(nombreConExt);
            Files.writeString(pathJuecesTxt, votoCegadoBase64, StandardCharsets.UTF_8);

            this.ultimaRutaVotoCegado = pathJuecesTxt;

            // 5. Imprimir información de la operación en consola
            System.out.println("==============================================================");
            System.out.println(" CEGADO DE CALIFICACIÓN REALIZADO CON ÉXITO (FIRMA CIEGA)");
            System.out.println("==============================================================");
            System.out.println("Juez emisor del voto:          " + nombreJuez);
            System.out.println("Autor de la obra:              " + autorObra);
            System.out.println("Llave pública RSA del Presi:   " + pathPubPresidente);
            System.out.println("Método de anonimato:           ModuloAnonimatoRSA.cegar(...)");
            System.out.println("Tamaño de payload cegado:      " + votoCegado.length + " bytes");
            System.out.println("Archivo cegado guardado en:    " + pathJuecesTxt);
            System.out.println("==============================================================\n");

            return pathJuecesTxt;

        } catch (Exception e) {
            System.out.println("\n[!] Error al realizar el cegado de la calificación: " + e.getMessage());
            return null;
        }
    }

    public byte[] getUltimoVotoCegado() {
        return ultimoVotoCegado;
    }

    public BigInteger getUltimoFactorCegado() {
        return ultimoFactorCegado;
    }

    public Path getUltimaRutaVotoCegado() {
        return ultimaRutaVotoCegado;
    }

    public BigInteger getFactorCegado(String nombreJuez, String autorObra) {
        return obtenerFactorCegado(nombreJuez, autorObra);
    }

    public BigInteger obtenerFactorCegado(String nombreJuez, String autorObra) {
        if (factoresCegado != null) {
            BigInteger f = factoresCegado.get(nombreJuez + "_" + autorObra);
            if (f != null) {
                return f;
            }
            for (Map.Entry<String, BigInteger> entry : factoresCegado.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(nombreJuez + "_" + autorObra)) {
                    return entry.getValue();
                }
            }
        }
        // Buscar factor persistido en
        // claves_usuario/jueces/<nombreJuez>/factor_cegado_<autorObra>.txt
        try {
            Path pathFactor = Paths.get("claves_usuario", "jueces", nombreJuez, "factor_cegado_" + autorObra + ".txt");
            if (Files.exists(pathFactor)) {
                String val = Files.readString(pathFactor, StandardCharsets.UTF_8).trim();
                BigInteger factorLeido = new BigInteger(val);
                if (this.factoresCegado == null) {
                    this.factoresCegado = new LinkedHashMap<>();
                }
                this.factoresCegado.put(nombreJuez + "_" + autorObra, factorLeido);
                return factorLeido;
            }
        } catch (Exception ignored) {
        }

        return this.ultimoFactorCegado;
    }

    public byte[] obtenerDatosVotoOriginal(String nombreJuez, String autorObra) {
        Path dirCalificaciones = Paths.get("calificaciones_jueces");
        if (Files.exists(dirCalificaciones)) {
            try (Stream<Path> s = Files.list(dirCalificaciones)) {
                Path archivoActa = s.filter(p -> {
                    String f = p.getFileName().toString().toLowerCase();
                    return f.startsWith(nombreJuez.toLowerCase() + "_acta_")
                            && f.endsWith("_" + autorObra.toLowerCase() + ".txt");
                }).findFirst().orElse(null);

                if (archivoActa != null && Files.exists(archivoActa)) {
                    byte[] bytes = Files.readAllBytes(archivoActa);
                    if (bytes.length <= 380) {
                        return bytes;
                    }
                }
            } catch (Exception ignored) {
            }
        }
        int est = (this.ultimoVeredictoEstrellas >= 1 && this.ultimoVeredictoEstrellas <= 3)
                ? this.ultimoVeredictoEstrellas
                : 3;
        String paquete = "JUEZ:" + nombreJuez + "|AUTOR:" + autorObra + "|ESTRELLAS:" + est;
        return paquete.getBytes(StandardCharsets.UTF_8);
    }

    public Path getUltimaRutaFirmaCegadaPresidente() {
        return ultimaRutaFirmaCegadaPresidente;
    }

    public byte[] getUltimaFirmaDescegada() {
        return ultimaFirmaDescegada;
    }

    public Path getUltimaRutaFirmaDescegada() {
        return ultimaRutaFirmaDescegada;
    }

    // =========================================================
    // DESCEGADO DE FIRMA POR EL JUEZ (CHAUM RSA)
    // =========================================================

    /**
     * Realiza el descegado de la firma del presidente por parte del juez
     * utilizando el método descegarFirmaRSA de ModuloAnonimatoRSA.
     * Recupera el voto con la firma del presidente y guarda el archivo descegado
     * en "calificaciones_jueces/NombreJuez_descegado_autorObra.txt".
     *
     * @param nombreJuez Nombre del juez que realizó la votación (NombreJuez)
     * @param autorObra  Nombre del autor de la obra evaluada (autorObra)
     * @return Path del archivo descegado generado en calificaciones_jueces/
     */
    public Path descegarFirmaJuez(String nombreJuez, String autorObra) {
        try {
            System.out.println("==============================================================");
            System.out.println(" DESCEGADO DE FIRMA POR EL JUEZ (CHAUM RSA)");
            System.out.println("==============================================================");

            if (!(motorAnonimato instanceof ModuloAnonimatoRSA moduloRSA)) {
                System.out.println("[!] El módulo de anonimato RSA no está disponible para descegar.");
                return null;
            }

            // 1. Cargar la llave pública RSA del presidente
            Path pathPubPresidente = Paths.get("claves_usuario", "presidente", "presidente_RSA_pub.txt");
            if (!Files.exists(pathPubPresidente)) {
                Path dirPresi = Paths.get("claves_usuario", "presidente");
                if (Files.exists(dirPresi)) {
                    try (Stream<Path> st = Files.list(dirPresi)) {
                        Path pubAlt = st.filter(p -> p.getFileName().toString().endsWith("_RSA_pub.txt"))
                                .findFirst().orElse(null);
                        if (pubAlt != null) {
                            pathPubPresidente = pubAlt;
                        }
                    }
                }
            }

            if (!Files.exists(pathPubPresidente)) {
                System.out.println("[!] No se encontró la llave pública RSA del presidente en: " + pathPubPresidente);
                return null;
            }

            RSAPublicKey pubPresidente = moduloRSA.cargarLlavePublica(pathPubPresidente);

            // 2. Obtener el archivo de firma ciega en
            // "firmas_presidente/firma_nombreAutor_nombreJuez.txt"
            Path dirFirmas = Paths.get("firmas_presidente");
            Path pathFirma = dirFirmas.resolve("firma_" + autorObra + "_" + nombreJuez + ".txt");
            if (!Files.exists(pathFirma)) {
                Path altFirma = dirFirmas.resolve("firma_" + nombreJuez + "_" + autorObra + ".txt");
                if (Files.exists(altFirma)) {
                    pathFirma = altFirma;
                } else {
                    Path encontrada = buscarFirmaPresidenteInsensible(nombreJuez, autorObra);
                    if (encontrada != null) {
                        pathFirma = encontrada;
                    } else {
                        System.out.println("[!] No se encontró el archivo de firma del presidente en: " + pathFirma);
                        return null;
                    }
                }
            }

            String firmaB64 = Files.readString(pathFirma, StandardCharsets.UTF_8).trim();
            byte[] firmaCegada = Base64.getDecoder().decode(firmaB64);
            if (firmaCegada == null || firmaCegada.length == 0) {
                System.out.println("[!] El archivo de firma del presidente está vacío: " + pathFirma);
                return null;
            }

            // 3. Obtener el factor de cegado r utilizado previamente por el juez
            BigInteger factor = obtenerFactorCegado(nombreJuez, autorObra);
            if (factor == null) {
                System.out.println("[!] No se encontró el factor de cegado para el juez '" + nombreJuez + "' y autor '"
                        + autorObra + "'.");
                return null;
            }

            // 4. Descegar la firma utilizando descegarFirmaRSA: s = s' * r^(-1) mod N
            byte[] firmaDescegada = moduloRSA.descegarFirmaRSA(firmaCegada, factor, pubPresidente);

            // 5. Guardar el archivo descegado en
            // "calificaciones_jueces/NombreJuez_descegado_autorObra.txt"
            Path dirCalificaciones = Paths.get("calificaciones_jueces");
            Files.createDirectories(dirCalificaciones);
            String nombreArchivoDescegado = nombreJuez + "_descegado_" + autorObra + ".txt";
            Path pathDescegado = dirCalificaciones.resolve(nombreArchivoDescegado);

            String firmaDescegadaB64 = Base64.getEncoder().encodeToString(firmaDescegada);
            Files.writeString(pathDescegado, firmaDescegadaB64, StandardCharsets.UTF_8);

            this.ultimaFirmaDescegada = firmaDescegada;
            this.ultimaRutaFirmaDescegada = pathDescegado;

            // 6. Verificar matemáticamente contra los datos originales del voto si están
            // disponibles
            byte[] datosOriginales = obtenerDatosVotoOriginal(nombreJuez, autorObra);
            boolean verificacionOk = false;
            if (datosOriginales != null) {
                verificacionOk = moduloRSA.verificarFirmaRSA(datosOriginales, firmaDescegada, pubPresidente);
            }

            // 7. Imprimir información de la operación en consola
            System.out.println("Juez solicitante:              " + nombreJuez);
            System.out.println("Autor de la obra:              " + autorObra);
            System.out.println("Archivo de firma de entrada:   " + pathFirma);
            System.out.println("Llave pública RSA del Presi:   " + pathPubPresidente);
            System.out.println("Método de anonimato:           ModuloAnonimatoRSA.descegarFirmaRSA(...)");
            System.out.println("Tamaño de firma descegada:     " + firmaDescegada.length + " bytes");
            System.out.println("Archivo descegado guardado en: " + pathDescegado);
            if (datosOriginales != null) {
                System.out.println("Verificación de autenticidad:  "
                        + (verificacionOk ? "[OK] AUTÉNTICA Y VÁLIDA (Firma válida del Presidente)"
                                : "[!] VERIFICACIÓN FALLIDA"));
            }
            System.out.println("==============================================================\n");

            return pathDescegado;

        } catch (Exception e) {
            System.out.println("\n[!] Error al descegar la firma del presidente: " + e.getMessage());
            return null;
        }
    }

    /**
     * Sobrecarga que recibe el objeto Usuario del juez.
     */
    public Path descegarFirmaJuez(Usuario juez, String autorObra) {
        String nombreJuez = (juez != null && juez.getNombreUsuario() != null)
                ? juez.getNombreUsuario()
                : (this.juezAutenticado != null ? this.juezAutenticado.getNombreUsuario() : "juez1");
        return descegarFirmaJuez(nombreJuez, autorObra);
    }

    /**
     * Interfaz interactiva de consola para que el juez descegue la firma del
     * presidente.
     */
    public void descegarFirmaInteractivo(Usuario juez) {
        String nombreJuez = (juez != null && juez.getNombreUsuario() != null)
                ? juez.getNombreUsuario()
                : (this.juezAutenticado != null ? this.juezAutenticado.getNombreUsuario() : "juez1");

        System.out.println("\n==============================================================");
        System.out.println(" DESCEGAR FIRMA DEL PRESIDENTE (JUEZ: " + nombreJuez + ")");
        System.out.println("==============================================================");

        List<Path> firmasDisponibles = listarFirmasPresidenteParaJuez(nombreJuez);
        if (firmasDisponibles.isEmpty()) {
            System.out.println("[!] No se encontraron archivos de firmas en 'firmas_presidente' para el juez '"
                    + nombreJuez + "'.");
            System.out.println("    Asegúrese de que el presidente haya firmado el voto previamente.");
            System.out.println("--------------------------------------------------------------");
            System.out.print("¿Desea ingresar el nombre del Autor de la obra manualmente? (s/n): ");
            String resp = scanner.nextLine().trim();
            if ("s".equalsIgnoreCase(resp)) {
                System.out.print("Ingrese nombre del Autor de la obra: ");
                String autor = scanner.nextLine().trim();
                if (!autor.isEmpty()) {
                    descegarFirmaJuez(nombreJuez, autor);
                }
            }
            return;
        }

        System.out.println("Firmas del presidente detectadas para descegar:");
        for (int i = 0; i < firmasDisponibles.size(); i++) {
            Path p = firmasDisponibles.get(i);
            String fn = p.getFileName().toString();
            String autor = extraerAutorDeFirmaPresidente(fn, nombreJuez);
            System.out.println((i + 1) + ". " + fn + "  [Autor de la obra: " + autor + "]");
        }
        System.out.println((firmasDisponibles.size() + 1) + ". Descegar TODAS las firmas detectadas");
        System.out.println("0. Regresar");
        System.out.print("Seleccione una opción: ");
        String op = scanner.nextLine().trim();

        try {
            int opNum = Integer.parseInt(op);
            if (opNum == 0) {
                return;
            }
            if (opNum == firmasDisponibles.size() + 1) {
                for (Path p : firmasDisponibles) {
                    String autor = extraerAutorDeFirmaPresidente(p.getFileName().toString(), nombreJuez);
                    if (autor != null) {
                        descegarFirmaJuez(nombreJuez, autor);
                    }
                }
            } else if (opNum >= 1 && opNum <= firmasDisponibles.size()) {
                Path p = firmasDisponibles.get(opNum - 1);
                String autor = extraerAutorDeFirmaPresidente(p.getFileName().toString(), nombreJuez);
                if (autor != null) {
                    descegarFirmaJuez(nombreJuez, autor);
                }
            } else {
                System.out.println("[!] Opción inválida.");
            }
        } catch (NumberFormatException e) {
            System.out.println("[!] Opción inválida.");
        }
    }

    /**
     * Lista los archivos en 'firmas_presidente' correspondientes a un juez
     * específico.
     */
    public List<Path> listarFirmasPresidenteParaJuez(String nombreJuez) {
        List<Path> lista = new ArrayList<>();
        Path dir = Paths.get("firmas_presidente");
        if (Files.exists(dir)) {
            String sufijo = ("_" + nombreJuez + ".txt").toLowerCase();
            try (Stream<Path> st = Files.list(dir)) {
                st.filter(p -> {
                    String fn = p.getFileName().toString().toLowerCase();
                    return fn.startsWith("firma_")
                            && (fn.endsWith(sufijo) || fn.contains("_" + nombreJuez.toLowerCase() + "_"));
                }).forEach(lista::add);
            } catch (Exception ignored) {
            }
        }
        return lista;
    }

    /**
     * Extrae el autor de la obra a partir del nombre del archivo de firma:
     * "firma_nombreAutor_nombreJuez.txt" -> "nombreAutor".
     */
    public String extraerAutorDeFirmaPresidente(String fileName, String nombreJuez) {
        String base = fileName.toLowerCase().endsWith(".txt")
                ? fileName.substring(0, fileName.length() - 4)
                : fileName;
        if (base.toLowerCase().startsWith("firma_")) {
            base = base.substring("firma_".length());
        }
        String sufijoJuez = "_" + nombreJuez.toLowerCase();
        if (base.toLowerCase().endsWith(sufijoJuez)) {
            return base.substring(0, base.length() - sufijoJuez.length());
        }
        String prefijoJuez = nombreJuez.toLowerCase() + "_";
        if (base.toLowerCase().startsWith(prefijoJuez)) {
            return base.substring(prefijoJuez.length());
        }
        return base;
    }

    /**
     * Búsqueda insensible a mayúsculas de la firma del presidente.
     */
    private Path buscarFirmaPresidenteInsensible(String nombreJuez, String autorObra) {
        Path dir = Paths.get("firmas_presidente");
        if (!Files.exists(dir)) {
            return null;
        }

        String patron1 = ("firma_" + autorObra + "_" + nombreJuez + ".txt").toLowerCase();
        String patron2 = ("firma_" + nombreJuez + "_" + autorObra + ".txt").toLowerCase();

        try (Stream<Path> st = Files.list(dir)) {
            return st.filter(p -> {
                String fn = p.getFileName().toString().toLowerCase();
                return fn.equals(patron1) || fn.equals(patron2);
            }).findFirst().orElse(null);
        } catch (Exception ignored) {
            return null;
        }
    }

    // =========================================================
    // FIRMA CIEGA DE VOTOS POR EL PRESIDENTE (CHAUM RSA)
    // =========================================================

    /**
     * Realiza la firma ciega por parte del presidente a un voto cegado emitido por
     * un juez.
     * Aplica la llave privada RSA del presidente (ubicada en
     * "claves_usuario/presidente/presidente_RSA_priv.txt")
     * al contenido del voto cegado que se encuentra en
     * "calificaciones_jueces/nombreUsuario_cegado_nombreAutor.txt"
     * y guarda la firma generada en
     * "firmas_presidente/firma_nombreAutor_nombreJuez.txt".
     *
     * @param nombreJuez  Nombre del juez que emitió el voto (nombreUsuario)
     * @param nombreAutor Nombre del autor de la obra evaluada
     * @return Path del archivo de firma generado en firmas_presidente/
     */
    public Path firmarVotoCegadoPresidente(String nombreJuez, String nombreAutor) {
        return firmarVotoCegadoPresidente(null, nombreJuez, nombreAutor);
    }

    /**
     * Realiza la firma ciega por parte del presidente a un voto cegado emitido por
     * un juez.
     *
     * @param presidente  Usuario presidente autenticado (opcional)
     * @param nombreJuez  Nombre del juez que emitió el voto (nombreUsuario)
     * @param nombreAutor Nombre del autor de la obra evaluada
     * @return Path del archivo de firma generado en firmas_presidente/
     */
    public Path firmarVotoCegadoPresidente(Usuario presidente, String nombreJuez, String nombreAutor) {
        try {
            System.out.println("==============================================================");
            System.out.println(" FIRMA CIEGA DE VOTO POR PARTE DEL PRESIDENTE (CHAUM RSA)");
            System.out.println("==============================================================");

            if (!(motorAnonimato instanceof ModuloAnonimatoRSA moduloRSA)) {
                System.out.println("[!] El módulo de anonimato RSA no está disponible para firmar.");
                return null;
            }

            // 1. Cargar la llave privada RSA del presidente desde
            // "claves_usuario/presidente/presidente_RSA_priv.txt"
            Path pathPriv = Paths.get("claves_usuario", "presidente", "presidente_RSA_priv.txt");
            if (!Files.exists(pathPriv) && presidente != null && presidente.getNombreUsuario() != null) {
                Path altPriv = Paths.get("claves_usuario", "presidente",
                        presidente.getNombreUsuario() + "_RSA_priv.txt");
                if (Files.exists(altPriv)) {
                    pathPriv = altPriv;
                }
            }

            if (!Files.exists(pathPriv)) {
                Path dirPresidente = Paths.get("claves_usuario", "presidente");
                if (Files.exists(dirPresidente)) {
                    try (Stream<Path> st = Files.list(dirPresidente)) {
                        Path privHallada = st.filter(p -> p.getFileName().toString().endsWith("_RSA_priv.txt"))
                                .findFirst().orElse(null);
                        if (privHallada != null) {
                            pathPriv = privHallada;
                        }
                    }
                }
            }

            if (!Files.exists(pathPriv)) {
                String nomPresi = (presidente != null && presidente.getNombreUsuario() != null)
                        ? presidente.getNombreUsuario()
                        : "presidente";
                moduloRSA.generarYGuardarLlavesRSAPresidente(nomPresi);
                pathPriv = Paths.get("claves_usuario", "presidente", "presidente_RSA_priv.txt");
                if (!Files.exists(pathPriv)) {
                    pathPriv = Paths.get("claves_usuario", "presidente", nomPresi + "_RSA_priv.txt");
                }
            }

            RSAPrivateKey privPresidente = moduloRSA.cargarLlavePrivada(pathPriv);

            // 2. Cargar el voto cegado desde
            // "calificaciones_jueces/nombreUsuario_cegado_nombreAutor.txt"
            String nombreArchivoCegado = nombreJuez + "_cegado_" + nombreAutor + ".txt";
            Path pathCegado = Paths.get("calificaciones_jueces", nombreArchivoCegado);

            if (!Files.exists(pathCegado)) {
                Path encontrado = buscarArchivoCegadoInsensible(nombreJuez, nombreAutor);
                if (encontrado != null) {
                    pathCegado = encontrado;
                } else {
                    System.out.println("[!] No se encontró el archivo de voto cegado en: " + pathCegado);
                    return null;
                }
            }

            String contenidoB64 = Files.readString(pathCegado, StandardCharsets.UTF_8).trim();
            byte[] bytesCegados = Base64.getDecoder().decode(contenidoB64);
            if (bytesCegados == null || bytesCegados.length == 0) {
                System.out.println("[!] El archivo de voto cegado no contiene bytes válidos: " + pathCegado);
                return null;
            }

            // 3. Aplicar la firma ciega RSA: s' = (m')^d mod N
            byte[] firmaCegada = moduloRSA.firmarCegadoRSA(bytesCegados, privPresidente);

            // 4. Guardar la firma en "firmas_presidente/firma_nombreAutor_nombreJuez.txt"
            Path dirFirmas = Paths.get("firmas_presidente");
            Files.createDirectories(dirFirmas);
            String nombreArchivoFirma = "firma_" + nombreAutor + "_" + nombreJuez + ".txt";
            Path pathFirma = dirFirmas.resolve(nombreArchivoFirma);

            String firmaB64 = Base64.getEncoder().encodeToString(firmaCegada);
            Files.writeString(pathFirma, firmaB64, StandardCharsets.UTF_8);

            this.ultimaRutaFirmaCegadaPresidente = pathFirma;

            // 5. Imprimir información de la operación en consola
            System.out.println("Presidente firmante:           "
                    + (presidente != null ? presidente.getNombreUsuario() : "presidente"));
            System.out.println("Juez emisor del voto:          " + nombreJuez);
            System.out.println("Autor de la obra:              " + nombreAutor);
            System.out.println("Llave privada RSA empleada:    " + pathPriv);
            System.out.println("Archivo de voto cegado leído:  " + pathCegado);
            System.out.println("Tamaño de firma ciega:         " + firmaCegada.length + " bytes");
            System.out.println("Firma ciega guardada en:       " + pathFirma);
            System.out.println("==============================================================\n");

            return pathFirma;

        } catch (Exception e) {
            System.out.println("\n[!] Error al realizar la firma ciega del presidente: " + e.getMessage());
            return null;
        }
    }

    /**
     * Búsqueda insensible a mayúsculas y minúsculas para archivos de voto cegado.
     */
    private Path buscarArchivoCegadoInsensible(String nombreJuez, String nombreAutor) {
        Path[] carpetas = { Paths.get("calificaciones_jueces") };
        String sufijoEsperado = ("_cegado_" + nombreAutor + ".txt").toLowerCase();
        String prefijoEsperado = (nombreJuez + "_cegado_").toLowerCase();

        for (Path dir : carpetas) {
            if (Files.exists(dir)) {
                try (Stream<Path> st = Files.list(dir)) {
                    Path hallado = st.filter(p -> {
                        String f = p.getFileName().toString().toLowerCase();
                        return f.startsWith(prefijoEsperado) && f.endsWith(sufijoEsperado);
                    }).findFirst().orElse(null);
                    if (hallado != null) {
                        return hallado;
                    }
                } catch (Exception ignored) {
                }
            }
        }
        return null;
    }

    /**
     * Interfaz interactiva de consola para que el presidente firme votos cegados.
     */
    public void firmarVotosCegadosInteractivo(Usuario presidente) {
        System.out.println("\n==============================================================");
        System.out.println(" FIRMA CIEGA DE VOTOS DE JUECES (PRESIDENTE)");
        System.out.println("==============================================================");

        List<Path> votosPendientes = listarVotosCegadosDisponibles();
        if (votosPendientes.isEmpty()) {
            System.out.println("[!] No se encontraron archivos de votos cegados en 'calificaciones_jueces'.");
            System.out.println("    Asegúrese de que los jueces hayan emitido y cegado sus calificaciones.");
            System.out.println("--------------------------------------------------------------");
            System.out.print("¿Desea ingresar el nombre del Juez y Autor manualmente? (s/n): ");
            String resp = scanner.nextLine().trim();
            if ("s".equalsIgnoreCase(resp)) {
                System.out.print("Ingrese nombre del Juez: ");
                String juez = scanner.nextLine().trim();
                System.out.print("Ingrese nombre del Autor: ");
                String autor = scanner.nextLine().trim();
                if (!juez.isEmpty() && !autor.isEmpty()) {
                    firmarVotoCegadoPresidente(presidente, juez, autor);
                }
            }
            return;
        }

        System.out.println("Votos cegados detectados pendientes de firma:");
        for (int i = 0; i < votosPendientes.size(); i++) {
            Path p = votosPendientes.get(i);
            String fn = p.getFileName().toString();
            String[] datos = extraerJuezYAutorDeNombre(fn);
            String detalle = (datos != null)
                    ? "Juez: " + datos[0] + " | Autor: " + datos[1]
                    : fn;
            System.out.println((i + 1) + ". " + fn + "  [" + detalle + "]");
        }
        System.out.println((votosPendientes.size() + 1) + ". Firmar TODOS los votos detectados");
        System.out.println("0. Regresar");
        System.out.print("Seleccione una opción: ");
        String op = scanner.nextLine().trim();

        try {
            int opNum = Integer.parseInt(op);
            if (opNum == 0) {
                return;
            }
            if (opNum == votosPendientes.size() + 1) {
                for (Path p : votosPendientes) {
                    String[] datos = extraerJuezYAutorDeNombre(p.getFileName().toString());
                    if (datos != null) {
                        firmarVotoCegadoPresidente(presidente, datos[0], datos[1]);
                    }
                }
            } else if (opNum >= 1 && opNum <= votosPendientes.size()) {
                Path p = votosPendientes.get(opNum - 1);
                String[] datos = extraerJuezYAutorDeNombre(p.getFileName().toString());
                if (datos != null) {
                    firmarVotoCegadoPresidente(presidente, datos[0], datos[1]);
                }
            } else {
                System.out.println("[!] Opción inválida.");
            }
        } catch (NumberFormatException e) {
            System.out.println("[!] Opción inválida.");
        }
    }

    /**
     * Lista todos los archivos de voto cegado disponibles en calificaciones_jueces.
     */
    public List<Path> listarVotosCegadosDisponibles() {
        List<Path> lista = new ArrayList<>();
        Path dir = Paths.get("calificaciones_jueces");
        if (Files.exists(dir)) {
            try (Stream<Path> st = Files.list(dir)) {
                st.filter(p -> {
                    String fn = p.getFileName().toString();
                    return fn.endsWith(".txt") && fn.contains("_cegado_");
                }).forEach(lista::add);
            } catch (Exception ignored) {
            }
        }
        return lista;
    }

    /**
     * Extrae el nombre del juez y del autor a partir del nombre del archivo:
     * "nombreUsuario_cegado_nombreAutor.txt" -> [nombreUsuario, nombreAutor].
     */
    public String[] extraerJuezYAutorDeNombre(String fileName) {
        String base = fileName.toLowerCase().endsWith(".txt")
                ? fileName.substring(0, fileName.length() - 4)
                : fileName;
        int idx = base.indexOf("_cegado_");
        if (idx > 0) {
            String juez = base.substring(0, idx);
            String autor = base.substring(idx + "_cegado_".length());
            return new String[] { juez, autor };
        }
        return null;
    }

    private void menuPresidente(Usuario presidente) {

        // Inicializar llaves EC del presidente (cargar existentes o generar nuevas)
        inicializarLlavesPresidente();

        // Inicializar o generar llaves RSA del presidente para la firma ciega de Chaum
        inicializarOGenerarLlavesRSAPresidente(presidente);

        boolean regresar = false;

        while (!regresar) {

            System.out.println(
                    "\n--- Panel del Presidente ("
                            + presidente.getNombreUsuario() + ") ---");

            System.out.println("1. [USO] Realizar firma ciega de voto de un Juez (Chaum RSA)");
            System.out.println("2. Emitir y firmar Acta de Resultados (RSASSA-PSS - FIPS 186-5)");
            System.out.println("3. Verificar firma de un Acta de Resultados existente");
            System.out.println("4. Simulación de firma ciega (RSA Chaum)");
            System.out.println("5. Regresar al menú de inicio");
            System.out.print("Seleccione una opción: ");

            String op = scanner.nextLine().trim();

            switch (op) {

                case "1":
                    firmarVotosCegadosInteractivo(presidente);
                    break;

                case "2":
                    emitirYFirmarActaResultados(presidente);
                    break;

                case "3":
                    verificarFirmaActaExistente();
                    break;

                case "4":
                    System.out.println(
                            "\n[Simulación]: Realizar firma ciega.");
                    simulacionPresidente();
                    break;

                case "5":
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
                        + "1er Lugar: 'Amanecer en el Valle' - Promedio: 3.00\n"
                        + "2do Lugar: 'Sombras de Otono'     - Promedio: 2.00\n"
                        + "3er Lugar: 'Horizonte Azul'      - Promedio: 1.00\n\n"
                        + "Certificacion oficial: Se declaran los resultados validos, inalterables\n"
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

    // =========================================================
    // MOSTRAR RESULTADOS DEL CONCURSO (VERIFICACIÓN CHAUM RSA)
    // =========================================================

    public static class ResultadoObraItem {
        public final String obra;
        public final String autor;
        public final String juez;
        public final int estrellasNum;
        public final String calificacion;

        public ResultadoObraItem(String obra, String autor, String juez, int estrellasNum, String calificacion) {
            this.obra = obra;
            this.autor = autor;
            this.juez = juez;
            this.estrellasNum = estrellasNum;
            this.calificacion = calificacion;
        }

        public ResultadoObraItem(String obra, String autor, String calificacion) {
            this(obra, autor, "juez", 3, calificacion);
        }
    }

    public static class ResumenClasificacionObra {
        public final String obra;
        public final String autor;
        public final List<VotoJuezDetalle> votos = new ArrayList<>();
        public int suma;
        public double promedio;
        public int lugar;

        public ResumenClasificacionObra(String obra, String autor) {
            this.obra = obra;
            this.autor = autor;
        }

        public void agregarVoto(String juez, int estrellas) {
            votos.add(new VotoJuezDetalle(juez, estrellas));
            suma += estrellas;
            promedio = votos.isEmpty() ? 0.0 : (double) suma / votos.size();
        }
    }

    public static class VotoJuezDetalle {
        public final String juez;
        public final int estrellas;

        public VotoJuezDetalle(String juez, int estrellas) {
            this.juez = juez;
            this.estrellas = estrellas;
        }

        @Override
        public String toString() {
            return juez + ": " + estrellas;
        }
    }

    /**
     * Muestra los resultados del concurso de pintura verificando la validez de las
     * firmas
     * con ModuloAnonimatoRSA.verificarFirmaRSA(...) y la llave pública del
     * Presidente.
     * Suma las calificaciones de los 3 jueces y las promedia, asignando el 1er
     * lugar al
     * que más se acerque a 3 y el último puesto al que más se acerque a 1.
     * Si la firma es válida (TRUE), muestra las obras y su calificación promedio
     * (SIN comentarios).
     * Si la firma es inválida (FALSE), muestra una imagen indicando que el voto fue
     * vulnerado
     * y no muestra nada.
     *
     * @return true si los votos fueron válidos y se mostraron resultados; false si
     *         algún voto fue vulnerado
     */
    public boolean mostrarResultadosConcurso() {
        return mostrarResultadosConcurso(null);
    }

    /**
     * Muestra y verifica los resultados del concurso para votos descegados.
     *
     * @param archivoDescegadoFiltro Archivo de voto descegado específico a
     *                               verificar (o null para todos)
     * @return true si todos los votos son válidos y auténticos; false si algún voto
     *         fue vulnerado
     */
    public boolean mostrarResultadosConcurso(Path archivoDescegadoFiltro) {
        if (!(motorAnonimato instanceof ModuloAnonimatoRSA moduloRSA)) {
            System.out.println("[!] El módulo de anonimato RSA no está disponible para verificar.");
            return false;
        }

        try {
            // 1. Cargar la llave pública RSA del presidente desde
            // "claves_usuario/presidente/presidente_RSA_pub.txt"
            Path pathPubPresidente = Paths.get("claves_usuario", "presidente", "presidente_RSA_pub.txt");
            if (!Files.exists(pathPubPresidente)) {
                Path dirPresi = Paths.get("claves_usuario", "presidente");
                if (Files.exists(dirPresi)) {
                    try (Stream<Path> st = Files.list(dirPresi)) {
                        Path pubAlt = st.filter(p -> p.getFileName().toString().endsWith("_RSA_pub.txt"))
                                .findFirst().orElse(null);
                        if (pubAlt != null) {
                            pathPubPresidente = pubAlt;
                        }
                    }
                }
            }

            if (!Files.exists(pathPubPresidente)) {
                System.out.println("\n[!] No se encontró la llave pública RSA del presidente en: " + pathPubPresidente);
                mostrarImagenVotoVulnerado();
                return false;
            }

            RSAPublicKey pubPresidente = moduloRSA.cargarLlavePublica(pathPubPresidente);

            // 2. Localizar archivos de votos descegados en "calificaciones_jueces/"
            List<Path> archivosDescegados = new ArrayList<>();
            if (archivoDescegadoFiltro != null && Files.exists(archivoDescegadoFiltro)) {
                archivosDescegados.add(archivoDescegadoFiltro);
            } else {
                Path dirCalificaciones = Paths.get("calificaciones_jueces");
                if (Files.exists(dirCalificaciones)) {
                    try (Stream<Path> st = Files.list(dirCalificaciones)) {
                        st.filter(p -> {
                            String fn = p.getFileName().toString().toLowerCase();
                            return fn.endsWith(".txt") && fn.contains("_descegado_");
                        }).forEach(archivosDescegados::add);
                    }
                }
            }

            if (archivosDescegados.isEmpty()) {
                System.out.println("\n==============================================================");
                System.out.println(" RESULTADOS DEL CONCURSO DE PINTURA");
                System.out.println("==============================================================");
                System.out.println(
                        "[!] No se encontraron votos descegados con firma del Presidente en 'calificaciones_jueces/'.");
                System.out.println("    Asegúrese de que los jueces hayan evaluado las obras y descegado las firmas.");
                System.out.println("==============================================================\n");
                return false;
            }

            // 3. Verificar cada voto descegado contra la llave pública del presidente
            List<ResultadoObraItem> listaResultados = new ArrayList<>();

            for (Path pathDescegado : archivosDescegados) {
                String fn = pathDescegado.getFileName().toString();
                String[] parsed = extraerJuezYAutorDeNombreDescegado(fn);
                String nombreJuez = (parsed != null) ? parsed[0] : "juez1";
                String autorObra = (parsed != null) ? parsed[1] : "autor";

                // Leer firma descegada (Base64)
                String firmaB64 = Files.readString(pathDescegado, StandardCharsets.UTF_8).trim();
                byte[] firmaDescegada = Base64.getDecoder().decode(firmaB64);

                // Obtener datos del voto original que fueron firmados
                byte[] datosOriginales = obtenerDatosVotoOriginal(nombreJuez, autorObra);

                // 4. Verificación criptográfica con ModuloAnonimatoRSA.verificarFirmaRSA
                boolean esValido = moduloRSA.verificarFirmaRSA(datosOriginales, firmaDescegada, pubPresidente);

                if (!esValido) {
                    // Si el método retorna FALSE, mostrar imagen de voto vulnerado y NO mostrar
                    // nada
                    System.out.println("\n[!] VERIFICACIÓN FALLIDA PARA EL VOTO: " + fn);
                    mostrarImagenVotoVulnerado();
                    return false;
                }

                // Obtener nombre de la obra y calificación (SIN comentario)
                Path pathActa = encontrarActa(nombreJuez, autorObra);
                ResultadoObraItem item = parsearObraYCalificacion(pathActa, nombreJuez, autorObra);
                listaResultados.add(item);
            }

            // 5. Agrupar las calificaciones de los jueces por obra y calcular suma y
            // promedio
            Map<String, ResumenClasificacionObra> obrasMap = new LinkedHashMap<>();
            for (ResultadoObraItem item : listaResultados) {
                String clave = (item.obra + "___" + item.autor).toLowerCase();
                ResumenClasificacionObra resumen = obrasMap.computeIfAbsent(clave,
                        k -> new ResumenClasificacionObra(item.obra, item.autor));
                resumen.agregarVoto(item.juez, item.estrellasNum);
            }

            List<ResumenClasificacionObra> ranking = new ArrayList<>(obrasMap.values());

            // Ordenar por promedio descendente:
            // "el que se acerque mas a 3 tendra el numero 1 y el que se acerque mas a 1
            // tendra el ultimo puesto"
            ranking.sort((a, b) -> {
                int cmp = Double.compare(b.promedio, a.promedio);
                if (cmp != 0) {
                    return cmp;
                }
                return Integer.compare(b.suma, a.suma);
            });

            for (int i = 0; i < ranking.size(); i++) {
                ranking.get(i).lugar = (i + 1);
            }

            // 6. Si todos los votos son validos (TRUE), mostrar la lista ordenada de obras,
            // suma, promedio y lugar
            String sep = "+-------+--------------------------+--------------------+------------------------------+--------+---------------+-----------------+";
            String borde = "+" + "-".repeat(sep.length() - 2) + "+";
            String titulo1 = "RESULTADOS OFICIALES DEL CONCURSO DE PINTURA";
            String titulo2 = "(PROMEDIO DE LOS 3 JUECES EVALUADORES)";
            int espacioInterno = sep.length() - 2;
            int pad1 = Math.max(0, (espacioInterno - titulo1.length()) / 2);
            int pad2 = Math.max(0, (espacioInterno - titulo2.length()) / 2);

            System.out.println("\n" + borde);
            System.out.println(
                    "|" + " ".repeat(pad1) + titulo1 + " ".repeat(espacioInterno - pad1 - titulo1.length()) + "|");
            System.out.println(
                    "|" + " ".repeat(pad2) + titulo2 + " ".repeat(espacioInterno - pad2 - titulo2.length()) + "|");
            System.out.println(sep);
            System.out.printf("| %-5s | %-24s | %-18s | %-28s | %-6s | %-13s | %-15s |%n",
                    "Lugar", "Obra Evaluada", "Autor / Pintor", "Calificaciones Jueces", "Suma", "Promedio", "Estado");
            System.out.println(sep);

            for (int i = 0; i < ranking.size(); i++) {
                ResumenClasificacionObra r = ranking.get(i);
                String estado = "-";
                if (i == 0) {
                    estado = "[GANADOR]";
                } else if (i == ranking.size() - 1 && ranking.size() > 1) {
                    estado = "[ULTIMO]";
                }

                StringBuilder sb = new StringBuilder();
                for (int j = 0; j < r.votos.size(); j++) {
                    if (j > 0)
                        sb.append(", ");
                    sb.append(r.votos.get(j).juez).append(": ").append(r.votos.get(j).estrellas);
                }
                String desgloseVotos = sb.toString();

                String promStr = String.format(java.util.Locale.US, "%.2f / 3.00", r.promedio);
                String sumaStr = r.suma + " pts";

                String obraStr = r.obra.length() > 24 ? r.obra.substring(0, 21) + "..." : r.obra;
                String autorStr = r.autor.length() > 18 ? r.autor.substring(0, 15) + "..." : r.autor;

                System.out.printf("| %-5s | %-24s | %-18s | %-28s | %-6s | %-13s | %-15s |%n",
                        "#" + r.lugar, obraStr, autorStr, desgloseVotos, sumaStr, promStr, estado);
            }

            System.out.println(sep);
            if (!ranking.isEmpty()) {
                ResumenClasificacionObra ganador = ranking.get(0);
                System.out.printf(
                        " [GANADOR - 1er LUGAR] Obra: '%s' | Autor: %s | Promedio: %.2f / 3.00 (Suma: %d pts)%n",
                        ganador.obra, ganador.autor, ganador.promedio, ganador.suma);
                if (ranking.size() > 1) {
                    ResumenClasificacionObra ultimo = ranking.get(ranking.size() - 1);
                    System.out.printf(
                            " [ULTIMO PUESTO]      Obra: '%s' | Autor: %s | Promedio: %.2f / 3.00 (Suma: %d pts)%n",
                            ultimo.obra, ultimo.autor, ultimo.promedio, ultimo.suma);
                }
            }
            System.out.println("-".repeat(sep.length()));
            System.out.println(" [OK] Todos los votos fueron validados criptograficamente mediante Chaum RSA");
            System.out.println("      con la llave publica del Presidente (" + pathPubPresidente + ").");
            System.out.println(borde + "\n");

            return true;

        } catch (Exception e) {
            System.out.println("\n[!] Error al verificar y mostrar los resultados: " + e.getMessage());
            mostrarImagenVotoVulnerado();
            return false;
        }
    }

    /**
     * Devuelve el ranking calculado de las obras evaluadas.
     */
    public List<ResumenClasificacionObra> obtenerRankingObras() {
        if (!(motorAnonimato instanceof ModuloAnonimatoRSA moduloRSA)) {
            return Collections.emptyList();
        }

        try {
            Path pathPubPresidente = Paths.get("claves_usuario", "presidente", "presidente_RSA_pub.txt");
            if (!Files.exists(pathPubPresidente)) {
                return Collections.emptyList();
            }
            RSAPublicKey pubPresidente = moduloRSA.cargarLlavePublica(pathPubPresidente);

            List<Path> archivosDescegados = new ArrayList<>();
            Path dirCalificaciones = Paths.get("calificaciones_jueces");
            if (Files.exists(dirCalificaciones)) {
                try (Stream<Path> st = Files.list(dirCalificaciones)) {
                    st.filter(p -> {
                        String fn = p.getFileName().toString().toLowerCase();
                        return fn.endsWith(".txt") && fn.contains("_descegado_");
                    }).forEach(archivosDescegados::add);
                }
            }

            Map<String, ResumenClasificacionObra> obrasMap = new LinkedHashMap<>();

            for (Path pathDescegado : archivosDescegados) {
                String fn = pathDescegado.getFileName().toString();
                String[] parsed = extraerJuezYAutorDeNombreDescegado(fn);
                String nombreJuez = (parsed != null) ? parsed[0] : "juez1";
                String autorObra = (parsed != null) ? parsed[1] : "autor";

                String firmaB64 = Files.readString(pathDescegado, StandardCharsets.UTF_8).trim();
                byte[] firmaDescegada = Base64.getDecoder().decode(firmaB64);
                byte[] datosOriginales = obtenerDatosVotoOriginal(nombreJuez, autorObra);

                if (!moduloRSA.verificarFirmaRSA(datosOriginales, firmaDescegada, pubPresidente)) {
                    return Collections.emptyList();
                }

                Path pathActa = encontrarActa(nombreJuez, autorObra);
                ResultadoObraItem item = parsearObraYCalificacion(pathActa, nombreJuez, autorObra);
                String clave = (item.obra + "___" + item.autor).toLowerCase();
                ResumenClasificacionObra resumen = obrasMap.computeIfAbsent(clave,
                        k -> new ResumenClasificacionObra(item.obra, item.autor));
                resumen.agregarVoto(item.juez, item.estrellasNum);
            }

            List<ResumenClasificacionObra> ranking = new ArrayList<>(obrasMap.values());
            ranking.sort((a, b) -> {
                int cmp = Double.compare(b.promedio, a.promedio);
                if (cmp != 0) {
                    return cmp;
                }
                return Integer.compare(b.suma, a.suma);
            });

            for (int i = 0; i < ranking.size(); i++) {
                ranking.get(i).lugar = (i + 1);
            }
            return ranking;

        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    /**
     * Realiza el flujo completo de evaluación y firma por los 3 jueces para una
     * misma imagen:
     * - Juez 1, Juez 2 y Juez 3 evalúan la imagen y registran sus calificaciones.
     * - Cada juez ciega su voto con la llave pública del presidente.
     * - El presidente firma cada voto cegado.
     * - Cada juez descega su firma recibida del presidente.
     *
     * @param nombreObra Nombre de la obra evaluada
     * @param autorObra  Nombre del autor de la obra
     * @param votos      Arreglo con las calificaciones de los 3 jueces (1 a 3
     *                   estrellas)
     * @return true si los 3 jueces completaron exitosamente su ciclo
     */
    public boolean evaluarObraPorTresJueces(String nombreObra, String autorObra, int[] votos) {
        if (votos == null || votos.length < 3) {
            throw new IllegalArgumentException("Se requieren las calificaciones de los 3 jueces.");
        }

        String[] nombresJueces = { "juez1", "juez2", "juez3" };
        System.out.println("\n==============================================================");
        System.out.println(" EVALUACIÓN DE OBRA POR LOS 3 JUECES (CONCURSO DE PINTURA)");
        System.out.println("==============================================================");
        System.out.println("Obra a evaluar:        " + nombreObra);
        System.out.println("Autor / Pintor:        " + autorObra);
        System.out.println("Jueces asignados:      juez1, juez2, juez3");
        System.out.println("Calificaciones dadas:  [" + votos[0] + ", " + votos[1] + ", " + votos[2] + "]");
        System.out.println("--------------------------------------------------------------");

        try {
            Usuario presi = new Usuario("presi-id", "presidente", RolUsuario.PRESIDENTE);
            inicializarOGenerarLlavesRSAPresidente(presi);

            for (int i = 0; i < 3; i++) {
                String juez = nombresJueces[i];
                int est = Math.max(1, Math.min(3, votos[i]));
                String com = "Evaluación emitida por " + juez;

                System.out.println(
                        "\n--- [PASO " + (i + 1) + "/3] Juez " + juez + " emite calificacion (" + est + "/3) ---");

                // 1. Juez registra acta
                registrarVeredictoJuez(juez, nombreObra, autorObra, est, com);

                // 2. Juez ciega su voto
                Path pathCegado = cegarCalificacionJuez(juez, autorObra);
                if (pathCegado == null) {
                    System.out.println("[!] Fallo al cegar el voto de " + juez);
                    return false;
                }

                // 3. Presidente firma el voto cegado
                Path pathFirmaPresi = firmarVotoCegadoPresidente(presi, juez, autorObra);
                if (pathFirmaPresi == null) {
                    System.out.println("[!] Fallo al firmar el voto cegado de " + juez);
                    return false;
                }

                // 4. Juez descega la firma
                Path pathDescegado = descegarFirmaJuez(juez, autorObra);
                if (pathDescegado == null) {
                    System.out.println("[!] Fallo al descegar la firma de " + juez);
                    return false;
                }
            }

            System.out.println("\n==============================================================");
            System.out.println(" [OK] Los 3 jueces han firmado y descegado sus votos para: " + nombreObra);
            System.out.println("==============================================================\n");
            return true;

        } catch (Exception e) {
            System.out.println("[!] Error durante la evaluación de los 3 jueces: " + e.getMessage());
            return false;
        }
    }

    /**
     * Muestra la alerta visual e imagen física indicando que el voto fue vulnerado.
     */
    public void mostrarImagenVotoVulnerado() {
        // 1. Mostrar banner e imagen ASCII en consola
        System.out.println("\n");
        System.out.println("  +---------------------------------------------------------------+");
        System.out.println("  |                 [!] ALERTA CRIPTOGRAFICA                      |");
        System.out.println("  |             EL VOTO HA SIDO VULNERADO / ALTERADO              |");
        System.out.println("  |---------------------------------------------------------------|");
        System.out.println("  |  [!] La firma digital RSA del Presidente NO coincide.         |");
        System.out.println("  |  [!] Por directiva de seguridad, NO se muestra ningun dato.   |");
        System.out.println("  +---------------------------------------------------------------+\n");

        // 2. Generar archivo de imagen físico en 'imagenes/voto_vulnerado.png'
        try {
            Path dirImagenes = Paths.get("imagenes");
            Files.createDirectories(dirImagenes);
            Path pathImagen = dirImagenes.resolve("voto_vulnerado.png");

            int width = 720;
            int height = 360;
            BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
            Graphics2D g2d = img.createGraphics();

            // Fondo oscuro con borde rojo de advertencia
            g2d.setColor(new Color(24, 24, 27));
            g2d.fillRect(0, 0, width, height);

            g2d.setColor(new Color(220, 38, 38));
            g2d.setStroke(new BasicStroke(6));
            g2d.drawRect(10, 10, width - 20, height - 20);

            // Icono / Encabezado
            g2d.setColor(new Color(239, 68, 68));
            g2d.setFont(new Font("Arial", Font.BOLD, 30));
            g2d.drawString("[!] ALERTA: VOTO VULNERADO [!]", 140, 70);

            g2d.setColor(Color.WHITE);
            g2d.setFont(new Font("Arial", Font.BOLD, 17));
            g2d.drawString("FALLA DE INTEGRIDAD CRIPTOGRAFICA (CHAUM RSA)", 115, 125);

            g2d.setFont(new Font("Arial", Font.PLAIN, 15));
            g2d.drawString("• ModuloAnonimatoRSA.verificarFirmaRSA(...) retorno: FALSE", 110, 175);
            g2d.drawString("• El contenido del voto o la firma sufrieron alteraciones.", 110, 215);
            g2d.drawString("• Por directiva de seguridad, ningun resultado sera mostrado.", 110, 255);

            g2d.setColor(new Color(220, 38, 38));
            g2d.setFont(new Font("Arial", Font.BOLD, 14));
            g2d.drawString("SISTEMA DE CONCURSO DE PINTURA - ELECCIONES SEGURAS", 135, 310);

            g2d.dispose();
            ImageIO.write(img, "png", pathImagen.toFile());

            // Abrir imagen en el visor del sistema si no es headless
            try {
                if (!GraphicsEnvironment.isHeadless() && Desktop.isDesktopSupported()) {
                    Desktop desktop = Desktop.getDesktop();
                    if (desktop.isSupported(Desktop.Action.OPEN)) {
                        desktop.open(pathImagen.toFile());
                    }
                }
            } catch (Exception ex) {
                try {
                    new ProcessBuilder("cmd", "/c", "start", "", pathImagen.toAbsolutePath().toString()).start();
                } catch (Exception ignored) {
                }
            }
        } catch (Exception e) {
            System.out.println("[!] Nota: No se pudo generar la imagen gráfica física: " + e.getMessage());
        }
    }

    /**
     * Extrae el juez y el autor a partir del nombre del archivo descegado:
     * "NombreJuez_descegado_autorObra.txt" -> [NombreJuez, autorObra].
     */
    public String[] extraerJuezYAutorDeNombreDescegado(String fileName) {
        String base = fileName.toLowerCase().endsWith(".txt")
                ? fileName.substring(0, fileName.length() - 4)
                : fileName;
        int idx = base.indexOf("_descegado_");
        if (idx > 0) {
            String juez = base.substring(0, idx);
            String autor = base.substring(idx + "_descegado_".length());
            return new String[] { juez, autor };
        }
        return null;
    }

    /**
     * Localiza el acta de calificación correspondiente al juez y autor.
     */
    public Path encontrarActa(String nombreJuez, String autorObra) {
        Path dirCalificaciones = Paths.get("calificaciones_jueces");
        if (!Files.exists(dirCalificaciones)) {
            return null;
        }
        try (Stream<Path> st = Files.list(dirCalificaciones)) {
            return st.filter(p -> {
                String fn = p.getFileName().toString().toLowerCase();
                return fn.startsWith(nombreJuez.toLowerCase() + "_acta_")
                        && fn.endsWith("_" + autorObra.toLowerCase() + ".txt");
            }).findFirst().orElse(null);
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Extrae la obra y calificación a partir del acta, SIN extraer ni mostrar el
     * comentario.
     */
    public ResultadoObraItem parsearObraYCalificacion(Path pathActa, String nombreJuez, String autorObra) {
        String obra = "Desconocida";
        String autor = autorObra;
        String juez = nombreJuez;
        int estrellasNum = 3;
        String calificacion = "3 estrellas";

        if (pathActa != null && Files.exists(pathActa)) {
            try {
                List<String> lineas = Files.readAllLines(pathActa, StandardCharsets.UTF_8);
                for (String l : lineas) {
                    String linea = l.trim();
                    if (linea.toLowerCase().startsWith("obra evaluada:")) {
                        obra = linea.substring("obra evaluada:".length()).trim();
                    } else if (linea.toLowerCase().startsWith("autor / pintor:")
                            || linea.toLowerCase().startsWith("autor:")) {
                        autor = linea.substring(linea.indexOf(":") + 1).trim();
                    } else if (linea.toLowerCase().startsWith("juez evaluador:")
                            || linea.toLowerCase().startsWith("juez:")) {
                        juez = linea.substring(linea.indexOf(":") + 1).trim();
                    } else if (linea.toLowerCase().startsWith("estrellas:")) {
                        String numStr = linea.substring("estrellas:".length()).trim();
                        try {
                            int n = Integer.parseInt(numStr);
                            estrellasNum = Math.max(1, Math.min(3, n));
                            calificacion = n + " estrellas";
                        } catch (Exception ex) {
                            calificacion = numStr + " estrellas";
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }

        if ("Desconocida".equals(obra)) {
            Path dirImg = Paths.get("imagenes");
            if (Files.exists(dirImg)) {
                try (Stream<Path> st = Files.list(dirImg)) {
                    Path img = st
                            .filter(p -> p.getFileName().toString().toLowerCase().contains(autorObra.toLowerCase()))
                            .findFirst().orElse(null);
                    if (img != null) {
                        obra = extraerNombreBaseObra(img.getFileName().toString());
                    }
                } catch (Exception ignored) {
                }
            }
        }

        return new ResultadoObraItem(obra, autor, juez, estrellasNum, calificacion);
    }
}
