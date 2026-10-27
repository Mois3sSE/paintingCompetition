package com.paintingcompetition;

import com.paintingcompetition.domain.ports.out.MotorCriptograficoPort;
import com.paintingcompetition.infrastructure.adapters.in.console.MenuPrincipalConsola;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloAnonimatoRSA;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloConfidencialidadAES;
import com.paintingcompetition.infrastructure.adapters.out.crypto.ModuloRegistroECDSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Main {

    public static void main(String[] args) {
        // Registro del proveedor de seguridad Bouncy Castle
        Security.addProvider(new BouncyCastleProvider());

        // Inyección de dependencias de los Adaptadores de Salida (Cajas Negras de los 3
        // Integrantes)
        MotorCriptograficoPort motorAES = new ModuloConfidencialidadAES();
        MotorCriptograficoPort motorECDSA = new ModuloRegistroECDSA();
        MotorCriptograficoPort motorRSA = new ModuloAnonimatoRSA();

        // Inicialización del Adaptador de Entrada (Consola)
        MenuPrincipalConsola menu = new MenuPrincipalConsola(motorAES, motorECDSA, motorRSA);
        menu.iniciar();
    }
}
