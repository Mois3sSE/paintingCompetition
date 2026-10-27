package com.paintingcompetition.domain.ports.out;

import java.security.KeyPair;

public interface GestorLlavesPort {

    KeyPair generarParLlaves();

    KeyPair generarParLlaves(int longitudBits);
}
