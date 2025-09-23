package com.bsep.pki_system.exceptions;

public class CertificateGenerationException extends RuntimeException {
    public CertificateGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}