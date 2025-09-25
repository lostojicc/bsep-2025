package com.bsep.pki_system.model;

public enum KeyUsageType {
    DIGITAL_SIGNATURE,
    NON_REPUDIATION,
    KEY_ENCIPHERMENT,
    DATA_ENCIPHERMENT,
    KEY_AGREEMENT,
    KEY_CERT_SIGN,
    CRL_SIGN,
    ENCIPHER_ONLY,
    DECIPHER_ONLY
}
