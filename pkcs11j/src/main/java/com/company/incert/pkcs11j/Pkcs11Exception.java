package com.company.incert.pkcs11j;

/**
 * Runtime exception raised when a Cryptoki native C_* call returns a non-zero CK_RV.
 */
public class Pkcs11Exception extends RuntimeException {

    private final long errorCode;
    private final String functionName;

    public Pkcs11Exception(String functionName, long errorCode) {
        super(String.format("%s failed with %s (0x%08x)",
                functionName, Pkcs11Constants.errorName(errorCode), errorCode));
        this.functionName = functionName;
        this.errorCode = errorCode;
    }

    public Pkcs11Exception(String message, Throwable cause) {
        super(message, cause);
        this.functionName = "PKCS#11";
        this.errorCode = Pkcs11Constants.CKR_GENERAL_ERROR;
    }

    public long getErrorCode() {
        return errorCode;
    }

    public String getFunctionName() {
        return functionName;
    }

    public boolean isSessionInvalid() {
        return errorCode == Pkcs11Constants.CKR_SESSION_HANDLE_INVALID
                || errorCode == Pkcs11Constants.CKR_DEVICE_ERROR;
    }

    public boolean isNotLoggedIn() {
        return errorCode == Pkcs11Constants.CKR_USER_NOT_LOGGED_IN;
    }
}

