package lu.incert.ocsp.signing.pkcs11;

import java.util.Map;

/**
 * Standard OASIS PKCS#11 v2.40 Cryptoki constants.
 */
public final class Pkcs11Constants {

    private Pkcs11Constants() {}

    // Initialize flags
    public static final long CKF_LIBRARY_CANT_CREATE_OS_THREADS = 0x00000001L;
    public static final long CKF_OS_LOCKING_OK                  = 0x00000002L;

    // Session flags
    public static final long CKF_RW_SESSION     = 0x00000002L;
    public static final long CKF_SERIAL_SESSION = 0x00000004L;

    // Token flags
    public static final long CKF_TOKEN_INITIALIZED = 0x00000400L;

    // User types
    public static final long CKU_SO               = 0L;
    public static final long CKU_USER             = 1L;
    public static final long CKU_CONTEXT_SPECIFIC = 2L;

    // Object classes
    public static final long CKO_DATA        = 0x00000000L;
    public static final long CKO_CERTIFICATE = 0x00000001L;
    public static final long CKO_PUBLIC_KEY  = 0x00000002L;
    public static final long CKO_PRIVATE_KEY = 0x00000003L;
    public static final long CKO_SECRET_KEY  = 0x00000004L;

    // Key types
    public static final long CKK_RSA = 0x00000000L;
    public static final long CKK_EC  = 0x00000003L;

    // Certificate types
    public static final long CKC_X_509 = 0x00000000L;

    // Attributes
    public static final long CKA_CLASS            = 0x00000000L;
    public static final long CKA_TOKEN            = 0x00000001L;
    public static final long CKA_PRIVATE          = 0x00000002L;
    public static final long CKA_LABEL            = 0x00000003L;
    public static final long CKA_VALUE            = 0x00000011L;
    public static final long CKA_CERTIFICATE_TYPE = 0x00000080L;
    public static final long CKA_KEY_TYPE         = 0x00000100L;
    public static final long CKA_SUBJECT          = 0x00000101L;
    public static final long CKA_ID               = 0x00000102L;
    public static final long CKA_SENSITIVE        = 0x00000103L;
    public static final long CKA_ENCRYPT          = 0x00000104L;
    public static final long CKA_DECRYPT          = 0x00000105L;
    public static final long CKA_SIGN             = 0x00000108L;
    public static final long CKA_VERIFY           = 0x0000010AL;
    public static final long CKA_MODULUS          = 0x00000120L;
    public static final long CKA_MODULUS_BITS     = 0x00000121L;
    public static final long CKA_PUBLIC_EXPONENT  = 0x00000122L;
    public static final long CKA_EXTRACTABLE      = 0x00000162L;
    public static final long CKA_EC_PARAMS        = 0x00000180L;
    public static final long CKA_EC_POINT         = 0x00000181L;

    // Mechanisms
    public static final long CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000L;
    public static final long CKM_RSA_PKCS              = 0x00000001L;
    public static final long CKM_RSA_PKCS_PSS          = 0x0000000DL;
    public static final long CKM_SHA256_RSA_PKCS       = 0x00000040L;
    public static final long CKM_SHA384_RSA_PKCS       = 0x00000041L;
    public static final long CKM_SHA512_RSA_PKCS       = 0x00000042L;
    public static final long CKM_SHA256_RSA_PKCS_PSS   = 0x00000043L;
    public static final long CKM_SHA384_RSA_PKCS_PSS   = 0x00000044L;
    public static final long CKM_SHA512_RSA_PKCS_PSS   = 0x00000045L;
    public static final long CKM_SHA256                = 0x00000250L;
    public static final long CKM_SHA384                = 0x00000260L;
    public static final long CKM_SHA512                = 0x00000270L;
    public static final long CKM_EC_KEY_PAIR_GEN       = 0x00001040L;
    public static final long CKM_ECDSA                 = 0x00001041L;

    // MGF
    public static final long CKG_MGF1_SHA1   = 0x00000001L;
    public static final long CKG_MGF1_SHA256 = 0x00000002L;
    public static final long CKG_MGF1_SHA384 = 0x00000003L;
    public static final long CKG_MGF1_SHA512 = 0x00000004L;

    // Return values
    public static final long CKR_OK                           = 0x00000000L;
    public static final long CKR_SLOT_ID_INVALID              = 0x00000003L;
    public static final long CKR_GENERAL_ERROR                = 0x00000005L;
    public static final long CKR_FUNCTION_FAILED              = 0x00000006L;
    public static final long CKR_ARGUMENTS_BAD                = 0x00000007L;
    public static final long CKR_ATTRIBUTE_SENSITIVE          = 0x00000011L;
    public static final long CKR_ATTRIBUTE_TYPE_INVALID       = 0x00000012L;
    public static final long CKR_ATTRIBUTE_VALUE_INVALID      = 0x00000013L;
    public static final long CKR_DEVICE_ERROR                 = 0x00000030L;
    public static final long CKR_DEVICE_MEMORY                = 0x00000031L;
    public static final long CKR_DEVICE_REMOVED               = 0x00000032L;
    public static final long CKR_KEY_HANDLE_INVALID           = 0x00000060L;
    public static final long CKR_KEY_SIZE_RANGE               = 0x00000062L;
    public static final long CKR_KEY_TYPE_INCONSISTENT        = 0x00000063L;
    public static final long CKR_MECHANISM_INVALID            = 0x00000070L;
    public static final long CKR_OBJECT_HANDLE_INVALID        = 0x00000082L;
    public static final long CKR_OPERATION_ACTIVE             = 0x00000090L;
    public static final long CKR_PIN_INCORRECT                = 0x000000A0L;
    public static final long CKR_PIN_LOCKED                   = 0x000000A4L;
    public static final long CKR_SESSION_HANDLE_INVALID       = 0x000000B3L;
    public static final long CKR_SESSION_READ_ONLY            = 0x000000B5L;
    public static final long CKR_TEMPLATE_INCOMPLETE          = 0x000000D0L;
    public static final long CKR_TEMPLATE_INCONSISTENT        = 0x000000D1L;
    public static final long CKR_TOKEN_NOT_PRESENT            = 0x000000E0L;
    public static final long CKR_USER_ALREADY_LOGGED_IN       = 0x00000100L;
    public static final long CKR_USER_NOT_LOGGED_IN           = 0x00000101L;
    public static final long CKR_CRYPTOKI_NOT_INITIALIZED     = 0x00000190L;
    public static final long CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191L;

    private static final Map<Long, String> ERROR_NAMES = Map.ofEntries(
            Map.entry(CKR_OK, "CKR_OK"),
            Map.entry(CKR_SLOT_ID_INVALID, "CKR_SLOT_ID_INVALID"),
            Map.entry(CKR_GENERAL_ERROR, "CKR_GENERAL_ERROR"),
            Map.entry(CKR_FUNCTION_FAILED, "CKR_FUNCTION_FAILED"),
            Map.entry(CKR_ARGUMENTS_BAD, "CKR_ARGUMENTS_BAD"),
            Map.entry(CKR_ATTRIBUTE_SENSITIVE, "CKR_ATTRIBUTE_SENSITIVE"),
            Map.entry(CKR_ATTRIBUTE_TYPE_INVALID, "CKR_ATTRIBUTE_TYPE_INVALID"),
            Map.entry(CKR_ATTRIBUTE_VALUE_INVALID, "CKR_ATTRIBUTE_VALUE_INVALID"),
            Map.entry(CKR_DEVICE_ERROR, "CKR_DEVICE_ERROR"),
            Map.entry(CKR_DEVICE_MEMORY, "CKR_DEVICE_MEMORY"),
            Map.entry(CKR_DEVICE_REMOVED, "CKR_DEVICE_REMOVED"),
            Map.entry(CKR_KEY_HANDLE_INVALID, "CKR_KEY_HANDLE_INVALID"),
            Map.entry(CKR_KEY_SIZE_RANGE, "CKR_KEY_SIZE_RANGE"),
            Map.entry(CKR_KEY_TYPE_INCONSISTENT, "CKR_KEY_TYPE_INCONSISTENT"),
            Map.entry(CKR_MECHANISM_INVALID, "CKR_MECHANISM_INVALID"),
            Map.entry(CKR_OBJECT_HANDLE_INVALID, "CKR_OBJECT_HANDLE_INVALID"),
            Map.entry(CKR_OPERATION_ACTIVE, "CKR_OPERATION_ACTIVE"),
            Map.entry(CKR_PIN_INCORRECT, "CKR_PIN_INCORRECT"),
            Map.entry(CKR_PIN_LOCKED, "CKR_PIN_LOCKED"),
            Map.entry(CKR_SESSION_HANDLE_INVALID, "CKR_SESSION_HANDLE_INVALID"),
            Map.entry(CKR_SESSION_READ_ONLY, "CKR_SESSION_READ_ONLY"),
            Map.entry(CKR_TEMPLATE_INCOMPLETE, "CKR_TEMPLATE_INCOMPLETE"),
            Map.entry(CKR_TEMPLATE_INCONSISTENT, "CKR_TEMPLATE_INCONSISTENT"),
            Map.entry(CKR_TOKEN_NOT_PRESENT, "CKR_TOKEN_NOT_PRESENT"),
            Map.entry(CKR_USER_ALREADY_LOGGED_IN, "CKR_USER_ALREADY_LOGGED_IN"),
            Map.entry(CKR_USER_NOT_LOGGED_IN, "CKR_USER_NOT_LOGGED_IN"),
            Map.entry(CKR_CRYPTOKI_NOT_INITIALIZED, "CKR_CRYPTOKI_NOT_INITIALIZED"),
            Map.entry(CKR_CRYPTOKI_ALREADY_INITIALIZED, "CKR_CRYPTOKI_ALREADY_INITIALIZED")
    );

    public static String errorName(long rv) {
        return ERROR_NAMES.getOrDefault(rv, String.format("0x%08x", rv));
    }
}

