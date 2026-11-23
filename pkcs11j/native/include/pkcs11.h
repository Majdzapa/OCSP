#ifndef PKCS11J_PKCS11_H
#define PKCS11J_PKCS11_H

/*
 * Self-contained OASIS PKCS#11 v2.40 Cryptoki C header for pkcs11j JNI bridge.
 * Natural C alignment is used on Unix/Linux/macOS; 1-byte packing is used only on Win32.
 */

#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#else
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#endif

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char     CK_BYTE;
typedef CK_BYTE           CK_CHAR;
typedef CK_BYTE           CK_UTF8CHAR;
typedef CK_BYTE           CK_BBOOL;
typedef unsigned long int CK_ULONG;
typedef long int          CK_LONG;
typedef CK_ULONG          CK_FLAGS;

typedef CK_BYTE     CK_PTR CK_BYTE_PTR;
typedef CK_CHAR     CK_PTR CK_CHAR_PTR;
typedef CK_UTF8CHAR CK_PTR CK_UTF8CHAR_PTR;
typedef CK_ULONG    CK_PTR CK_ULONG_PTR;
typedef void        CK_PTR CK_VOID_PTR;
typedef CK_VOID_PTR CK_PTR CK_VOID_PTR_PTR;

#define CK_TRUE  1
#define CK_FALSE 0

#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_EFFECTIVELY_INFINITE    0UL
#define CK_INVALID_HANDLE          0UL

typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;
typedef CK_VERSION CK_PTR CK_VERSION_PTR;

typedef struct CK_INFO {
    CK_VERSION  cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS    flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION  libraryVersion;
} CK_INFO;
typedef CK_INFO CK_PTR CK_INFO_PTR;

typedef CK_ULONG CK_NOTIFICATION;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_SLOT_ID CK_PTR CK_SLOT_ID_PTR;

typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS    flags;
    CK_VERSION  hardwareVersion;
    CK_VERSION  firmwareVersion;
} CK_SLOT_INFO;
typedef CK_SLOT_INFO CK_PTR CK_SLOT_INFO_PTR;

#define CKF_TOKEN_PRESENT     0x00000001UL
#define CKF_REMOVABLE_DEVICE  0x00000002UL
#define CKF_HW_SLOT           0x00000004UL

typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_CHAR     serialNumber[16];
    CK_FLAGS    flags;
    CK_ULONG    ulMaxSessionCount;
    CK_ULONG    ulSessionCount;
    CK_ULONG    ulMaxRwSessionCount;
    CK_ULONG    ulRwSessionCount;
    CK_ULONG    ulMaxPinLen;
    CK_ULONG    ulMinPinLen;
    CK_ULONG    ulTotalPublicMemory;
    CK_ULONG    ulFreePublicMemory;
    CK_ULONG    ulTotalPrivateMemory;
    CK_ULONG    ulFreePrivateMemory;
    CK_VERSION  hardwareVersion;
    CK_VERSION  firmwareVersion;
    CK_CHAR     utcTime[16];
} CK_TOKEN_INFO;
typedef CK_TOKEN_INFO CK_PTR CK_TOKEN_INFO_PTR;

typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE CK_PTR CK_SESSION_HANDLE_PTR;

typedef CK_ULONG CK_USER_TYPE;
#define CKU_SO               0UL
#define CKU_USER             1UL
#define CKU_CONTEXT_SPECIFIC 2UL

typedef CK_ULONG CK_STATE;

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;
    CK_STATE   state;
    CK_FLAGS   flags;
    CK_ULONG   ulDeviceError;
} CK_SESSION_INFO;
typedef CK_SESSION_INFO CK_PTR CK_SESSION_INFO_PTR;

#define CKF_RW_SESSION     0x00000002UL
#define CKF_SERIAL_SESSION 0x00000004UL

typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE CK_PTR CK_OBJECT_HANDLE_PTR;

typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_OBJECT_CLASS CK_PTR CK_OBJECT_CLASS_PTR;

#define CKO_DATA        0x00000000UL
#define CKO_CERTIFICATE 0x00000001UL
#define CKO_PUBLIC_KEY  0x00000002UL
#define CKO_PRIVATE_KEY 0x00000003UL
#define CKO_SECRET_KEY  0x00000004UL

typedef CK_ULONG CK_KEY_TYPE;
#define CKK_RSA 0x00000000UL
#define CKK_EC  0x00000003UL

typedef CK_ULONG CK_CERTIFICATE_TYPE;
#define CKC_X_509 0x00000000UL

typedef CK_ULONG CK_ATTRIBUTE_TYPE;
#define CKA_CLASS              0x00000000UL
#define CKA_TOKEN              0x00000001UL
#define CKA_PRIVATE            0x00000002UL
#define CKA_LABEL              0x00000003UL
#define CKA_VALUE              0x00000011UL
#define CKA_CERTIFICATE_TYPE   0x00000080UL
#define CKA_KEY_TYPE           0x00000100UL
#define CKA_SUBJECT            0x00000101UL
#define CKA_ID                 0x00000102UL
#define CKA_SENSITIVE          0x00000103UL
#define CKA_ENCRYPT            0x00000104UL
#define CKA_DECRYPT            0x00000105UL
#define CKA_SIGN               0x00000108UL
#define CKA_VERIFY             0x0000010AUL
#define CKA_MODULUS            0x00000120UL
#define CKA_MODULUS_BITS       0x00000121UL
#define CKA_PUBLIC_EXPONENT    0x00000122UL
#define CKA_EXTRACTABLE        0x00000162UL
#define CKA_EC_PARAMS          0x00000180UL
#define CKA_EC_POINT           0x00000181UL

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR       pValue;
    CK_ULONG          ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE CK_PTR CK_ATTRIBUTE_PTR;

typedef struct CK_DATE {
    CK_CHAR year[4];
    CK_CHAR month[2];
    CK_CHAR day[2];
} CK_DATE;

typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_MECHANISM_TYPE CK_PTR CK_MECHANISM_TYPE_PTR;

#define CKM_RSA_PKCS_KEY_PAIR_GEN  0x00000000UL
#define CKM_RSA_PKCS               0x00000001UL
#define CKM_RSA_PKCS_PSS           0x0000000DUL
#define CKM_SHA256_RSA_PKCS        0x00000040UL
#define CKM_SHA384_RSA_PKCS        0x00000041UL
#define CKM_SHA512_RSA_PKCS        0x00000042UL
#define CKM_SHA256_RSA_PKCS_PSS    0x00000043UL
#define CKM_SHA384_RSA_PKCS_PSS    0x00000044UL
#define CKM_SHA512_RSA_PKCS_PSS    0x00000045UL
#define CKM_SHA256                 0x00000250UL
#define CKM_SHA384                 0x00000260UL
#define CKM_SHA512                 0x00000270UL
#define CKM_EC_KEY_PAIR_GEN        0x00001040UL
#define CKM_ECDSA                  0x00001041UL

#define CKG_MGF1_SHA1              0x00000001UL
#define CKG_MGF1_SHA256            0x00000002UL
#define CKG_MGF1_SHA384            0x00000003UL
#define CKG_MGF1_SHA512            0x00000004UL

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR       pParameter;
    CK_ULONG          ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM CK_PTR CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO CK_PTR CK_MECHANISM_INFO_PTR;

typedef struct CK_RSA_PKCS_PSS_PARAMS {
    CK_MECHANISM_TYPE hashAlg;
    CK_ULONG          mgf;
    CK_ULONG          sLen;
} CK_RSA_PKCS_PSS_PARAMS;

typedef CK_ULONG CK_RV;

#define CKR_OK                          0x00000000UL
#define CKR_GENERAL_ERROR               0x00000005UL
#define CKR_ATTRIBUTE_SENSITIVE         0x00000011UL
#define CKR_ATTRIBUTE_TYPE_INVALID      0x00000012UL
#define CKR_DEVICE_ERROR                0x00000030UL
#define CKR_PIN_INCORRECT               0x000000A0UL
#define CKR_SESSION_HANDLE_INVALID      0x000000B3UL
#define CKR_USER_ALREADY_LOGGED_IN      0x00000100UL
#define CKR_USER_NOT_LOGGED_IN          0x00000101UL
#define CKR_CRYPTOKI_NOT_INITIALIZED    0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_NOTIFY)(
    CK_SESSION_HANDLE hSession,
    CK_NOTIFICATION   event,
    CK_VOID_PTR       pApplication
);

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_CREATEMUTEX)(CK_VOID_PTR_PTR ppMutex);
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_DESTROYMUTEX)(CK_VOID_PTR pMutex);
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_LOCKMUTEX)(CK_VOID_PTR pMutex);
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_UNLOCKMUTEX)(CK_VOID_PTR pMutex);

typedef struct CK_C_INITIALIZE_ARGS {
    CK_CREATEMUTEX  CreateMutex;
    CK_DESTROYMUTEX DestroyMutex;
    CK_LOCKMUTEX    LockMutex;
    CK_UNLOCKMUTEX  UnlockMutex;
    CK_FLAGS        flags;
    CK_VOID_PTR     pReserved;
} CK_C_INITIALIZE_ARGS;
typedef CK_C_INITIALIZE_ARGS CK_PTR CK_C_INITIALIZE_ARGS_PTR;

#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001UL
#define CKF_OS_LOCKING_OK                  0x00000002UL

struct CK_FUNCTION_LIST;
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_Initialize)(CK_VOID_PTR pInitArgs);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetInfo)(CK_INFO_PTR pInfo);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_CloseAllSessions)(CK_SLOT_ID slotID);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_Logout)(CK_SESSION_HANDLE hSession);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_CancelFunction)(CK_SESSION_HANDLE hSession);
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_C_Initialize C_Initialize;
    CK_C_Finalize C_Finalize;
    CK_C_GetInfo C_GetInfo;
    CK_C_GetFunctionList C_GetFunctionList;
    CK_C_GetSlotList C_GetSlotList;
    CK_C_GetSlotInfo C_GetSlotInfo;
    CK_C_GetTokenInfo C_GetTokenInfo;
    CK_C_GetMechanismList C_GetMechanismList;
    CK_C_GetMechanismInfo C_GetMechanismInfo;
    CK_C_InitToken C_InitToken;
    CK_C_InitPIN C_InitPIN;
    CK_C_SetPIN C_SetPIN;
    CK_C_OpenSession C_OpenSession;
    CK_C_CloseSession C_CloseSession;
    CK_C_CloseAllSessions C_CloseAllSessions;
    CK_C_GetSessionInfo C_GetSessionInfo;
    CK_C_GetOperationState C_GetOperationState;
    CK_C_SetOperationState C_SetOperationState;
    CK_C_Login C_Login;
    CK_C_Logout C_Logout;
    CK_C_CreateObject C_CreateObject;
    CK_C_CopyObject C_CopyObject;
    CK_C_DestroyObject C_DestroyObject;
    CK_C_GetObjectSize C_GetObjectSize;
    CK_C_GetAttributeValue C_GetAttributeValue;
    CK_C_SetAttributeValue C_SetAttributeValue;
    CK_C_FindObjectsInit C_FindObjectsInit;
    CK_C_FindObjects C_FindObjects;
    CK_C_FindObjectsFinal C_FindObjectsFinal;
    CK_C_EncryptInit C_EncryptInit;
    CK_C_Encrypt C_Encrypt;
    CK_C_EncryptUpdate C_EncryptUpdate;
    CK_C_EncryptFinal C_EncryptFinal;
    CK_C_DecryptInit C_DecryptInit;
    CK_C_Decrypt C_Decrypt;
    CK_C_DecryptUpdate C_DecryptUpdate;
    CK_C_DecryptFinal C_DecryptFinal;
    CK_C_DigestInit C_DigestInit;
    CK_C_Digest C_Digest;
    CK_C_DigestUpdate C_DigestUpdate;
    CK_C_DigestKey C_DigestKey;
    CK_C_DigestFinal C_DigestFinal;
    CK_C_SignInit C_SignInit;
    CK_C_Sign C_Sign;
    CK_C_SignUpdate C_SignUpdate;
    CK_C_SignFinal C_SignFinal;
    CK_C_SignRecoverInit C_SignRecoverInit;
    CK_C_SignRecover C_SignRecover;
    CK_C_VerifyInit C_VerifyInit;
    CK_C_Verify C_Verify;
    CK_C_VerifyUpdate C_VerifyUpdate;
    CK_C_VerifyFinal C_VerifyFinal;
    CK_C_VerifyRecoverInit C_VerifyRecoverInit;
    CK_C_VerifyRecover C_VerifyRecover;
    CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
    CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
    CK_C_SignEncryptUpdate C_SignEncryptUpdate;
    CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
    CK_C_GenerateKey C_GenerateKey;
    CK_C_GenerateKeyPair C_GenerateKeyPair;
    CK_C_WrapKey C_WrapKey;
    CK_C_UnwrapKey C_UnwrapKey;
    CK_C_DeriveKey C_DeriveKey;
    CK_C_SeedRandom C_SeedRandom;
    CK_C_GenerateRandom C_GenerateRandom;
    CK_C_GetFunctionStatus C_GetFunctionStatus;
    CK_C_CancelFunction C_CancelFunction;
    CK_C_WaitForSlotEvent C_WaitForSlotEvent;
};

#ifdef __cplusplus
}
#endif

#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif

#endif /* PKCS11J_PKCS11_H */

