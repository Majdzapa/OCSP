#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>

#include "pkcs11.h"

#define ATTR_KIND_BYTES 0
#define ATTR_KIND_ULONG 1
#define ATTR_KIND_BOOL  2

typedef struct {
    void *dlHandle;
    CK_FUNCTION_LIST_PTR fnList;
} Pkcs11ModuleCtx;

static void throwPkcs11Exception(JNIEnv *env, const char *fnName, CK_RV rv) {
    jclass exCls = (*env)->FindClass(env, "com/company/incert/pkcs11j/Pkcs11Exception");
    if (exCls == NULL) {
        return;
    }
    jmethodID ctor = (*env)->GetMethodID(env, exCls, "<init>", "(Ljava/lang/String;J)V");
    if (ctor == NULL) {
        (*env)->ThrowNew(env, exCls, fnName);
        return;
    }
    jstring jFn = (*env)->NewStringUTF(env, fnName != NULL ? fnName : "PKCS#11");
    jobject exObj = (*env)->NewObject(env, exCls, ctor, jFn, (jlong)rv);
    if (exObj != NULL) {
        (*env)->Throw(env, (jthrowable)exObj);
    }
    if (jFn != NULL) {
        (*env)->DeleteLocalRef(env, jFn);
    }
}

static void throwIllegalState(JNIEnv *env, const char *msg) {
    jclass cls = (*env)->FindClass(env, "java/lang/IllegalStateException");
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, msg);
    }
}

static Pkcs11ModuleCtx *requireModule(JNIEnv *env, jlong moduleHandle) {
    if (moduleHandle == 0) {
        throwIllegalState(env, "PKCS#11 module handle is closed (0)");
        return NULL;
    }
    Pkcs11ModuleCtx *ctx = (Pkcs11ModuleCtx *)(intptr_t)moduleHandle;
    if (ctx->fnList == NULL) {
        throwIllegalState(env, "PKCS#11 function list is null");
        return NULL;
    }
    return ctx;
}

typedef struct {
    CK_ATTRIBUTE *attrs;
    CK_ULONG count;
    CK_ULONG *ulongScratch;
    CK_BBOOL *boolScratch;
    jbyteArray *byteArrayRefs;
    jbyte **bytePtrs;
} AttrTemplate;

static void freeAttrTemplate(JNIEnv *env, AttrTemplate *tpl) {
    if (tpl == NULL) {
        return;
    }
    if (tpl->bytePtrs != NULL && tpl->byteArrayRefs != NULL) {
        for (CK_ULONG i = 0; i < tpl->count; i++) {
            if (tpl->byteArrayRefs[i] != NULL && tpl->bytePtrs[i] != NULL) {
                (*env)->ReleaseByteArrayElements(env, tpl->byteArrayRefs[i], tpl->bytePtrs[i], JNI_ABORT);
                (*env)->DeleteLocalRef(env, tpl->byteArrayRefs[i]);
            }
        }
    }
    free(tpl->byteArrayRefs);
    free(tpl->bytePtrs);
    free(tpl->ulongScratch);
    free(tpl->boolScratch);
    free(tpl->attrs);
    memset(tpl, 0, sizeof(*tpl));
}

static int buildAttrTemplate(
        JNIEnv *env,
        jlongArray attrTypes,
        jintArray attrKinds,
        jlongArray longVals,
        jobjectArray byteVals,
        AttrTemplate *out) {

    memset(out, 0, sizeof(*out));
    if (attrTypes == NULL) {
        return 0;
    }

    jsize len = (*env)->GetArrayLength(env, attrTypes);
    if (len == 0) {
        return 0;
    }

    out->count = (CK_ULONG)len;
    out->attrs = (CK_ATTRIBUTE *)calloc((size_t)len, sizeof(CK_ATTRIBUTE));
    out->ulongScratch = (CK_ULONG *)calloc((size_t)len, sizeof(CK_ULONG));
    out->boolScratch = (CK_BBOOL *)calloc((size_t)len, sizeof(CK_BBOOL));
    out->byteArrayRefs = (jbyteArray *)calloc((size_t)len, sizeof(jbyteArray));
    out->bytePtrs = (jbyte **)calloc((size_t)len, sizeof(jbyte *));

    if (!out->attrs || !out->ulongScratch || !out->boolScratch || !out->byteArrayRefs || !out->bytePtrs) {
        freeAttrTemplate(env, out);
        throwIllegalState(env, "Out of native memory allocating PKCS#11 attributes");
        return -1;
    }

    jlong *types = (*env)->GetLongArrayElements(env, attrTypes, NULL);
    jint *kinds = (*env)->GetIntArrayElements(env, attrKinds, NULL);
    jlong *longs = longVals != NULL ? (*env)->GetLongArrayElements(env, longVals, NULL) : NULL;

    int rc = 0;
    for (jsize i = 0; i < len; i++) {
        out->attrs[i].type = (CK_ATTRIBUTE_TYPE)types[i];
        int kind = kinds[i];
        if (kind == ATTR_KIND_ULONG) {
            out->ulongScratch[i] = longs != NULL ? (CK_ULONG)longs[i] : 0UL;
            out->attrs[i].pValue = &out->ulongScratch[i];
            out->attrs[i].ulValueLen = (CK_ULONG)sizeof(CK_ULONG);
        } else if (kind == ATTR_KIND_BOOL) {
            jlong v = longs != NULL ? longs[i] : 0L;
            out->boolScratch[i] = (v != 0L) ? CK_TRUE : CK_FALSE;
            out->attrs[i].pValue = &out->boolScratch[i];
            out->attrs[i].ulValueLen = (CK_ULONG)sizeof(CK_BBOOL);
        } else {
            jbyteArray arr = byteVals != NULL ? (jbyteArray)(*env)->GetObjectArrayElement(env, byteVals, i) : NULL;
            if (arr != NULL) {
                jsize byteLen = (*env)->GetArrayLength(env, arr);
                jbyte *ptr = byteLen > 0 ? (*env)->GetByteArrayElements(env, arr, NULL) : NULL;
                out->byteArrayRefs[i] = arr;
                out->bytePtrs[i] = ptr;
                out->attrs[i].pValue = (CK_VOID_PTR)ptr;
                out->attrs[i].ulValueLen = (CK_ULONG)byteLen;
            } else {
                out->attrs[i].pValue = NULL_PTR;
                out->attrs[i].ulValueLen = 0;
            }
        }
    }

    (*env)->ReleaseLongArrayElements(env, attrTypes, types, JNI_ABORT);
    (*env)->ReleaseIntArrayElements(env, attrKinds, kinds, JNI_ABORT);
    if (longs != NULL) {
        (*env)->ReleaseLongArrayElements(env, longVals, longs, JNI_ABORT);
    }

    return rc;
}

static jstring paddedUtf8ToJstring(JNIEnv *env, const CK_BYTE *buf, size_t maxLen) {
    char tmp[128];
    size_t copyLen = maxLen < sizeof(tmp) - 1 ? maxLen : sizeof(tmp) - 1;
    memcpy(tmp, buf, copyLen);
    tmp[copyLen] = '\0';
    while (copyLen > 0 && (tmp[copyLen - 1] == ' ' || tmp[copyLen - 1] == '\0')) {
        tmp[--copyLen] = '\0';
    }
    return (*env)->NewStringUTF(env, tmp);
}

JNIEXPORT jlong JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_loadModule(
        JNIEnv *env, jclass cls, jstring jLibraryPath) {
    (void)cls;
    if (jLibraryPath == NULL) {
        throwIllegalState(env, "PKCS#11 library path cannot be null");
        return 0;
    }
    const char *path = (*env)->GetStringUTFChars(env, jLibraryPath, NULL);
    if (path == NULL) {
        return 0;
    }

    void *dlHandle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (dlHandle == NULL) {
        const char *err = dlerror();
        char msg[512];
        snprintf(msg, sizeof(msg), "dlopen('%s') failed: %s", path, err ? err : "unknown error");
        (*env)->ReleaseStringUTFChars(env, jLibraryPath, path);
        throwIllegalState(env, msg);
        return 0;
    }

    typedef CK_RV (*GetFunctionListFn)(CK_FUNCTION_LIST_PTR_PTR);
    GetFunctionListFn getFnList = (GetFunctionListFn)dlsym(dlHandle, "C_GetFunctionList");
    if (getFnList == NULL) {
        const char *err = dlerror();
        char msg[512];
        snprintf(msg, sizeof(msg), "dlsym('C_GetFunctionList') failed for '%s': %s", path, err ? err : "not found");
        (*env)->ReleaseStringUTFChars(env, jLibraryPath, path);
        dlclose(dlHandle);
        throwIllegalState(env, msg);
        return 0;
    }

    (*env)->ReleaseStringUTFChars(env, jLibraryPath, path);

    CK_FUNCTION_LIST_PTR fnList = NULL;
    CK_RV rv = getFnList(&fnList);
    if (rv != CKR_OK || fnList == NULL) {
        dlclose(dlHandle);
        throwPkcs11Exception(env, "C_GetFunctionList", rv);
        return 0;
    }

    Pkcs11ModuleCtx *ctx = (Pkcs11ModuleCtx *)calloc(1, sizeof(Pkcs11ModuleCtx));
    if (ctx == NULL) {
        dlclose(dlHandle);
        throwIllegalState(env, "Out of native memory allocating module context");
        return 0;
    }
    ctx->dlHandle = dlHandle;
    ctx->fnList = fnList;
    return (jlong)(intptr_t)ctx;
}

JNIEXPORT void JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_unloadModule(
        JNIEnv *env, jclass cls, jlong moduleHandle) {
    (void)env;
    (void)cls;
    if (moduleHandle == 0) {
        return;
    }
    Pkcs11ModuleCtx *ctx = (Pkcs11ModuleCtx *)(intptr_t)moduleHandle;
    if (ctx->dlHandle != NULL) {
        dlclose(ctx->dlHandle);
    }
    free(ctx);
}

JNIEXPORT jlong JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cInitialize(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong flags) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return (jlong)CKR_GENERAL_ERROR;
    }
    if (flags != 0) {
        CK_C_INITIALIZE_ARGS args;
        memset(&args, 0, sizeof(args));
        args.flags = (CK_FLAGS)flags;
        return (jlong)ctx->fnList->C_Initialize(&args);
    }
    return (jlong)ctx->fnList->C_Initialize(NULL_PTR);
}

JNIEXPORT jlong JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cFinalize(
        JNIEnv *env, jclass cls, jlong moduleHandle) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return (jlong)CKR_GENERAL_ERROR;
    }
    return (jlong)ctx->fnList->C_Finalize(NULL_PTR);
}

JNIEXPORT jlongArray JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cGetSlotList(
        JNIEnv *env, jclass cls, jlong moduleHandle, jboolean tokenPresent) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return NULL;
    }
    CK_BBOOL present = tokenPresent ? CK_TRUE : CK_FALSE;
    CK_ULONG count = 0;
    CK_RV rv = ctx->fnList->C_GetSlotList(present, NULL_PTR, &count);
    if (rv != CKR_OK) {
        throwPkcs11Exception(env, "C_GetSlotList(count)", rv);
        return NULL;
    }
    if (count == 0) {
        return (*env)->NewLongArray(env, 0);
    }

    CK_SLOT_ID *slots = (CK_SLOT_ID *)calloc((size_t)count, sizeof(CK_SLOT_ID));
    if (slots == NULL) {
        throwIllegalState(env, "Out of native memory allocating slot list");
        return NULL;
    }
    rv = ctx->fnList->C_GetSlotList(present, slots, &count);
    if (rv != CKR_OK) {
        free(slots);
        throwPkcs11Exception(env, "C_GetSlotList", rv);
        return NULL;
    }

    jlongArray out = (*env)->NewLongArray(env, (jsize)count);
    if (out != NULL) {
        jlong *buf = (jlong *)calloc((size_t)count, sizeof(jlong));
        if (buf != NULL) {
            for (CK_ULONG i = 0; i < count; i++) {
                buf[i] = (jlong)slots[i];
            }
            (*env)->SetLongArrayRegion(env, out, 0, (jsize)count, buf);
            free(buf);
        }
    }
    free(slots);
    return out;
}

JNIEXPORT jobjectArray JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cGetTokenInfo(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong slotId) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return NULL;
    }
    CK_TOKEN_INFO info;
    memset(&info, 0, sizeof(info));
    CK_RV rv = ctx->fnList->C_GetTokenInfo((CK_SLOT_ID)slotId, &info);
    if (rv != CKR_OK) {
        throwPkcs11Exception(env, "C_GetTokenInfo", rv);
        return NULL;
    }

    jclass strCls = (*env)->FindClass(env, "java/lang/String");
    jobjectArray result = (*env)->NewObjectArray(env, 5, strCls, NULL);
    if (result == NULL) {
        return NULL;
    }

    char flagsBuf[32];
    snprintf(flagsBuf, sizeof(flagsBuf), "%lu", (unsigned long)info.flags);

    jstring jLabel = paddedUtf8ToJstring(env, info.label, sizeof(info.label));
    jstring jManuf = paddedUtf8ToJstring(env, info.manufacturerID, sizeof(info.manufacturerID));
    jstring jModel = paddedUtf8ToJstring(env, info.model, sizeof(info.model));
    jstring jSerial = paddedUtf8ToJstring(env, info.serialNumber, sizeof(info.serialNumber));
    jstring jFlags = (*env)->NewStringUTF(env, flagsBuf);

    (*env)->SetObjectArrayElement(env, result, 0, jLabel);
    (*env)->SetObjectArrayElement(env, result, 1, jManuf);
    (*env)->SetObjectArrayElement(env, result, 2, jModel);
    (*env)->SetObjectArrayElement(env, result, 3, jSerial);
    (*env)->SetObjectArrayElement(env, result, 4, jFlags);

    (*env)->DeleteLocalRef(env, jLabel);
    (*env)->DeleteLocalRef(env, jManuf);
    (*env)->DeleteLocalRef(env, jModel);
    (*env)->DeleteLocalRef(env, jSerial);
    (*env)->DeleteLocalRef(env, jFlags);

    return result;
}

JNIEXPORT jlong JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cOpenSession(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong slotId, jlong flags) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return 0;
    }
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV rv = ctx->fnList->C_OpenSession((CK_SLOT_ID)slotId, (CK_FLAGS)flags, NULL_PTR, NULL_PTR, &session);
    if (rv != CKR_OK) {
        throwPkcs11Exception(env, "C_OpenSession", rv);
        return 0;
    }
    return (jlong)session;
}

JNIEXPORT void JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cCloseSession(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return;
    }
    CK_RV rv = ctx->fnList->C_CloseSession((CK_SESSION_HANDLE)sessionHandle);
    if (rv != CKR_OK && rv != CKR_SESSION_HANDLE_INVALID) {
        throwPkcs11Exception(env, "C_CloseSession", rv);
    }
}

JNIEXPORT void JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cCloseAllSessions(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong slotId) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return;
    }
    CK_RV rv = ctx->fnList->C_CloseAllSessions((CK_SLOT_ID)slotId);
    if (rv != CKR_OK) {
        throwPkcs11Exception(env, "C_CloseAllSessions", rv);
    }
}

JNIEXPORT jlong JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cLogin(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle, jlong userType, jbyteArray jPin) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return (jlong)CKR_GENERAL_ERROR;
    }
    CK_ULONG pinLen = 0;
    CK_UTF8CHAR *pinCopy = NULL;
    if (jPin != NULL) {
        jsize rawLen = (*env)->GetArrayLength(env, jPin);
        if (rawLen > 0) {
            pinLen = (CK_ULONG)rawLen;
            pinCopy = (CK_UTF8CHAR *)calloc((size_t)rawLen, 1);
            if (pinCopy == NULL) {
                throwIllegalState(env, "Out of native memory copying PIN");
                return (jlong)CKR_GENERAL_ERROR;
            }
            (*env)->GetByteArrayRegion(env, jPin, 0, rawLen, (jbyte *)pinCopy);
        }
    }
    CK_RV rv = ctx->fnList->C_Login((CK_SESSION_HANDLE)sessionHandle, (CK_USER_TYPE)userType, pinCopy, pinLen);
    if (pinCopy != NULL) {
        volatile CK_UTF8CHAR *p = pinCopy;
        for (CK_ULONG i = 0; i < pinLen; i++) {
            p[i] = 0;
        }
        free(pinCopy);
    }
    return (jlong)rv;
}

JNIEXPORT jlong JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cLogout(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return (jlong)CKR_GENERAL_ERROR;
    }
    return (jlong)ctx->fnList->C_Logout((CK_SESSION_HANDLE)sessionHandle);
}

JNIEXPORT void JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cFindObjectsInit(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle,
        jlongArray attrTypes, jintArray attrKinds, jlongArray longVals, jobjectArray byteVals) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return;
    }
    AttrTemplate tpl;
    if (buildAttrTemplate(env, attrTypes, attrKinds, longVals, byteVals, &tpl) != 0) {
        return;
    }
    CK_RV rv = ctx->fnList->C_FindObjectsInit((CK_SESSION_HANDLE)sessionHandle, tpl.attrs, tpl.count);
    freeAttrTemplate(env, &tpl);
    if (rv != CKR_OK) {
        throwPkcs11Exception(env, "C_FindObjectsInit", rv);
    }
}

JNIEXPORT jlongArray JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cFindObjects(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle, jint maxCount) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return NULL;
    }
    if (maxCount <= 0) {
        return (*env)->NewLongArray(env, 0);
    }
    CK_OBJECT_HANDLE *objs = (CK_OBJECT_HANDLE *)calloc((size_t)maxCount, sizeof(CK_OBJECT_HANDLE));
    if (objs == NULL) {
        throwIllegalState(env, "Out of native memory allocating object handles");
        return NULL;
    }
    CK_ULONG found = 0;
    CK_RV rv = ctx->fnList->C_FindObjects((CK_SESSION_HANDLE)sessionHandle, objs, (CK_ULONG)maxCount, &found);
    if (rv != CKR_OK) {
        free(objs);
        throwPkcs11Exception(env, "C_FindObjects", rv);
        return NULL;
    }
    jlongArray out = (*env)->NewLongArray(env, (jsize)found);
    if (out != NULL && found > 0) {
        jlong *buf = (jlong *)calloc((size_t)found, sizeof(jlong));
        if (buf != NULL) {
            for (CK_ULONG i = 0; i < found; i++) {
                buf[i] = (jlong)objs[i];
            }
            (*env)->SetLongArrayRegion(env, out, 0, (jsize)found, buf);
            free(buf);
        }
    }
    free(objs);
    return out;
}

JNIEXPORT void JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cFindObjectsFinal(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return;
    }
    CK_RV rv = ctx->fnList->C_FindObjectsFinal((CK_SESSION_HANDLE)sessionHandle);
    if (rv != CKR_OK) {
        throwPkcs11Exception(env, "C_FindObjectsFinal", rv);
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cGetAttributeValue(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle, jlong objectHandle, jlong attrType) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return NULL;
    }
    CK_ATTRIBUTE attr;
    attr.type = (CK_ATTRIBUTE_TYPE)attrType;
    attr.pValue = NULL_PTR;
    attr.ulValueLen = 0;

    CK_RV rv = ctx->fnList->C_GetAttributeValue((CK_SESSION_HANDLE)sessionHandle, (CK_OBJECT_HANDLE)objectHandle, &attr, 1);
    if (rv != CKR_OK) {
        throwPkcs11Exception(env, "C_GetAttributeValue(len)", rv);
        return NULL;
    }
    if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
        return NULL;
    }
    if (attr.ulValueLen == 0) {
        return (*env)->NewByteArray(env, 0);
    }

    jbyte *buf = (jbyte *)calloc((size_t)attr.ulValueLen, 1);
    if (buf == NULL) {
        throwIllegalState(env, "Out of native memory reading attribute");
        return NULL;
    }
    attr.pValue = buf;
    rv = ctx->fnList->C_GetAttributeValue((CK_SESSION_HANDLE)sessionHandle, (CK_OBJECT_HANDLE)objectHandle, &attr, 1);
    if (rv != CKR_OK) {
        free(buf);
        throwPkcs11Exception(env, "C_GetAttributeValue", rv);
        return NULL;
    }

    jbyteArray out = (*env)->NewByteArray(env, (jsize)attr.ulValueLen);
    if (out != NULL) {
        (*env)->SetByteArrayRegion(env, out, 0, (jsize)attr.ulValueLen, buf);
    }
    free(buf);
    return out;
}

JNIEXPORT jlong JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cGetAttributeUlong(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle, jlong objectHandle, jlong attrType) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return -1;
    }
    CK_ULONG val = 0;
    CK_ATTRIBUTE attr;
    attr.type = (CK_ATTRIBUTE_TYPE)attrType;
    attr.pValue = &val;
    attr.ulValueLen = (CK_ULONG)sizeof(CK_ULONG);

    CK_RV rv = ctx->fnList->C_GetAttributeValue((CK_SESSION_HANDLE)sessionHandle, (CK_OBJECT_HANDLE)objectHandle, &attr, 1);
    if (rv != CKR_OK) {
        throwPkcs11Exception(env, "C_GetAttributeValue(ulong)", rv);
        return -1;
    }
    return (jlong)val;
}

JNIEXPORT jlongArray JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cGenerateKeyPair(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle, jlong mechanismType,
        jlongArray pubTypes, jintArray pubKinds, jlongArray pubLongs, jobjectArray pubBytes,
        jlongArray privTypes, jintArray privKinds, jlongArray privLongs, jobjectArray privBytes) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return NULL;
    }
    AttrTemplate pubTpl, privTpl;
    if (buildAttrTemplate(env, pubTypes, pubKinds, pubLongs, pubBytes, &pubTpl) != 0) {
        return NULL;
    }
    if (buildAttrTemplate(env, privTypes, privKinds, privLongs, privBytes, &privTpl) != 0) {
        freeAttrTemplate(env, &pubTpl);
        return NULL;
    }

    CK_MECHANISM mech;
    mech.mechanism = (CK_MECHANISM_TYPE)mechanismType;
    mech.pParameter = NULL_PTR;
    mech.ulParameterLen = 0;

    CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPriv = CK_INVALID_HANDLE;

    CK_RV rv = ctx->fnList->C_GenerateKeyPair(
        (CK_SESSION_HANDLE)sessionHandle,
        &mech,
        pubTpl.attrs, pubTpl.count,
        privTpl.attrs, privTpl.count,
        &hPub, &hPriv);

    freeAttrTemplate(env, &pubTpl);
    freeAttrTemplate(env, &privTpl);

    if (rv != CKR_OK) {
        throwPkcs11Exception(env, "C_GenerateKeyPair", rv);
        return NULL;
    }

    jlong pair[2] = { (jlong)hPub, (jlong)hPriv };
    jlongArray out = (*env)->NewLongArray(env, 2);
    if (out != NULL) {
        (*env)->SetLongArrayRegion(env, out, 0, 2, pair);
    }
    return out;
}

JNIEXPORT jlong JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cCreateObject(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle,
        jlongArray attrTypes, jintArray attrKinds, jlongArray longVals, jobjectArray byteVals) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return 0;
    }
    AttrTemplate tpl;
    if (buildAttrTemplate(env, attrTypes, attrKinds, longVals, byteVals, &tpl) != 0) {
        return 0;
    }
    CK_OBJECT_HANDLE hObj = CK_INVALID_HANDLE;
    CK_RV rv = ctx->fnList->C_CreateObject((CK_SESSION_HANDLE)sessionHandle, tpl.attrs, tpl.count, &hObj);
    freeAttrTemplate(env, &tpl);
    if (rv != CKR_OK) {
        throwPkcs11Exception(env, "C_CreateObject", rv);
        return 0;
    }
    return (jlong)hObj;
}

JNIEXPORT void JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cSignInit(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle,
        jlong mechanismType, jboolean isPss, jlong pssHashAlg, jlong pssMgf, jlong pssSaltLen, jlong keyHandle) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return;
    }
    CK_RSA_PKCS_PSS_PARAMS pssParams;
    CK_MECHANISM mech;
    mech.mechanism = (CK_MECHANISM_TYPE)mechanismType;

    if (isPss) {
        pssParams.hashAlg = (CK_MECHANISM_TYPE)pssHashAlg;
        pssParams.mgf = (CK_ULONG)pssMgf;
        pssParams.sLen = (CK_ULONG)pssSaltLen;
        mech.pParameter = &pssParams;
        mech.ulParameterLen = (CK_ULONG)sizeof(CK_RSA_PKCS_PSS_PARAMS);
    } else {
        mech.pParameter = NULL_PTR;
        mech.ulParameterLen = 0;
    }

    CK_RV rv = ctx->fnList->C_SignInit((CK_SESSION_HANDLE)sessionHandle, &mech, (CK_OBJECT_HANDLE)keyHandle);
    if (rv != CKR_OK) {
        throwPkcs11Exception(env, "C_SignInit", rv);
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_company_incert_pkcs11j_nativebridge_Pkcs11NativeBridge_cSign(
        JNIEnv *env, jclass cls, jlong moduleHandle, jlong sessionHandle, jbyteArray jData) {
    (void)cls;
    Pkcs11ModuleCtx *ctx = requireModule(env, moduleHandle);
    if (ctx == NULL) {
        return NULL;
    }

    jsize dataLen = jData != NULL ? (*env)->GetArrayLength(env, jData) : 0;
    jbyte *dataPtr = (jData != NULL && dataLen > 0) ? (*env)->GetByteArrayElements(env, jData, NULL) : NULL;

    CK_ULONG sigLen = 0;
    CK_RV rv = ctx->fnList->C_Sign((CK_SESSION_HANDLE)sessionHandle, (CK_BYTE_PTR)dataPtr, (CK_ULONG)dataLen, NULL_PTR, &sigLen);
    if (rv != CKR_OK) {
        if (dataPtr != NULL) {
            (*env)->ReleaseByteArrayElements(env, jData, dataPtr, JNI_ABORT);
        }
        throwPkcs11Exception(env, "C_Sign(len)", rv);
        return NULL;
    }

    jbyte *sigBuf = (jbyte *)calloc(sigLen > 0 ? (size_t)sigLen : 1, 1);
    if (sigBuf == NULL) {
        if (dataPtr != NULL) {
            (*env)->ReleaseByteArrayElements(env, jData, dataPtr, JNI_ABORT);
        }
        throwIllegalState(env, "Out of native memory allocating signature buffer");
        return NULL;
    }

    rv = ctx->fnList->C_Sign((CK_SESSION_HANDLE)sessionHandle, (CK_BYTE_PTR)dataPtr, (CK_ULONG)dataLen, (CK_BYTE_PTR)sigBuf, &sigLen);
    if (dataPtr != NULL) {
        (*env)->ReleaseByteArrayElements(env, jData, dataPtr, JNI_ABORT);
    }
    if (rv != CKR_OK) {
        free(sigBuf);
        throwPkcs11Exception(env, "C_Sign", rv);
        return NULL;
    }

    jbyteArray out = (*env)->NewByteArray(env, (jsize)sigLen);
    if (out != NULL) {
        (*env)->SetByteArrayRegion(env, out, 0, (jsize)sigLen, sigBuf);
    }
    free(sigBuf);
    return out;
}

