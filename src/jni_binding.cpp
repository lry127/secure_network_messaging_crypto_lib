//
// Created by ubuntu on 11/2/24.
//
#include <fstream>
#include <jni.h>
#include <LengthMessageCrypto.h>
#include <NegotiatedCryptoNative.h>
#include <sodium.h>


static auto JAVA_BINDING_CLASS_NAME = "us/leaf3stones/snm/crypto/NegotiatedCryptoNative";
static auto JAVA_BINDING_MESSAGE_CLASS_NAME = "us/leaf3stones/snm/crypto/LengthMessageCrypto";
static auto JAVA_BINDING_NATIVE_BUFFER_CLASS = "us/leaf3stones/snm/crypto/NativeBuffer";
static jfieldID lengthMessageNativeHandleField;


static LengthMessageCrypto *getLengthMessage(JNIEnv *env, jobject obj) {
    int64_t handle = env->GetLongField(obj, lengthMessageNativeHandleField);
    return reinterpret_cast<LengthMessageCrypto *>(handle);
}

jint init_sodium_lib(JNIEnv *env, jclass obj) {
    return sodium_init();
}


jlong nativeInit(JNIEnv *env, jobject obj, jbyteArray myPublicKey, jbyteArray myPrivateKey,
                 jbyteArray peerPublicKey, jboolean isServer) {
    jbyte *myPublicKeyBytes{nullptr}, *myPrivateKeyBytes{nullptr}, *peerPublicKeyBytes{nullptr};

    if (peerPublicKey == nullptr) {
        return 0;
    }
    peerPublicKeyBytes = env->GetByteArrayElements(peerPublicKey, nullptr);

    if (myPublicKey != nullptr) {
        myPublicKeyBytes = env->GetByteArrayElements(myPublicKey, nullptr);
    }
    if (myPrivateKey != nullptr) {
        myPrivateKeyBytes = env->GetByteArrayElements(myPrivateKey, nullptr);
    }
    NegotiatedCryptoNative *nativeCrypto = NegotiatedCryptoNative::create(
        reinterpret_cast<const unsigned char *>(peerPublicKeyBytes), isServer,
        reinterpret_cast<const unsigned char *>(myPublicKeyBytes),
        reinterpret_cast<const unsigned char *>(myPrivateKeyBytes));
    if (!nativeCrypto) {
        return 0;
    }

    env->ReleaseByteArrayElements(peerPublicKey, peerPublicKeyBytes, JNI_ABORT);
    if (myPublicKeyBytes != nullptr) {
        env->ReleaseByteArrayElements(myPublicKey, myPublicKeyBytes, JNI_ABORT);
    }
    if (myPrivateKeyBytes != nullptr) {
        env->ReleaseByteArrayElements(myPrivateKey, myPrivateKeyBytes, JNI_ABORT);
    }
    return reinterpret_cast<jlong>(nativeCrypto);
}

void fillSymmetricKeyBuffer(JNIEnv *env, jclass obj, jlong cryptoPtr, jlong bufferPtr) {
    NegotiatedCryptoNative *nativeCrypto = reinterpret_cast<NegotiatedCryptoNative *>(cryptoPtr);
    if (!nativeCrypto) {
        return;
    }
    auto nativePtr = reinterpret_cast<unsigned char *>(bufferPtr);
    memcpy(nativePtr, nativeCrypto->getTransmitKey(), crypto_secretbox_KEYBYTES);
    nativePtr += crypto_secretbox_KEYBYTES;
    memcpy(nativePtr, nativeCrypto->getReceiveKey(), crypto_secretbox_KEYBYTES);
    nativePtr += crypto_secretbox_KEYBYTES;
    memcpy(nativePtr, nativeCrypto->getMyPublicKey(), crypto_kx_PUBLICKEYBYTES);
    nativePtr += crypto_kx_PUBLICKEYBYTES;
    memcpy(nativePtr, nativeCrypto->getMyPrivateKey(), crypto_kx_SECRETKEYBYTES);
    delete nativeCrypto;
}


int getTotalInstanceCount(JNIEnv *env, jclass obj) {
    return NegotiatedCryptoNative::getTotalInstanceCount();
}

void cleanLengthMessageNative(JNIEnv *env, jobject obj, jlong handle) {
    LengthMessageCrypto *lengthMessage{reinterpret_cast<LengthMessageCrypto *>(handle)};
    delete lengthMessage;
    LengthMessageCrypto::removeInstance();
}

jlong createNewLengthMessageNativeForDecryption(JNIEnv *env, jobject obj, jbyteArray header, jbyteArray receiveKey) {
    jbyte *headerBytes = env->GetByteArrayElements(header, nullptr);
    uint64_t headerLen = env->GetArrayLength(header);

    jbyte *keyBytes = env->GetByteArrayElements(receiveKey, nullptr);

    LengthMessageCrypto *lengthMessage = LengthMessageCrypto::create(
        reinterpret_cast<unsigned char *>(headerBytes), headerLen,
        reinterpret_cast<unsigned char *>(keyBytes));

    env->ReleaseByteArrayElements(header, headerBytes, JNI_ABORT);
    env->ReleaseByteArrayElements(receiveKey, keyBytes, JNI_ABORT);

    if (lengthMessage) {
        return reinterpret_cast<int64_t>(lengthMessage);
    }
    return 0;
}

jlong createNewLengthMessageNativeForEncryption(JNIEnv *env, jobject obj, jbyteArray transmitKey) {
    jbyte *keyBytes = env->GetByteArrayElements(transmitKey, nullptr);

    LengthMessageCrypto *lengthMessage = LengthMessageCrypto::create(reinterpret_cast<unsigned char *>(keyBytes));
    env->ReleaseByteArrayElements(transmitKey, keyBytes, JNI_ABORT);

    if (lengthMessage) {
        return reinterpret_cast<int64_t>(lengthMessage);
    }
    return 0;
}

jbyteArray encryptNative(JNIEnv *env, jobject obj, jlong ptr, jlong size) {
    LengthMessageCrypto *lengthMessage = getLengthMessage(env, obj);
    if (!lengthMessage) {
        return nullptr;
    }

    LengthMessageCrypto::CryptoResult result = lengthMessage->encryptToFullMessage(
        reinterpret_cast<unsigned char *>(ptr), size);

    if (!result.data) {
        return nullptr;
    }
    jbyteArray ciphertext = env->NewByteArray(result.length);
    if (ciphertext == nullptr) {
        return nullptr;
    }
    env->SetByteArrayRegion(ciphertext, 0, result.length,
                            reinterpret_cast<const jbyte *>(result.data.get()));
    return ciphertext;
}

jbyteArray decryptNative(JNIEnv *env, jobject obj, jbyteArray encrypted) {
    LengthMessageCrypto *lengthMessage = getLengthMessage(env, obj);
    if (!lengthMessage) {
        return nullptr;
    }
    jbyte *bodyBytes = env->GetByteArrayElements(encrypted, nullptr);

    LengthMessageCrypto::CryptoResult result = lengthMessage->decryptBody(
        reinterpret_cast<unsigned char *>(bodyBytes));
    env->ReleaseByteArrayElements(encrypted, bodyBytes, JNI_ABORT);

    if (!result.data) {
        return nullptr;
    }
    jbyteArray decryptedArray = env->NewByteArray(result.length);
    if (decryptedArray == nullptr) {
        return nullptr;
    }
    env->SetByteArrayRegion(decryptedArray, 0, result.length,
                            reinterpret_cast<const jbyte *>(result.data.get()));
    return decryptedArray;
}

jlong getEncryptedBodySize(JNIEnv *env, jobject obj) {
    LengthMessageCrypto *lengthMessage = getLengthMessage(env, obj);
    if (!lengthMessage) {
        return -1;
    }
    return lengthMessage->getBodySize();
}

jint getLengthMessageTotalInstanceCount(JNIEnv *env, jclass clazz) {
    return LengthMessageCrypto::getTotalInstanceCount();
}

jobject wrapAsByteBuffer(JNIEnv *env, jclass clazz, jlong addr, jlong size) {
    jobject buffer = env->NewDirectByteBuffer(reinterpret_cast<unsigned char *>(addr), size);
    return buffer;
}


jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass negotiatedCryptoClass = env->FindClass(JAVA_BINDING_CLASS_NAME);
    if (negotiatedCryptoClass == nullptr) {
        return JNI_ERR; // Class not found.
    }

    static JNINativeMethod negotiatedCryptoMethods[] = {
        {"initSodiumLibrary", "()I", reinterpret_cast<void *>(init_sodium_lib)},
        {"nativeInit", "([B[B[BZ)J", reinterpret_cast<void *>(nativeInit)},
        {"fillBufferWithKeys", "(JJ)V", reinterpret_cast<void *>(fillSymmetricKeyBuffer)},
        {"getTotalInstanceCount", "()I", reinterpret_cast<void *>(getTotalInstanceCount)},
        {
            "createNewLengthMessageNativeForDecryption", "([B[B)J",
            reinterpret_cast<void *>(createNewLengthMessageNativeForDecryption)
        },
        {
            "createNewLengthMessageNativeForEncryption", "([B)J",
            reinterpret_cast<void *>(createNewLengthMessageNativeForEncryption)
        },
        {"cleanLengthMessageNative", "(J)V", reinterpret_cast<void *>(cleanLengthMessageNative)},

    };

    if (env->RegisterNatives(negotiatedCryptoClass, negotiatedCryptoMethods,
                             sizeof(negotiatedCryptoMethods) / sizeof(negotiatedCryptoMethods[0])) != 0) {
        return JNI_ERR;
    }

    jclass lengthMessageCryptoClass = env->FindClass(JAVA_BINDING_MESSAGE_CLASS_NAME);
    if (lengthMessageCryptoClass == nullptr) {
        return JNI_ERR;
    }

    lengthMessageNativeHandleField = env->GetFieldID(lengthMessageCryptoClass, "nativeHandle", "J");
    if (lengthMessageNativeHandleField == nullptr) {
        return JNI_ERR;
    }

    static JNINativeMethod lengthMessageCryptoMethods[] = {
        {"encryptNative", "(JJ)[B", reinterpret_cast<void *>(encryptNative)},
        {"decryptNative", "([B)[B", reinterpret_cast<void *>(decryptNative)},
        {"getEncryptedBodySize", "()J", reinterpret_cast<void *>(getEncryptedBodySize)},
        {"getTotalInstanceCount", "()I", reinterpret_cast<void *>(getLengthMessageTotalInstanceCount)},
    };
    if (env->RegisterNatives(lengthMessageCryptoClass, lengthMessageCryptoMethods,
                             sizeof(lengthMessageCryptoMethods) / sizeof(lengthMessageCryptoMethods[0])) != 0) {
        return JNI_ERR;
    }

    jclass nativeBufferClass = env->FindClass(JAVA_BINDING_NATIVE_BUFFER_CLASS);
    if (!nativeBufferClass) {
        return JNI_ERR;
    }

    static JNINativeMethod nativeBufferMethods[] = {
        {"wrapAsByteBuffer", "(JJ)Ljava/nio/ByteBuffer;", reinterpret_cast<void *>(wrapAsByteBuffer)},
    };
    if (env->RegisterNatives(nativeBufferClass, nativeBufferMethods,
                             sizeof(nativeBufferMethods) / sizeof(nativeBufferMethods[0])) != 0) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
