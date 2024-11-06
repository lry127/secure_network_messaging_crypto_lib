//
// Created by ubuntu on 11/1/24.
//

#ifndef NEGOTIATEDCRYPTONATIVE_H
#define NEGOTIATEDCRYPTONATIVE_H

#include <mutex>
#include <sodium.h>

class SymmetricCrypto;

class NegotiatedCryptoNative {
public:
    explicit NegotiatedCryptoNative(const unsigned char *peerPublicKey, const unsigned char *myPublicKey = nullptr,
                                    const unsigned char *myPrivateKey = nullptr);

    bool negotiateSessionKeyWithPeer(bool isServer);

    bool encrypt(const unsigned char *nonce, unsigned char *cleartext, uint64_t size, unsigned char *dest) const;

    bool decrypt(const unsigned char *nonce, unsigned char *ciphertext, uint64_t size, unsigned char *dest) const;

    bool operator==(const NegotiatedCryptoNative &other) const;

    const unsigned char *getPeerPublicKey() const { return peerPublicKey; }
    const unsigned char *getMyPublicKey() const { return myPublicKey; }
    const unsigned char *getMyPrivateKey() const { return myPrivateKey; }
    const unsigned char *getTransmitKey() const { return transmitKey; }
    const unsigned char *getReceiveKey() const { return receiveKey; }

    static NegotiatedCryptoNative *create(const unsigned char *peerPublicKey, bool isServer = false,
                                          const unsigned char *myPublicKey = nullptr,
                                          const unsigned char *myPrivateKey = nullptr) {
        auto crypto = new NegotiatedCryptoNative(peerPublicKey, myPublicKey, myPrivateKey);
        if (!crypto->negotiateSessionKeyWithPeer(isServer)) {
            delete crypto;
            return nullptr;
        }
        addInstance();
        return crypto;
    }

    static void removeInstance() {
        // lock.lock();
        // --instanceCount;
        // lock.unlock();
    }

    static int getTotalInstanceCount() {
        // lock.lock();
        // int size = instanceCount;
        // lock.unlock();
        // return size;
        return 0;
    }

private:
    // static uint64_t instanceCount;
    // static std::mutex lock;

    static void addInstance() {
        // lock.lock();
        // ++instanceCount;
        // lock.unlock();
    }

    unsigned char peerPublicKey[crypto_kx_PUBLICKEYBYTES];
    unsigned char myPublicKey[crypto_kx_PUBLICKEYBYTES];
    unsigned char myPrivateKey[crypto_kx_SECRETKEYBYTES];
    unsigned char transmitKey[crypto_kx_SESSIONKEYBYTES];
    unsigned char receiveKey[crypto_kx_SESSIONKEYBYTES];
};


#endif //NEGOTIATEDCRYPTONATIVE_H
