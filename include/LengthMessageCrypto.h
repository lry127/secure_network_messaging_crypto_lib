//
// Created by ubuntu on 11/2/24.
//

#ifndef LENGTHMESSAGECRYPTO_H
#define LENGTHMESSAGECRYPTO_H
#include <cstring>
#include <memory>
#include <sodium/crypto_secretbox.h>

#include "NegotiatedCryptoNative.h"


class LengthMessageCrypto {
public:
    explicit LengthMessageCrypto(unsigned char *part1, unsigned char *key);

    explicit LengthMessageCrypto(unsigned char *key);

    using CryptoResult = struct {
        int64_t length;
        std::unique_ptr<unsigned char[]> data;
    };

    int64_t getBodySize() const {
        return encryptedBodySize;
    }

    CryptoResult decryptBody(unsigned char *bodyCiphertext);

    CryptoResult encryptToFullMessage(unsigned char *body, int64_t size);

    static LengthMessageCrypto *create(unsigned char *part1Message, uint64_t part1Size, unsigned char *key) {
        if (part1Size < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + sizeof(uint64_t)) {
            return nullptr;
        }
        auto crypto = new LengthMessageCrypto(part1Message, key);
        if (crypto->decryptHeader(part1Message + crypto_secretbox_NONCEBYTES) < 0) {
            delete crypto;
            return nullptr;
        }
        addInstance();
        return crypto;
    }

    static LengthMessageCrypto *create(unsigned char *key) {
        auto crypto = new LengthMessageCrypto(key);
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
    int64_t decryptHeader(unsigned char *header);

    int64_t encryptedBodySize{-1};
    unsigned char nonceBase[crypto_secretbox_NONCEBYTES];
    unsigned char symmetricKey[crypto_secretbox_KEYBYTES];

    // static uint64_t instanceCount;
    // static std::mutex lock;

    static void addInstance() {
        // lock.lock();
        // ++instanceCount;
        // lock.unlock();
    }
};


#endif //LENGTHMESSAGECRYPTO_H
