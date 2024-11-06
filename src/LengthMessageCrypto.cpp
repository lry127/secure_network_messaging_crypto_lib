//
// Created by ubuntu on 11/2/24.
//

#include "LengthMessageCrypto.h"

// uint64_t LengthMessageCrypto::instanceCount{};
// std::mutex LengthMessageCrypto::lock{};

LengthMessageCrypto::CryptoResult LengthMessageCrypto::decryptBody(unsigned char *bodyCiphertext) {
    for (int i = 0; i < crypto_secretbox_NONCEBYTES; ++i) {
        *(nonceBase + i) = ~*(nonceBase + i);
    }
    int64_t decryptedBodySize = encryptedBodySize - crypto_secretbox_MACBYTES;

    CryptoResult result{decryptedBodySize, std::make_unique<unsigned char[]>(decryptedBodySize)};
    if (crypto_secretbox_open_easy(result.data.get(), bodyCiphertext, encryptedBodySize, nonceBase, symmetricKey) !=
        0) {
        return {0, nullptr};
    }

    return result;
}

LengthMessageCrypto::CryptoResult LengthMessageCrypto::encryptToFullMessage(unsigned char *body, int64_t size) {
    int64_t length = size + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES * 2 + sizeof(int64_t);
    CryptoResult result{length, std::make_unique<unsigned char[]>(length)};
    unsigned char *nonceBegin = result.data.get();

    // first put the nonce to the fully encrypted message
    randombytes_buf(nonceBegin, crypto_secretbox_NONCEBYTES);

    // prepare the header
    unsigned char header[sizeof(int64_t)];
    int64_t encryptedBodySize = size + crypto_secretbox_MACBYTES;
    for (size_t i = 0; i < 8; ++i) {
        header[i] = encryptedBodySize >> 8 * (7 - i) & 0xFF;
    }

    auto *const headerBegin = nonceBegin + crypto_secretbox_NONCEBYTES;
    if (crypto_secretbox_easy(headerBegin, header, sizeof header, nonceBegin, symmetricKey) != 0) {
        return {0, nullptr};
    }

    for (int i = 0; i < crypto_secretbox_NONCEBYTES; ++i) {
        *(nonceBegin + i) = ~*(nonceBegin + i);
    }
    auto *const bodyBegin = headerBegin + crypto_secretbox_MACBYTES + sizeof header;
    if (crypto_secretbox_easy(bodyBegin, body, size, nonceBegin, symmetricKey) != 0) {
        return {0, nullptr};
    }
    for (int i = 0; i < crypto_secretbox_NONCEBYTES; ++i) {
        *(nonceBegin + i) = ~*(nonceBegin + i);
    }

    return result;
}

LengthMessageCrypto::
LengthMessageCrypto(unsigned char *part1, unsigned char *key) {
    memcpy(nonceBase, part1, crypto_secretbox_NONCEBYTES);
    memcpy(symmetricKey, key, sizeof(symmetricKey));
}

LengthMessageCrypto::LengthMessageCrypto(unsigned char *key) {
    memcpy(symmetricKey, key, sizeof(symmetricKey));
}

int64_t LengthMessageCrypto::decryptHeader(unsigned char *header) {
    unsigned char decryptedHeader[sizeof(int64_t)];
    bool decryptionResultCode =
            crypto_secretbox_open_easy(decryptedHeader, header, sizeof(int64_t) + crypto_secretbox_MACBYTES, nonceBase,
                                       symmetricKey) == 0;
    if (!decryptionResultCode) {
        return -2;
    }

    int64_t result = 0;
    for (size_t i = 0; i < sizeof(int64_t); ++i) {
        result = result << 8 | decryptedHeader[i];
    }
    encryptedBodySize = result;
    return result;
}
