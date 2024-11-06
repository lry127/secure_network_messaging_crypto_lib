//
// Created by ubuntu on 11/1/24.
//

#include "NegotiatedCryptoNative.h"

#include <cstring>

// uint64_t NegotiatedCryptoNative::instanceCount{};
// std::mutex NegotiatedCryptoNative::lock{};

NegotiatedCryptoNative::NegotiatedCryptoNative(const unsigned char *peerPublicKey, const unsigned char *myPublicKey,
                                               const unsigned char *myPrivateKey) {
    if (myPublicKey == nullptr && myPrivateKey == nullptr) {
        crypto_kx_keypair(this->myPublicKey, this->myPrivateKey);
    } else {
        memcpy(this->myPublicKey, myPublicKey, crypto_kx_PUBLICKEYBYTES);
        memcpy(this->myPrivateKey, myPrivateKey, crypto_kx_SECRETKEYBYTES);
    }
    memcpy(this->peerPublicKey, peerPublicKey, crypto_kx_PUBLICKEYBYTES);
}

bool NegotiatedCryptoNative::negotiateSessionKeyWithPeer(bool isServer) {
    if (isServer) {
        return crypto_kx_server_session_keys(receiveKey, transmitKey, myPublicKey, myPrivateKey, peerPublicKey) == 0;
    }
    return crypto_kx_client_session_keys(receiveKey, transmitKey, myPublicKey, myPrivateKey, peerPublicKey) == 0;
}

bool NegotiatedCryptoNative::encrypt(const unsigned char *nonce, unsigned char *cleartext, uint64_t size,
                                     unsigned char *dest) const {
    return crypto_secretbox_easy(dest, cleartext, size, nonce, transmitKey) == 0;
}

bool NegotiatedCryptoNative::decrypt(const unsigned char *nonce, unsigned char *ciphertext, uint64_t size,
                                     unsigned char *dest) const {
    return crypto_secretbox_open_easy(dest, ciphertext, size, nonce, receiveKey) == 0;
}

bool NegotiatedCryptoNative::operator==(const NegotiatedCryptoNative &other) const {
    if (memcmp(transmitKey, other.receiveKey, sizeof transmitKey) != 0) {
        return false;
    }
    if (memcmp(receiveKey, other.transmitKey, sizeof receiveKey) != 0) {
        return false;
    }
    return true;
}
