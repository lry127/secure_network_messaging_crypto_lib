//
// Created by ubuntu on 11/2/24.
//
#include <gtest/gtest.h>
#include "LengthMessageCrypto.h"


TEST(NegotiatedCryptoTest, CryptoFuntionalilityTest) {
    unsigned char serverPublic[crypto_kx_PUBLICKEYBYTES];
    unsigned char serverPrivate[crypto_kx_SECRETKEYBYTES];

    crypto_kx_keypair(serverPublic, serverPrivate);

    auto clientSide = NegotiatedCryptoNative::create(serverPublic);
    ASSERT_TRUE(clientSide);

    auto serverSide = NegotiatedCryptoNative::create(clientSide->getMyPublicKey(), true,
                                                     serverPublic, serverPrivate);
    ASSERT_TRUE(serverSide);


    ASSERT_EQ(*clientSide, *serverSide);

    std::string s(1000, 'c');

    auto *message = const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(s.data()));
    int messageLen = 1000 + 1;

    auto serverCrypto = LengthMessageCrypto::create(serverSide);
    LengthMessageCrypto::CryptoResult result = serverCrypto->encryptToFullMessage(message, messageLen);
    ASSERT_EQ(result.length,
              messageLen + crypto_secretbox_MACBYTES * 2 + crypto_secretbox_NONCEBYTES + sizeof(int64_t));

    int64_t headerSize = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + sizeof(uint64_t);
    int64_t encryptedBodySize = result.length - headerSize;
    auto clientSideCrypto = LengthMessageCrypto::create(result.data.get(), headerSize, clientSide);
    ASSERT_TRUE(clientSideCrypto);

    ASSERT_EQ(clientSideCrypto->getBodySize(), encryptedBodySize);

    LengthMessageCrypto::CryptoResult bodyDecrypted = clientSideCrypto->decryptBody(result.data.get() + headerSize);
    ASSERT_EQ(bodyDecrypted.length, messageLen);
    ASSERT_EQ(memcmp(bodyDecrypted.data.get(), message, messageLen), 0);
}
