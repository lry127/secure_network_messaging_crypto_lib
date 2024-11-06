#include <cstring>
#include <iostream>
#include <sodium.h>


int main() {
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(server_pk, server_sk);

    constexpr int encLen = sodium_base64_ENCODED_LEN(sizeof server_pk, sodium_base64_VARIANT_ORIGINAL);
    char pkEnc[encLen], skEnc[encLen];
    sodium_bin2base64(pkEnc, encLen, server_pk, sizeof server_pk, sodium_base64_VARIANT_ORIGINAL);

    sodium_bin2base64(skEnc, encLen, server_sk, sizeof server_sk, sodium_base64_VARIANT_ORIGINAL);
    std::cerr << "generating key exchange key pair..." << std::endl;
    std::cerr << "public: " << pkEnc << std::endl;
    std::cerr << "secret: " << skEnc << std::endl;
}
