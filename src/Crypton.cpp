#include "Crypton.h"

#include <iostream>
#include <iomanip>

#include <aes.h>
#include <filters.h>
#include <modes.h>
#include <osrng.h>
#include <hex.h>
#include <files.h>
#include "Exception.h"

#undef DEBUG

/**
 * @warning Using vectors for sensitive data is considered bad practice
 */
std::vector<std::byte> Crypton::encrypt(const vector<std::byte> &plain, const vector<std::byte> &key) {

    auto encrypted = apply(plain, key, CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption());
#if DEBUG
    CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
    encoder.Put(reinterpret_cast<CryptoPP::byte *>(encrypted.data()), encrypted.size());
    encoder.MessageEnd();
    std::cout << std::endl;
#endif
    return encrypted;
}

std::vector<std::byte> Crypton::decrypt(const vector<std::byte> &encrypted, const vector<std::byte> &key) {
    auto decrypted = apply(encrypted, key, CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption());
#if DEBUG
    CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
    encoder.Put(reinterpret_cast<CryptoPP::byte *>(decrypted.data()), decrypted.size());
    encoder.MessageEnd();
    std::cout << std::endl;
#endif
    return decrypted;
}

template<class Op>
std::vector<std::byte> Crypton::apply(const vector<std::byte> &data, const vector<std::byte> &key, Op operation) {
    return apply(data.data(), data.size(), key.data(), key.size(), operation);
}

template<class Op>
std::vector<std::byte> Crypton::apply(const std::byte *data, size_t data_len,
                                      const std::byte *key, size_t key_len, Op operation) {

//    CryptoPP::AutoSeededRandomPool random;
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

//    random.GenerateBlock(iv, iv.size());
    memset(iv.data(), 0x00, iv.size()); // iv is included in protocol

    if (key_len != CryptoPP::AES::DEFAULT_KEYLENGTH) {
        throw Exception("Wrong key length!");
    }
    operation.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte *>(key), key_len,
                           reinterpret_cast<const CryptoPP::byte *>(iv.data()), iv.size());


    std::vector<CryptoPP::byte> product(data_len + CryptoPP::AES::BLOCKSIZE);
    CryptoPP::ArraySink sink(product.data(), product.size());

    CryptoPP::ArraySource(reinterpret_cast<const CryptoPP::byte *>(data), data_len, true,
                          new CryptoPP::StreamTransformationFilter(operation, new CryptoPP::Redirector(sink)));

    product.resize(sink.TotalPutLength());
    return std::vector(reinterpret_cast<std::byte *>(&product.begin()[0]),
                       reinterpret_cast<std::byte *>(&product.end()[0]));
}

std::vector<std::byte>
Crypton::encrypt(const std::byte *plain, size_t plain_len, const std::byte *key, size_t key_len) {
    return apply(plain, plain_len, key, key_len, CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption());
}

std::vector<std::byte>
Crypton::decrypt(const std::byte *plain, size_t plain_len, const std::byte *key, size_t key_len) {
    return apply(plain, plain_len, key, key_len, CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption());
}

