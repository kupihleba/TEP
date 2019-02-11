#pragma once

#include <vector>
#include <cstddef>

using std::vector;

/**
 * Class Crypton encrypts data with AES CBC cipher using Crypto++ library
 * Key should be of length CryptoPP::AES::DEFAULT_KEYLENGTH, which is 16 bytes
 */
class Crypton {
public:
    vector<std::byte> encrypt(const vector<std::byte> &plain, const vector<std::byte> &key);

    vector<std::byte> decrypt(const vector<std::byte> &data, const vector<std::byte> &key);

    vector<std::byte> encrypt(const std::byte *plain, size_t plain_len, const std::byte *key, size_t key_len);

    vector<std::byte> decrypt(const std::byte *plain, size_t plain_len, const std::byte *key, size_t key_len);

private:
    template<class Op>
    vector<std::byte> apply(const vector<std::byte> &data, const vector<std::byte> &key, Op operation);

    template<class Op>
    vector<std::byte> apply(const std::byte *data, size_t data_len, const std::byte *key, size_t key_len, Op operation);
};
