#include "Header.h"
#include <osrng.h>


Header::Header(const std::vector<std::byte> &data, Tins::IPv4Address address, int port)
        : address(address), port(port) {
    this->data_length = data.size();
    CryptoPP::AutoSeededRandomPool rnd;
    rnd.GenerateBlock(this->random, RANDOM_PAYLOAD_SIZE);
}

Header::Header(const std::byte *data, size_t data_len, Tins::IPv4Address address, int port)
        : data_length(data_len), address(address), port(port) {
    CryptoPP::AutoSeededRandomPool rnd;
    rnd.GenerateBlock(this->random, RANDOM_PAYLOAD_SIZE);
}
