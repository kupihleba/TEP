#pragma once

#include <cstddef>
#include <vector>
#include <pch.h>
#include <tins/tins.h>

static const size_t RANDOM_PAYLOAD_SIZE = 8;

#pragma pack(push, 1) // No offsets

struct Header {
    Header(const std::vector<std::byte> &data, Tins::IPv4Address address, int port);

    Header(const std::byte *data, size_t data_len, Tins::IPv4Address address, int port);

    CryptoPP::byte random[RANDOM_PAYLOAD_SIZE];
    int64_t data_length;
    int32_t address;
    int32_t port;
};

#pragma pack(pop)
