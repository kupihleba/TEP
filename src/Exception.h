#include <utility>

#pragma once

#include <exception>
#include <cstring>
#include <string>

using std::exception;
using std::string;

class Exception : public exception {
public:
    explicit Exception(string err) : description(std::move(err)) {}


    const char *what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_USE_NOEXCEPT override {
        return description.c_str();
    };

private:
    string description;
};
