#ifndef SECUREBUFFERUTILS_H
#define SECUREBUFFERUTILS_H

#include <memory>
#include <sodium.h>
#include <cstddef>


struct SodiumZeroDeleter {
    size_t size;
    explicit SodiumZeroDeleter(size_t s) : size(s) {}

    void operator()(unsigned char* p) const {
        if (p) {
            sodium_memzero(p, size);
            delete[] p;
        }
    }
};

template<size_t Size>
auto make_secure_buffer() {
    return std::unique_ptr<unsigned char[], SodiumZeroDeleter>(
        new unsigned char[Size], SodiumZeroDeleter(Size));
}

#endif
