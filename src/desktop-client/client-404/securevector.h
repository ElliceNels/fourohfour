#ifndef SECUREVECTOR_H
#define SECUREVECTOR_H

#include <vector>
#include <cstddef>

class SecureVector {
public:
    SecureVector();
    explicit SecureVector(size_t size);
    SecureVector(const std::vector<unsigned char>& v);
    ~SecureVector();

    // Disable copy constructor and assignment
    SecureVector(const SecureVector&) = delete;
    SecureVector& operator=(const SecureVector&) = delete;

    // Enable move constructor and assignment
    SecureVector(SecureVector&& other) noexcept;
    SecureVector& operator=(SecureVector&& other) noexcept;

    unsigned char* data();
    const unsigned char* data() const;
    size_t size() const;

    void resize(size_t newSize);
    void clear();

    using iterator = std::vector<unsigned char>::iterator;
    using const_iterator = std::vector<unsigned char>::const_iterator;

    iterator insert(iterator pos, const unsigned char* first, const unsigned char* last);

    iterator begin();
    iterator end();

private:
    std::vector<unsigned char> data_;
};

#endif // SECUREVECTOR_H
