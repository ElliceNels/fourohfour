#include "securevector.h"
#include <sodium.h>
#include <QDebug>

using namespace std;

// Constructors and Destructor
SecureVector::SecureVector() = default;

SecureVector::SecureVector(size_t size) : data_(size) {}

SecureVector::SecureVector(const  vector<unsigned char>& v) : data_(v) {}

SecureVector::~SecureVector() {
    if (!data_.empty()) {
        sodium_memzero(data_.data(), data_.size());
    }
}

// Move constructor and assignment
SecureVector::SecureVector(SecureVector&& other) noexcept : data_( std::move(other.data_)) {
    other.clear();
}

SecureVector& SecureVector::operator=(SecureVector&& other) noexcept {
    if (this != &other) {
        clear();
        data_ =  std::move(other.data_);
        other.clear();
    }
    return *this;
}

// Data accessors
unsigned char* SecureVector::data() {
    return data_.data();
}

const unsigned char* SecureVector::data() const {
    return data_.data();
}

size_t SecureVector::size() const {
    return data_.size();
}

// Modify size and clear
void SecureVector::resize(size_t newSize) {
    data_.resize(newSize);
}

void SecureVector::clear() {
    if (!data_.empty()) {
        sodium_memzero(data_.data(), data_.size());
        data_.clear();
    }
}

 vector<unsigned char>::iterator SecureVector::insert( vector<unsigned char>::iterator pos, const unsigned char* first, const unsigned char* last) {
    return data_.insert(pos, first, last);
}


SecureVector::iterator SecureVector::begin() {
    return data_.begin();
}

SecureVector::iterator SecureVector::end() {
    return data_.end();
}

