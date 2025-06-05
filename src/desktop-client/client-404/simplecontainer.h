#ifndef SIMPLECONTAINER_H
#define SIMPLECONTAINER_H

#include <QDebug>

template<typename T>
class SimpleContainer {
private:
    T value;

public:
    void setValue(T newValue);
    T getValue();
};

template<typename T>
void SimpleContainer<T>::setValue(T newValue) {
    value = newValue;
}

template<typename T>
T SimpleContainer<T>::getValue() {
    return value;
}

#endif
