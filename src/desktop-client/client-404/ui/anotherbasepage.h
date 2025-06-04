#ifndef ANOTHERBASEPAGE_H
#define ANOTHERBASEPAGE_H
#include <QDebug>

class AnotherBasePage
{
public:
    AnotherBasePage();
    ~AnotherBasePage();


protected:
    void displayMessage();
    std::string protectedString;
};

#endif // ANOTHERBASEPAGE_H
