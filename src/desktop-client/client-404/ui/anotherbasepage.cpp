#include "anotherbasepage.h"

AnotherBasePage::AnotherBasePage() {
    qDebug() << "AnotherBasePage constructor called";
    this->protectedString = "Protected string from another base page";
}

AnotherBasePage::~AnotherBasePage() {
    qDebug() << "AnotherBasePage destructor called";
}

void AnotherBasePage::displayMessage() {
    qDebug() << "AnotherBasePage displayMessage called";
}
