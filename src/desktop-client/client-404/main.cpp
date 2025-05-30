#include "mainwindow.h"
#include <QApplication>
#include <sodium.h>
#include <iostream>
#include "utils/password_utils.h"
using namespace std;
int main(int argc, char *argv[])
{

    // immediately shut down if this fails
    if (sodium_init() < 0) {
        throw runtime_error("Failed to initialize libsodium");
    }
  
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();


}
