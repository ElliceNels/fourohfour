#include "mainwindow.h"
#include <QApplication>
#include <sodium.h>
#include <iostream>
#include "password_utils.h"
#include "registerpage.h"
using namespace std;
int main(int argc, char *argv[])
{
    string password = "mysecretpassword";
    string hashed;

    hash_password(password, hashed);

    cout << "Hashed password: " << hashed << endl;

    string secondPassword = "mysecretpassword";

    cout << "Password verification: " << verify_password(hashed, secondPassword) << endl;


    // QApplication a(argc, argv);
    // RegisterPage w;
    // w.show();
    // return a.exec();




    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
