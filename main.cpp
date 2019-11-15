#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    //construct and show mainwindow class. Everything is handled from there
    MainWindow w;
    w.show();

    return a.exec();
}
