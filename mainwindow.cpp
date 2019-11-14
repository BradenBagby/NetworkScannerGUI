#include "mainwindow.h"
#include "ui_mainwindow.h"



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    scanner(),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    //connect scanner's signals to MainWindows slots
    QObject::connect(&scanner, &Scanner::Log, this, &MainWindow::Log);
     QObject::connect(&scanner, &Scanner::PortInfo, this, &MainWindow::PortInfo);


     scanner.SynScan("192.168.0.25","192.168.0.31",22);
          scanner.SynScan("192.168.0.25","192.168.0.31",23);
                    scanner.SynScan("192.168.0.25","192.168.0.31",23);
                              scanner.SynScan("192.168.0.25","192.168.0.31",23);
                              cout << "______________" << endl;
                              scanner.TCPScan("192.168.0.25","192.168.0.31",22);
                                scanner.TCPScan("192.168.0.25","192.168.0.31",24);
                                  scanner.TCPScan("192.168.0.25","192.168.0.31",28);
                                     cout << "______________" << endl;
                                     scanner.FINScan("192.168.0.25","192.168.0.31",22);
                                       scanner.FINScan("192.168.0.25","192.168.0.31",24);
                                         scanner.FINScan("192.168.0.25","192.168.0.31",28);
                                         cout << "______________" << endl;
                                         scanner.XMASScan("192.168.0.25","192.168.0.31",22);
                                           scanner.XMASScan("192.168.0.25","192.168.0.31",24);
                                             scanner.XMASScan("192.168.0.25","192.168.0.31",28);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::Log(QString log){
   // cout << log.toStdString() << endl;
}

void MainWindow::PortInfo(QString info){
        cout << info.toStdString() << endl;
}
