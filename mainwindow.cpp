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
}

MainWindow::~MainWindow()
{
    delete ui;
}
