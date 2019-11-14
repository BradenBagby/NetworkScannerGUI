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

    //setup the combo boxes
    ui->comboBox_scanType->addItem("SYN");
    ui->comboBox_scanType->addItem("TCP Handshake");
    ui->comboBox_scanType->addItem("FIN");
    ui->comboBox_scanType->addItem("XMAS");

    ui->comboBox_logLevel->addItem("VERBOS");
    ui->comboBox_logLevel->addItem("ERRORS");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::Log(QString log){
    cout << log.toStdString() << endl;
    ui->textBrowser_log->append(log);
}

void MainWindow::PortInfo(QString info){
    cout << info.toStdString() << endl;
    ui->textBrowser_scanInfo->append(info);
}

void MainWindow::on_pushButton_clicked()
{
    QString scanType = ui->comboBox_scanType->currentText();
    ui->textBrowser_scanInfo->append("--------------NEW SCAN: <b>" + scanType +"</b>--------------------");
}

//sets the cool info for the user to learn about network scanning
void MainWindow::on_comboBox_scanType_currentIndexChanged(const QString &arg1)
{
    QString currentText = ui->comboBox_scanType->currentText();
    QString helpText = "";
    if(currentText == "SYN"){
        helpText = Scanner::SYN_SCAN_INFO;
    }else if(currentText == "TCP Handshake"){
        helpText = Scanner::TCP_SCAN_INFO;
    }else if(currentText == "FIN"){
        helpText = Scanner::FIN_SCAN_INFO;
    }else if(currentText == "XMAS"){
        helpText = Scanner::XMAS_SCAN_INFO;
    }

    ui->textBrowser_coolInfo->clear();
    ui->textBrowser_coolInfo->setText(helpText);
}
