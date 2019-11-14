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
    QObject::connect(&scanner, &Scanner::ScanComplete, this, &MainWindow::ScanComplete);

    //setup the combo boxes
    ui->comboBox_scanType->addItem("SYN");
    ui->comboBox_scanType->addItem("TCP Handshake");
    ui->comboBox_scanType->addItem("FIN");
    ui->comboBox_scanType->addItem("XMAS");

    ui->comboBox_logLevel->addItem("VERBOS");
    ui->comboBox_logLevel->addItem("WARNINGS");
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
void MainWindow::ScanComplete(QString info){
    ui->textBrowser_scanInfo->append(info);
    QString scanType = ui->comboBox_scanType->currentText();
    ui->textBrowser_scanInfo->append("--------------Scan Complete: <b>" + scanType +"</b>--------------------");
    ui->textBrowser_log->append("--------------Scan Complete: <b>" + scanType +"</b>--------------------");

    //re-enable ui
    ui->groupBox_configureScan->setEnabled(true);
    ui->groupBox_custom->setEnabled(true);
    ui->groupBox_displayOptions->setEnabled(true);
}

void MainWindow::on_pushButton_clicked()
{



    QString scanType = ui->comboBox_scanType->currentText();
    ui->textBrowser_scanInfo->append("--------------NEW SCAN: <b>" + scanType +"</b>--------------------");
    ui->textBrowser_log->append("--------------NEW SCAN: <b>" + scanType +"</b>--------------------");

    //get ip range

    QString startIP = ui->textEdit_IPStart->toPlainText();
    QString endIP = ui->textEdit_IPEnd->toPlainText();
    IPv4Range range(IPv4Address(startIP.toStdString()),IPv4Address(endIP.toStdString()));


    //get port range
    QList<int> ports;
    try {
        QStringList split = ui->textEdit_IPPorts->toPlainText().split(",");
        for(QString s : split){
            if(s.contains("-")){
                QStringList twoRange = s.split("-");
                if(twoRange.count() == 2){
                    int start = twoRange[0].toInt();
                    int end = twoRange[1].toInt();
                    for(int i = start; i <= end; i ++){
                        ports.push_back(i);
                    }
                }
            }else{
                ports.push_back(s.toInt());
            }
        }
    } catch (...) {
        Log("<font color='red'>failed to get ports. Please check and make sure your ports are separated by a comma like: '22,80,20' or range '20-80'.</font>");
        return;
    }


    //set interface
    if(range.begin() == range.end()){
        return;
    }
    scanner.SetInterface(startIP);

    //disabel scan configuration during scan
    ui->groupBox_configureScan->setEnabled(false);
    ui->groupBox_custom->setEnabled(false);
    ui->groupBox_displayOptions->setEnabled(false);


    //call scan
    scanner.Scan(ui->comboBox_scanType->currentText(),range,ports);


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

void MainWindow::on_comboBox_logLevel_currentTextChanged(const QString &current)
{
    scanner.logLevel = (current == "VERBOS" ? ::VERBOS : (current == "ERRORS" ? ::ERRORS : ::WARNINGS));

}

void MainWindow::on_checkBox_openPortsOnly_stateChanged(int arg1)
{
    scanner.displayOnlyOpenPorts = arg1;
}

void MainWindow::on_pushButton_sendTCP_clicked()
{
    bool syn = ui->checkBox_custom_syn->isChecked();
    bool fin = ui->checkBox_custom_fin->isChecked();
    bool psh = ui->checkBox_custom_psh->isChecked();
    bool urg = ui->checkBox_custom_urg->isChecked();

    QString destination = ui->textEdit_custom_destination->toPlainText();
    int packetCount = ui->textEdit_custom_packetCount->toPlainText().toInt();
    int port = ui->textEdit_custom_port->toPlainText().toInt();

    ui->groupBox_configureScan->setEnabled(false);
    ui->groupBox_custom->setEnabled(false);
    ui->groupBox_displayOptions->setEnabled(false);
    ui->groupBox_custom->setEnabled(false);
    qApp->processEvents(); //update ui
    scanner.CustomPacket(destination,port,syn,fin,psh,urg,packetCount);
    ui->groupBox_configureScan->setEnabled(true);
    ui->groupBox_custom->setEnabled(true);
    ui->groupBox_displayOptions->setEnabled(true);
    ui->groupBox_custom->setEnabled(true);

}
