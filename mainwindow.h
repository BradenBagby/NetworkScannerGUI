#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "scanner.h"
#include <iostream>

using namespace Scanning;
using namespace std;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    Scanner scanner;

private:
    Ui::MainWindow *ui;

private slots:
    void Log(QString);
    void PortInfo(QString);
    void ScanComplete(QString);
    void on_pushButton_clicked();
    void on_comboBox_scanType_currentIndexChanged(const QString &arg1);
    void on_comboBox_logLevel_currentTextChanged(const QString &arg1);
    void on_checkBox_openPortsOnly_stateChanged(int arg1);
};

#endif // MAINWINDOW_H
