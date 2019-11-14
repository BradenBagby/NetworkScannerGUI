#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "scanner.h"

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
};

#endif // MAINWINDOW_H