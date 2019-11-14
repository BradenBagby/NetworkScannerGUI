#ifndef SCANNER_H
#define SCANNER_H
#include <QObject> //use qt signals and slots

///TINS PACKET CONSTRUCTION LIBRARY
#include <unistd.h>
#include <tins/ip.h>
#include <tins/tcp.h>
#include <tins/ip_address.h>
#include <tins/ethernetII.h>
#include <tins/network_interface.h>
#include <tins/utils.h>
#include <tins/packet_sender.h>
#include <tins/tins.h>




namespace Scanning {

using namespace Tins;

enum LOGLEVEL{
    VERBOS = 0,
    ERRORS = 1
};

class Scanner : public QObject
{
    Q_OBJECT


public:
    Scanner();
    int displayOnlyOpenPorts = false; //should we display all port info or only open ports
    LOGLEVEL logLevel = VERBOS;
    void SynScan(QString hostAddr, QString destAddr, int port); //syn scan sends first packet in the tcp three way handshake. if gets ack/syn back, the port is open

private:
    void log(QString, LOGLEVEL);
    void portInfo(QString, bool open);


signals:
    void Log(QString);
    void PortInfo(QString);
};
}

#endif // SCANNER_H
