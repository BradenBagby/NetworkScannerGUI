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

///system socket libraries
#include <sys/socket.h>
#include <arpa/inet.h>

//threading
#include <mutex>
#include <QtConcurrent/QtConcurrent>

//elapsed time
#include <chrono>

namespace Scanning {

using namespace Tins;

enum LOGLEVEL{
    VERBOS = 0,
    WARNINGS = 1,
    ERRORS = 2
};

class Scanner : public QObject
{
    Q_OBJECT


public:
    Scanner();
    int displayOnlyOpenPorts = false; //should we display all port info or only open ports
    LOGLEVEL logLevel = VERBOS;
    void Scan(QString scanType, IPv4Range destinations, QList<int> ports);
    void SetInterface(QString ip); //configures interface for given ip
    void CustomPacket(QString destAddr, int port,bool syn, bool fin, bool psh, bool urg, int numberOfPackets);





    //SCANNING INFO
    static const QString SYN_SCAN_INFO;
    static const QString TCP_SCAN_INFO;
    static const QString FIN_SCAN_INFO;
    static const QString XMAS_SCAN_INFO;

private:
    void log(QString, LOGLEVEL);
    void portInfo(QString,int,QString, bool open);
    void _waitForScanComplete(QList<QFuture<void>> &futures); //a thread that just waits for all scans to complete then it emits a signal




    std::unique_ptr<PDU> _createAndSendTCP(QString destAddr, int port,bool syn, bool fin, bool psh, bool urg); //creates and sends tcp packet with specified flags set

    //scans
    bool SynScan(QString destAddr, int port, int retries); //syn scan sends first packet in the tcp three way handshake. if gets ack/syn back, the port is open. Root privalages would be required on the computer
    void TCPScan(QString destAddr, int port); //TCP Scan simply trys to connect to a port with full tcp handshake and sees if connection succeeds or not.
    void FINScan(QString destAddr, int port);
    void XMASScan(QString destAddr, int port);
    std::chrono::steady_clock::time_point scanStartTime;
    int portsScanned = 0;
    int openPorts = 0;
    int scanErrors = 0;
    int scanWarnings = 0;
    std::mutex mutex;

    NetworkInterface *iface = nullptr; //stores network interface info for tins


signals:
    void Log(QString);
    void PortInfo(QString);
    void ScanComplete(QString);
};
}

#endif // SCANNER_H
