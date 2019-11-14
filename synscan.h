#ifndef SYNSCAN_H
#define SYNSCAN_H

#include <QString>


#include <unistd.h>
#include <tins/ip.h>
#include <tins/tcp.h>
#include <tins/ip_address.h>
#include <tins/ethernetII.h>
#include <tins/network_interface.h>
#include <tins/utils.h>
#include <tins/packet_sender.h>
#include <tins/tins.h>



using namespace Tins;

class SynScan
{
public:
    static QString Scan(QString host, QString dest, int port);
};

#endif // SYNSCAN_H
