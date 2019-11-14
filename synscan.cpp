#include "synscan.h"



QString SynScan::Scan(QString hostAddr, QString destAddr, int port){

    //Tins uses this object for addresses to build the packets
    IPv4Address dest(destAddr.toStdString());

    //used to send packet
    PacketSender sender;

    // create the packets. This creates an IP packet with an encapsulated TCP packet
    IP ip = IP(dest, hostAddr.toStdString()) / TCP();

    //configure TCP Packet
    TCP& tcp = ip.rfind_pdu<TCP>();
    tcp.set_flag(TCP::SYN, 1); //enable SYN flag for syn scan
    tcp.sport((rand() % 1000) + 1025); //host port doesnt matter. This just makes it between 1025 and 2025
    tcp.dport(static_cast<uint16_t>(port)); //destination port to scan

    //send and receive response
    std::unique_ptr<PDU> response(sender.send_recv(ip, hostAddr.toStdString()));

    if(response == nullptr){return "CLOSED - no response";}




}
