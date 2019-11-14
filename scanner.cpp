#include "scanner.h"

using namespace Scanning;

Scanner::Scanner()
{

}

void Scanner::log(QString log, LOGLEVEL logLevelIn){

    //make sure we want to display this log
    if(logLevelIn >= logLevel){
        emit Log(log);
    }
}











////////SYN SCAN
void Scanner::SynScan(QString hostAddr, QString destAddr, int port){

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

    log("Sending TCP packet with SYN Flag enabled to destination: " + destAddr + ":" + QString::number(port), LOGLEVEL::VERBOS);

    //send and receive response
    std::unique_ptr<PDU> response(sender.send_recv(ip, hostAddr.toStdString()));



    if(response == nullptr){
        portInfo("CLOSED - no response",false);
        log("ERROR - no response from: " + destAddr + ":" + QString::number(port), LOGLEVEL::ERRORS);
        return;}

    try {


    //get protocol packets from response
    IP& ip_res = response->rfind_pdu<IP>();
     TCP& tcp_res = response->rfind_pdu<TCP>();


    //check response to see if port is open or closed

    if(tcp_res.sport() == port) {

          log("Received response from " + destAddr + +":" + QString::number(port) + " with | syn: " + QString::number(tcp_res.get_flag(TCP::SYN)) + " ack: " + QString::number(tcp_res.get_flag(TCP::ACK)) + " rst: " + QString::number(tcp_res.get_flag(TCP::RST)), LOGLEVEL::VERBOS);

        //if RST flag is on, the port is closed
        if(tcp_res.get_flag(TCP::RST)) {
           portInfo("CLOSED",false);
            return;
        }

        //if SYN flag and ACK flag is on the port is open and a service is running
        else if(tcp_res.flags() == (TCP::SYN && TCP::ACK)) {
           portInfo("OPEN - service running",true);
            return;
        }

        //if SYN flag or ACK flag is on the port is definitely open
        else if(tcp_res.flags() == (TCP::SYN | TCP::ACK)) {
           portInfo("OPEN",true);
            return;
        }
    }
    } catch (...) {
        portInfo("CLOSED - bad response",false);
              log("ERROR - bad response (failed parsing packets) from: " + destAddr + ":" + QString::number(port), LOGLEVEL::ERRORS);
        return;
    }






}

































