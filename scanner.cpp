#include "scanner.h"

using namespace Scanning;

const QString Scanner::SYN_SCAN_INFO = "SYN scan info blah blah";
const QString Scanner::TCP_SCAN_INFO = "TCP scan info blah blah";
const QString Scanner::FIN_SCAN_INFO = "FIN scan info blah blah";
const QString Scanner::XMAS_SCAN_INFO = "XMAS scan info blah blah";

Scanner::Scanner()
{

}
#include <iostream>

void Scanner::log(QString log, LOGLEVEL logLevelIn){
    if(logLevelIn == ::ERRORS){
        mutex.lock();
        scanErrors ++;
        mutex.unlock();
    }

    if(logLevelIn == ::WARNINGS){
        mutex.lock();
        scanWarnings ++;
        mutex.unlock();
    }


    //make sure we want to display this log
    if((int)logLevelIn >= (int)logLevel){
        emit Log((logLevelIn == ::VERBOS ? "<font color='black'>" : ( logLevelIn == ::ERRORS  ? "<font color='red'>" : "<font color='#ff9966'>")) + log + "</font>");
    }
}

void Scanner::portInfo(QString destAddr, int port, QString info, bool open){

    //keeping info about whole scan
    mutex.lock();
    portsScanned ++;
    if(open){
        openPorts ++;
    }
    mutex.unlock();

    //only emit this info if user has decided to view all port info or the port is open
    if(!displayOnlyOpenPorts || open){
        emit PortInfo("<b><font color='black'>" + destAddr + ":</font>" + (open ? "<font color='green'>" : "<font color='red'>") + QString::number(port) +  "<font></b> " + info);
    }
}

void Scanner::_waitForScanComplete( QList<QFuture<void>> &threads){
    for(auto thread : threads){
        thread.waitForFinished();
    }

    //get elapsed time
    auto duration = std::chrono::duration_cast<std::chrono::seconds>
            (std::chrono::steady_clock::now() - scanStartTime);

    emit ScanComplete("SCAN COMPLETE | ports scanned: " + QString::number(portsScanned) + " | open ports: " + QString::number(openPorts)+  "| elapsed time: " + QString::number(duration.count()) + " seconds | errors: " + QString::number(scanErrors) + " | warnings: " + QString::number(scanWarnings));

}

void Scanner::Scan(QString scanType, IPv4Range destinations, QList<int> ports)
{

    QList<QFuture<void>> threads = {};

    //reset scan info
    scanStartTime = std::chrono::steady_clock::now();
    openPorts = 0;
    portsScanned = 0;
    scanErrors = 0;
    scanWarnings = 0;


    //determine correct scan function based on user selectoin
    auto scanFunction = &Scanner::SynScan;
    if(scanType == "TCP Handshake"){
        scanFunction = &Scanner::TCPScan;
    }else if(scanType == "FIN"){
        scanFunction = &Scanner::FINScan;
    }else if(scanType == "XMAS"){
        scanFunction = &Scanner::XMASScan;
    }

    ///do scan threads
    for(auto &dest : destinations){ //loop through each ip
        for(int port : ports){ //loop through each port
            QFuture<void> future = QtConcurrent::run(this, scanFunction,QString::fromStdString(dest.to_string()),port);
            threads.push_back(future);
        }
    }

    //wait for scan to complete in a different thread so this is non-blocking
    QtConcurrent::run(this, &Scanner::_waitForScanComplete,threads);
}

void Scanner::SetInterface(QString ip){
    iface = new NetworkInterface(IPv4Address(ip.toStdString()));
}

std::unique_ptr<PDU> Scanner::_createAndSendTCP(QString destAddr, int port,bool syn, bool fin, bool psh, bool urg){

    if(iface == nullptr){
        log("ERROR - no interface set. Automatically setting interface", LOGLEVEL::ERRORS);
        SetInterface(destAddr);
    }


    //Tins uses these object for addresses and network interface
    IPv4Address dest(destAddr.toStdString());
    NetworkInterface::Info info = iface->addresses();
    IPv4Address host(info.ip_addr);


    //used to send packet
    PacketSender sender;


    // create the packets. This creates an IP packet with an encapsulated TCP packet
    IP ip = IP(dest, host) / TCP();

    //configure TCP Packet
    TCP& tcp = ip.rfind_pdu<TCP>();
    tcp.set_flag(TCP::SYN, syn);
    tcp.set_flag(TCP::FIN, fin);
    tcp.set_flag(TCP::PSH, psh);
    tcp.set_flag(TCP::URG, urg);
    tcp.sport((rand() % 1000) + 1025); //host port doesnt matter. This just makes it between 1025 and 2025
    tcp.dport(static_cast<uint16_t>(port)); //destination port to scan

    log("Sending TCP packet to: " + destAddr + ":" + QString::number(port) + " with flags: SYN=" + QString::number(syn) + " FIN=" + QString::number(fin) +" PSH=" + QString::number(psh) +" urg=" + QString::number(urg), LOGLEVEL::VERBOS);

    //send and receive response
    std::unique_ptr<PDU> response(sender.send_recv(ip, *iface));

    return response;

}



////////TCP (Full Handshake) SCAN
void Scanner::TCPScan(QString destAddr, int port){
    int sock = 0;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        log("ERROR - failed to open socket to TCPScan host: " + destAddr + ":" + QString::number(port), LOGLEVEL::ERRORS);
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(static_cast<uint16_t>(port));

    if(inet_pton(AF_INET, destAddr.toStdString().c_str(), &serv_addr.sin_addr)<=0)
    {
        log("ERROR - failed to convert destAddress to binary form for host: " + destAddr + ":" + QString::number(port), LOGLEVEL::ERRORS);
        return;
    }

    log("Trying to connect using TCP (full handshake) to destination: " + destAddr + ":" + QString::number(port), LOGLEVEL::VERBOS);

    if(::connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) >= 0){
        log("Connection using TCP (full handshake) established with : " + destAddr + ":" + QString::number(port), LOGLEVEL::VERBOS);
        portInfo(destAddr,port,"OPEN",true);
    }else{
        log("Connection using TCP (full handshake) timeout with : " + destAddr + ":" + QString::number(port), LOGLEVEL::VERBOS);
        portInfo(destAddr,port,"CLOSED",false);
    }
    close(sock);

}




////////SYN SCAN
void Scanner::SynScan(QString destAddr, int port){


    //enable syn flag for syn scan.
    std::unique_ptr<PDU> response = _createAndSendTCP(destAddr, port,true, false,false,false);


    if(response == nullptr){
        portInfo(destAddr,port,"CLOSED - no response / filtered",false);
        log("WARNING - no response from: " + destAddr + ":" + QString::number(port), LOGLEVEL::WARNINGS);
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
                portInfo(destAddr,port,"CLOSED",false);
                return;
            }

            //if SYN flag and ACK flag is on the port is open and a service is running
            else if(tcp_res.flags() == (TCP::SYN && TCP::ACK)) {
                portInfo(destAddr,port,"OPEN - service running",true);
                return;
            }

            //if SYN flag or ACK flag is on the port is definitely open
            else if(tcp_res.flags() == (TCP::SYN | TCP::ACK)) {
                portInfo(destAddr,port,"OPEN",true);
                return;
            }
        }
    } catch (...) {
        portInfo(destAddr,port,"CLOSED - non IP/TCP response - closed/filtered",false);
        log("bad response (failed parsing packets) from. Failed parsing resonse packet as IP/TCP so possibly an ICMP packet meaning port is filtered: " + destAddr + ":" + QString::number(port), LOGLEVEL::VERBOS);
        return;
    }
}


////////FIN SCAN
void Scanner::FINScan(QString destAddr, int port){


    //enabel the FIN flag for a FIN scan
    std::unique_ptr<PDU> response = _createAndSendTCP(destAddr, port,false, true,false,false);

    if(response == nullptr){
        portInfo(destAddr,port,"OPEN - no response",true);
        return;}

    try {


        //get protocol packets from response
        IP& ip_res = response->rfind_pdu<IP>();
        TCP& tcp_res = response->rfind_pdu<TCP>();


        //check response to see if port is open or closed

        if(tcp_res.sport() == port) {

            log("Received response from " + destAddr + +":" + QString::number(port) + " with | rst: " + QString::number(tcp_res.get_flag(TCP::RST)), LOGLEVEL::VERBOS);

            //if RST flag is on, the port is closed
            if(tcp_res.get_flag(TCP::RST)) {
                portInfo(destAddr,port,"CLOSED",false);
                return;
            }
        }
    } catch (...) {
        portInfo(destAddr,port,"FILTERED - non IP/TCP response",false);
        log("bad response (failed parsing packets) from. Failed parsing resonse packet as IP/TCP so possibly an ICMP packet meaning port is filtered: " + destAddr + ":" + QString::number(port), LOGLEVEL::VERBOS);
        return;
    }
}




////////XMas SCAN
void Scanner::XMASScan(QString destAddr, int port){


    //enabel the FIN, PSH, and URG flags for a XMas scan
    std::unique_ptr<PDU> response = _createAndSendTCP(destAddr, port,false, true,true,true);

    if(response == nullptr){
        portInfo(destAddr,port,"OPEN - no response",true);
        return;}

    try {


        //get protocol packets from response
        IP& ip_res = response->rfind_pdu<IP>();
        TCP& tcp_res = response->rfind_pdu<TCP>();


        //check response to see if port is open or closed

        if(tcp_res.sport() == port) {

            log("Received response from " + destAddr + +":" + QString::number(port) + " with | rst: " + QString::number(tcp_res.get_flag(TCP::RST)), LOGLEVEL::VERBOS);

            //if RST flag is on, the port is closed
            if(tcp_res.get_flag(TCP::RST)) {
                portInfo(destAddr,port,"CLOSED",false);
                return;
            }
        }
    } catch (...) {
        portInfo(destAddr,port,"FILTERED - non IP/TCP response",false);
        log("bad response (failed parsing packets) from. Failed parsing resonse packet as IP/TCP so possibly an ICMP packet meaning port is filtered: " + destAddr + ":" + QString::number(port), LOGLEVEL::VERBOS);
        return;
    }
}
void Scanner::CustomPacket(QString destAddr, int port,bool syn, bool fin, bool psh, bool urg,int numberOfPackets){

    for(int i = 0; i < numberOfPackets; i ++){
        emit PortInfo("---CUSTOM PACKET: " + QString::number(i));
        std::unique_ptr<PDU> response = _createAndSendTCP(destAddr, port,syn, fin,psh,urg);
        emit PortInfo("Sending TCP Packet to " + destAddr + +":" + QString::number(port) + " with | SYN: " + QString::number(syn) + " FIN: " + QString::number(fin) + " PSH: " + QString::number(psh) + " URG: " + QString::number(urg));
        QString portInfo = "";
        if(response == nullptr){
        portInfo = "Received no response.";
        }else{
            try {


                //get protocol packets from response
                IP& ip_res = response->rfind_pdu<IP>();
                TCP& tcp_res = response->rfind_pdu<TCP>();


                //check response to see if port is open or closed

                if(tcp_res.sport() == port) {
                    portInfo = ("Received response from " + destAddr + +":" + QString::number(port) + " with | syn: " + QString::number(tcp_res.get_flag(TCP::SYN)) + " ack: " + QString::number(tcp_res.get_flag(TCP::ACK)) + " rst: " + QString::number(tcp_res.get_flag(TCP::RST)));
                }else{
                    portInfo = "Received response with different port. ERROR";
                }
            } catch (...) {

                portInfo = "Received response that wasnt a TCP packet. Possibly ICMP.";
            }

        }

        emit PortInfo(portInfo);
    }

}









































