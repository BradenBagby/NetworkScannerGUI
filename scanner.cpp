#include "scanner.h"

using namespace Scanning;

///info on each scan. Displayed to the user under the 'Cool Info' group box
const QString Scanner::SYN_SCAN_INFO = "SYN scan: The most popular scanning technique. It sends the first packet in a tcp handshake by setting the SYN flag, and uses the response to detect if the port is open/closed/filtered. Because you are only sending part of a TCP handshake, this type of scanning requires root privilages to create custom packets. If the response has a SYN and ACK flag the port is open and a service is running. If the response has either SYN or ACK flag but not both, the port is definitely open. If the response has the RST flag on, the port is closed. Finally, no response is considered as the port being closed/filtered after, for our case, 4 retransmssions.";
const QString Scanner::TCP_SCAN_INFO = "TCP scan. This scan is the easiest to program and to understand. It attempts to complete a tcp handshake with the port. If the handshake is successful, port is open. If unsuccessful, port is closed. This program uses Linux Sockets.";
const QString Scanner::FIN_SCAN_INFO = "FIN scan. Simply sets the FIN flag of a tcp packet. This type of scan is more stealthy than a syn scan but the response cannot be as trusted as no response is considered an open port. Microsoft Windows will label all ports as closed with this type of scan.";
const QString Scanner::XMAS_SCAN_INFO = "XMAS scan. Sets the FIN, PSH, and URG flags of a tcp packet. Called XMAS scan because it lights the packet up like a christmas tree. Similar to the FIN scan, this type of scan is more stealthy than a syn scan but the response cannot be as trusted as no response is considered an open port. Microsoft Windows will label all ports as closed with this type of scan.";

Scanner::Scanner()
{

}


//********************************************************************
//
// Log function
//
// This function emits a log signal with the correct formatting depending on the logLevel
//
// Return Value
// ------------
// void
//
// Value Parameters
// ----------------
// log      QString     the log information
// logLevelIn   LOGLEVEL    the level of the log (VERBOS, WARNINGS, ERRORS)
//
//*******************************************************************
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

//********************************************************************
//
// portInfo function
//
// This function emits a portInfo signal with correct formatting given the parameters
//
// Return Value
// ------------
// void
//
// Value Parameters
// ----------------
//QString       destAddr  the destination address
//int           port       the destination port
//QString       info        the info about the port. Open/Closed/Filtered/etc
//bool          open        used to determine if we should emit the signal or not. If user has selected to see only open ports and this is false, we will not emit
//
//*******************************************************************
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

//********************************************************************
//
// Wait For Scan To Complete function
//
// This function takes a list of QFutures and waits for all them to complete. Then it emits a ScanComplete signal
//
// Return Value
// ------------
// void
//
// Reference Parameters
// ----------------
// QList<QFuture<void>>		threads		The threads to wait for to complete
//
//
//*******************************************************************
void Scanner::_waitForScanComplete( QList<QFuture<void>> &threads){
    for(auto thread : threads){
        thread.waitForFinished();
    }

    //get elapsed time
    auto duration = std::chrono::duration_cast<std::chrono::seconds>
            (std::chrono::steady_clock::now() - scanStartTime);

    emit ScanComplete("SCAN COMPLETE | ports scanned: " + QString::number(portsScanned) + " | open ports: " + QString::number(openPorts)+  "| elapsed time: " + QString::number(duration.count()) + " seconds | errors: " + QString::number(scanErrors) + " | warnings: " + QString::number(scanWarnings));

}


//********************************************************************
//
// Scan Function
//
// This function takes a scan type, destinations, and ports and calls the correct functions to complete the desired scan
//
// Return Value
// ------------
// void
//
// Value Parameters
// ----------------
// QString		scanType		The scan type, can be SYN, TCP Handshake, FIN, or XMAS
// IPv4Range    destinations    the destinations the user has selected to scan
// QList<int>   ports           the ports the user has collected to scan
//
//
//*******************************************************************
void Scanner::Scan(QString scanType, IPv4Range destinations, QList<int> ports)
{

    QList<QFuture<void>> threads = {};

    //reset scan info. This info is incremented throughout scan to keep track of results
    scanStartTime = std::chrono::steady_clock::now();
    openPorts = 0;
    portsScanned = 0;
    scanErrors = 0;
    scanWarnings = 0;


    //determine correct scan function based on user selectoin


    ///do scan threads
    for(auto &dest : destinations){ //loop through each ip
        for(int port : ports){ //loop through each port
            QFuture<void> future;
            if(scanType == "SYN"){
                future  = QtConcurrent::run(this, &Scanner::SynScan,QString::fromStdString(dest.to_string()),port,0);
            }
            else if(scanType == "TCP Handshake"){
                future  = QtConcurrent::run(this, &Scanner::TCPScan,QString::fromStdString(dest.to_string()),port);
            }else if(scanType == "FIN"){
                future  = QtConcurrent::run(this, &Scanner::FINScan,QString::fromStdString(dest.to_string()),port);
            }else if(scanType == "XMAS"){
                future  = QtConcurrent::run(this, &Scanner::XMASScan,QString::fromStdString(dest.to_string()),port);
            }

            threads.push_back(future);
        }
    }

    //wait for scan to complete in a different thread so this is non-blocking
    QtConcurrent::run(this, &Scanner::_waitForScanComplete,threads);
}

//********************************************************************
//
// Set Interface Function
//
// This function sets the interface to be scanned. Uses a destination address to figure out the correct interface.
//
// Return Value
// ------------
// void
//
// Value Parameters
// ----------------
// QString      ip      the ip address that will be used to determine the correct interface
//
//*******************************************************************
void Scanner::SetInterface(QString ip){
    iface = new NetworkInterface(IPv4Address(ip.toStdString()));
}

//********************************************************************
//
// Create and Send TCP Function
//
// This function creates the correct IP/TCP packet with the given flags set and sends it to the given address. It iwll return the response
//
// Return Value
// ------------
// std::unique_ptr<PDU>                     this is the response from the sent TCP packet
//
// Value Parameters
// ----------------
// QString      destAddress     ip address of where to send the packet
// int          port            port of where to send the packet
// bool         syn             enable/disable syn flag of TCP packet
// bool         fin             enable/disable fin flag of TCP packet
// bool         psh             enable/disable psh flag of TCP packet
// bool         urg             enable/disable urg flag of TCP packet
//
//*******************************************************************
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



//********************************************************************
//
// TCP Scan Function
//
// TCP scan. This scan is the easiest to program and to understand. It attempts to complete a tcp handshake with the port. If the handshake is successful, port is open.
// If unsuccessful, port is closed. This program uses Linux Sockets.
//
// Return Value
// ------------
// void
//
// Value Parameters
// ----------------
// QString      destAddress     ip address of where to send the packet
// int          port            port of where to send the packet
//
//***********************************************************************
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




//********************************************************************
//
// Syn Scan Function
//
// SYN scan: The most popular scanning technique. It sends the first packet in a tcp handshake by setting the SYN flag, and uses the response to detect if the port is open/closed/filtered. Because you are only sending part of a TCP handshake, this type of scanning requires root privilages to create custom packets.
// If the response has a SYN and ACK flag the port is open and a service is running. If the response has either SYN or ACK flag but not both, the port is definitely open.
// If the response has the RST flag on, the port is closed. Finally, no response is considered as the port being closed/filtered after, for our case, 4 retransmssions.
//
// Return Value
// ------------
// void
//
// Value Parameters
// ----------------
// QString      destAddress     ip address of where to send the packet
// int          port            port of where to send the packet
//
//***********************************************************************
bool Scanner::SynScan(QString destAddr, int port, int retries = 0){


    //enable syn flag for syn scan.
    std::unique_ptr<PDU> response = _createAndSendTCP(destAddr, port,true, false,false,false);


    if(response == nullptr){
        //for tcp scan, retry a couple times on no response
        if(retries < 4){
            log("WARNING - no response from: " + destAddr + ":" + QString::number(port) + " retransmitting to try again.", LOGLEVEL::WARNINGS);
            return SynScan(destAddr,port,++retries);
        }
        portInfo(destAddr,port,"CLOSED - no response / filtered",false);

        return true;
    }

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
                return true;
            }

            //if SYN flag and ACK flag is on the port is open and a service is running
            else if(tcp_res.flags() == (TCP::SYN && TCP::ACK)) {
                portInfo(destAddr,port,"OPEN - service running",true);
                return true;
            }

            //if SYN flag or ACK flag is on the port is definitely open
            else if(tcp_res.flags() == (TCP::SYN | TCP::ACK)) {
                portInfo(destAddr,port,"OPEN",true);
                return true;
            }
        }
    } catch (...) {
        portInfo(destAddr,port,"CLOSED - non IP/TCP response - closed/filtered",false);
        log("bad response (failed parsing packets) from. Failed parsing resonse packet as IP/TCP so possibly an ICMP packet meaning port is filtered: " + destAddr + ":" + QString::number(port), LOGLEVEL::VERBOS);
        return true;
    }
}

//********************************************************************
//
// FIN Scan Function
//
// FIN scan. Simply sets the FIN flag of a tcp packet. This type of scan is more stealthy than a syn scan but the response cannot be as trusted as no response is considered an open port.
// Microsoft Windows will label all ports as closed with this type of scan.
//
// Return Value
// ------------
// void
//
// Value Parameters
// ----------------
// QString      destAddress     ip address of where to send the packet
// int          port            port of where to send the packet
//
//***********************************************************************
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




//********************************************************************
//
// XMAS Scan Function
//
// XMAS scan. Sets the FIN, PSH, and URG flags of a tcp packet. Called XMAS scan because it lights the packet up like a christmas tree. Similar to the FIN scan,
// this type of scan is more stealthy than a syn scan but the response cannot be as trusted as no response is considered an open port. Microsoft Windows will label all ports as closed with this type of scan.
//
// Return Value
// ------------
// void
//
// Value Parameters
// ----------------
// QString      destAddress     ip address of where to send the packet
// int          port            port of where to send the packet
//
//***********************************************************************
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

//********************************************************************
//
// Custom Packet Function
//
// This function allows a user to specify a custom packet to be sent with custom values for syn, fin, psh, urg flags. Then it will emit the response
//
// Return Value
// ------------
// void
//
// Value Parameters
// ----------------
// QString      destAddress     ip address of where to send the packet
// int          port            port of where to send the packet
// bool         syn             enable/disable syn flag of TCP packet
// bool         fin             enable/disable fin flag of TCP packet
// bool         psh             enable/disable psh flag of TCP packet
// bool         urg             enable/disable urg flag of TCP packet
// int          numberOfPackets number of times to send the packet
//
//***********************************************************************
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









































