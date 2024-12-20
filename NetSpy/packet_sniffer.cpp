#include "packet_sniffer.h"
#include "ui_packet_sniffer.h"
#include "notification.h"
#include <QMessageBox>
#include <QString>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <windows.h>
#include <QThread>
#include <QDebug>
#include <QScrollBar>
#include <QMutexLocker>
#include <QLabel>
#include <QFont>
#include <QFileDialog>

int no = 1;
QString devInterface;
QFont font;
int selection = 0;

packet_sniffer::packet_sniffer(QWidget *parent, QListWidgetItem *item, pcap_if_t *d, QString filter)
    : QDialog(parent), ui(new Ui::packet_sniffer), item(item), d(d), started(false), filter(filter) {
    ui->setupUi(this);
    cargarInterfaz();

    trayIcon = new QSystemTrayIcon(this);
    QString iconPath = QApplication::applicationDirPath() + "/img/image.ico";
    trayIcon->setIcon(QIcon(iconPath));
    trayIcon->setVisible(true);

    this->comenzarIntercepcion();
    connect(this->captureThread, &PacketCaptureThread::connectionDetected, this, &packet_sniffer::showNotification);
    putFilter();
}

PacketCaptureThread::PacketCaptureThread(pcap_t *adhandle, QObject *parent) : QThread(parent), adhandle(adhandle), paused(false), stopped(false) {}

void PacketCaptureThread::pause() {
    QMutexLocker locker(&this->mutex);
    this->paused = true;
}

void PacketCaptureThread::resume() {
    QMutexLocker locker(&this->mutex);
    this->paused = false;
    this->condition.wakeOne();
}

void PacketCaptureThread::stop() {
    QMutexLocker locker(&this->mutex);
    this->stopped = true;
    this->paused = false;
    this->condition.wakeOne();
}

packet_sniffer::~packet_sniffer() {
    if (this->captureThread) {
        this->captureThread->quit();
        this->captureThread->wait();
        delete this->captureThread;
    }
    delete ui;
}

void PacketCaptureThread::run() {
    while (true) {
        this->mutex.lock();

        if (this->stopped) {
            this->mutex.unlock();
            break;
        }

        if (this->paused) {
            this->condition.wait(&this->mutex);
        }

        this->mutex.unlock();
        //pcap_loop(adhandle, 0, PacketCaptureThread::packetHandler, reinterpret_cast<u_char*>(this));
        this->processPackets();
    }
}

void PacketCaptureThread::processPackets() {
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int result;

    while (true) {
        this->mutex.lock();

        if (this->stopped) {
            this->mutex.unlock();
            break;
        }

        if (this->paused) {
            this->condition.wait(&this->mutex);
        }

        this->mutex.unlock();

        result = pcap_next_ex(this->adhandle, &header, &pkt_data);
        if (result == 1) {
            this->packetHandler(reinterpret_cast<u_char*>(this), header, pkt_data);
        } else if (result == 0) {
            continue;
        } else {
            break;
        }
    }
}

void PacketCaptureThread::packetHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    auto* captureThread = reinterpret_cast<PacketCaptureThread*>(param);

    struct tm ltime;
    char timestr[16];
    cabecera_ip* ih;
    cabecera_udp* uh;
    u_int ip_len;
    u_short sport, dport;
    time_t local_tv_sec;

    // Convertir de timestamp to readable format /
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

    // Regresar la posicion de la cabecera ip /
    ih = (cabecera_ip*)(pkt_data + 14); // Trama o de la cabecera Ethernet/

    //Regresar la posicion de la cabecera udp /
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (cabecera_udp*)((u_char*)ih + ip_len);

    // Convertir desde byte de internet a byte de host /
    sport = ntohs(uh->sport);
    dport = ntohs(uh->dport);

    if(selection == 0){
        if(sport == 1194 || dport == 1194){
            emit captureThread->connectionDetected("Conexion por VPN");
        }
    }else if(selection == 1){
        if(sport == 1701 || dport == 1701){
            emit captureThread->connectionDetected("Conexion por L2TP");
        }
    }else if(selection == 2){
        if(sport == 1723 || dport == 1723){
            emit captureThread->connectionDetected("Conexion por PPTP");
        }
    }else if(selection == 3){
        if(sport == 22 || dport == 22){
            emit captureThread->connectionDetected("Conexion por SSH");
        }
    }else if(selection == 4){
        if(sport == 23 || dport == 23){
            emit captureThread->connectionDetected("Conexion por TELNET");
        }
    }else if(selection == 5){
        if(sport == 3389 || dport == 3389){
            emit captureThread->connectionDetected("Conexion por RDP");
        }
    }

    //Informacion general de x paquete
    int length = header->len;
    QString srcAddr = QString("%1.%2.%3.%4").arg(ih->saddr.byte1).arg(ih->saddr.byte2).arg(ih->saddr.byte3).arg(ih->saddr.byte4);
    QString destAddr = QString("%1.%2.%3.%4").arg(ih->daddr.byte1).arg(ih->daddr.byte2).arg(ih->daddr.byte3).arg(ih->daddr.byte4);
    u_char tos = ih->tos;

    //Informacion estructurada del paquete x
    QString structInfo;

    cabecera_ethernet* eth = (cabecera_ethernet*)pkt_data;
    QString srcMac = QString("%1:%2:%3:%4:%5:%6").arg(eth->src[0], 2, 16, QChar('0'))
                         .arg(eth->src[1], 2, 16, QChar('0')).arg(eth->src[2], 2, 16, QChar('0'))
                         .arg(eth->src[3], 2, 16, QChar('0')).arg(eth->src[4], 2, 16, QChar('0'))
                         .arg(eth->src[5], 2, 16, QChar('0'));

    QString destMac = QString("%1:%2:%3:%4:%5:%6").arg(eth->dest[0], 2, 16, QChar('0'))
                          .arg(eth->dest[1], 2, 16, QChar('0')).arg(eth->dest[2], 2, 16, QChar('0'))
                          .arg(eth->dest[3], 2, 16, QChar('0')).arg(eth->dest[4], 2, 16, QChar('0'))
                          .arg(eth->dest[5], 2, 16, QChar('0'));

    structInfo.append("<h3 style='color:purple;'>Paquete " + QString::number(no) + "</h3>");
    structInfo.append("<p><b>Bytes capturados:</b> " + QString::number(length) + " bytes (" + QString::number(length * 8) + " bits)</p>");
    structInfo.append("<p><b>Dispositivo:</b> " + devInterface + "</p>");
    structInfo.append("<p><b>Ethernet</b> - <b>src:</b> " + srcMac + ", <b>dst:</b> " + destMac + "</p>");
    structInfo.append("<p><b>IP</b> - <b>src:</b> " + srcAddr + ", <b>dst:</b> " + destAddr + "</p>");
    structInfo.append("<p><b>Tipo de servicios</b>" + QString(", DSCP=%1 (Clase de Servicio), ECN=%2 (Notificación de congestión)\n").arg(tos >> 2).arg(tos & 0x03) + "</p>");

    //Informacion RAW del paquete
    QString rawInfoCaptured;
    QString translatedInfo;
    QString rawInfo;

    const u_char* raw_ip_packet = pkt_data + 14;
    int raw_ip_packet_length = header->caplen - 14;

    for (int i = 0; i < raw_ip_packet_length; i++) {

        // rawInfo.append("<span style='font-family: Courier; font-size: 12px;'>");
        rawInfo.append(QString("%1 ").arg(raw_ip_packet[i], 2, 16, QChar('0')).toUpper());
        // rawInfo.append("</span>");

        // Traducir a texto legible (ASCII)
        char byte = static_cast<char>(raw_ip_packet[i]);
        // translatedInfo.append("<span style='font-family: Courier; font-size: 12px;'>");
        if (isprint(byte)) { // Si el byte es imprimible
            translatedInfo.append(byte);
        } else { // Si no es imprimible, agregar un marcador (p. ej., '.')
            translatedInfo.append('.');
        }
        // translatedInfo.append("</span>");

        // Formatear para grupos de 16 bytes
        if ((i + 1) % 16 == 0) {
            rawInfo.append("  ");
            rawInfo.append(translatedInfo);
            rawInfo.append("\n");
            translatedInfo.clear();
        }

    }


    //Protocolo
    uint16_t protocolo = ih->proto;
    QString nombreProtocolo;
    QString info;
    u_int offset = ip_len + 14;

    switch (protocolo) {
    case 0: {
        nombreProtocolo = "HOPOPT";
        structInfo.append("Hop by hop");
        break;
    }
    case 1: {
        nombreProtocolo = "ICMP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Internet Control Message Protocol");
        break;
    }
    case 2: {
        nombreProtocolo = "IGMP";
        cabecera_igmp* igmp = (cabecera_igmp*)((u_char*)ih + ip_len);
        QString groupAddr = QString("%1:%2:%3:%4").arg(igmp->group_addr.byte1).arg(igmp->group_addr.byte2).arg(igmp->group_addr.byte3).arg(igmp->group_addr.byte4);
        QString type = "Membership ";
        switch (igmp->type) {
        case 17: type.append("Query"); break;
        case 18: type.append("Report (v1)"); break;
        case 22: type.append("Report (v2)"); break;
        case 23: type.append("Leave Group"); break;
        default: type.append("Unknown IGMP type"); break;
        }
        info.append(type + " " + groupAddr + " ");
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Internet Group Management Protocol");
        break;
    }
    case 3: {
        nombreProtocolo = "GGP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Gateway-to-Gateway Protocol");
        break;
    }
    case 4: {
        nombreProtocolo = "IPv4";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Internet Protocol version 4");
        break;
    }
    case 5: {
        nombreProtocolo = "ST";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Stream");
        break;
    }
    case 6: {
        nombreProtocolo = "TCP";
        cabecera_tcp* tcp = (cabecera_tcp*)((u_char*)ih + ((ih->ver_ihl & 0x0F) * 4));
        uint16_t sport = ntohs(tcp->sport);
        uint16_t dport = ntohs(tcp->dport);
        info.append(QString::number(ntohs(tcp->sport)) + " -> " + QString::number(ntohs(tcp->dport)) + " Seq=" + QString::number(tcp->sq) + " Ack=" + QString::number(tcp->ack) + " Win=" + QString::number(tcp->window) + " Len=" + QString::number(ih->tlen - ih->ver_ihl - ((tcp->data_offset >> 4) * 4)) + " ");
        info.append(QString("Tos=%1, Flags=%2").arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append(QString("Transmission Control Protocol, src Port: %1, dst Port: %2, Seq: %3, Ack: %4, Len: %5 ").arg(ntohs(tcp->sport))
                              .arg(ntohs(tcp->dport)).arg(tcp->sq).arg(tcp->ack).arg(ih->tlen - ih->ver_ihl - ((tcp->data_offset >> 4) * 4)));

        if (sport == 23 || dport == 23) {
            emit captureThread->connectionDetected("Conexión con Telnet detectada, cuidado, muy inseguro");
        } else if (sport == 22 || dport == 22) {
            emit captureThread->connectionDetected("Conexión con SSH detectada");
        }

        //emit captureThread->connectionDetected("Paquete TCP");
        break;
    }
    case 7: {
        nombreProtocolo = "CBT";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("CBT");
        break;
    }
    case 8: {
        nombreProtocolo = "EGP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Exterior Gateway Protocol");
        break;
    }
    case 9: {
        nombreProtocolo = "IGP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Interior Gateway Protocol");
        break;
    }
    case 10: {
        nombreProtocolo = "BBN-RCC-MON";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("BBN RCC Monitoring");
        break;
    }
    case 11: {
        nombreProtocolo = "NVP-II";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Network Voice Protocol");
        break;
    }
    case 12: {
        nombreProtocolo = "PUP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("PUP");
        break;
    }
    case 13: {
        nombreProtocolo = "ARGUS";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("ARGUS");
        break;
    }
    case 14: {
        nombreProtocolo = "EMCON";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("EMCON");
        break;
    }
    case 15: {
        nombreProtocolo = "XNET";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Cross Net Debugger");
        break;
    }
    case 16: {
        nombreProtocolo = "CHAOS";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Chaos");
        break;
    }
    case 17: {
        nombreProtocolo = "UDP";
        cabecera_udp* udp = (cabecera_udp*)((u_char*)ih + ((ih->ver_ihl & 0x0F) * 4));
        info.append(QString::number(ntohs(udp->sport)) + "->" + QString::number(ntohs(udp->dport)) + " Len=" + QString::number(udp->len) + " ");
        structInfo.append(QString("User Datagram Protocol, src Port: %1, dst Port: %2 \n").arg(sport).arg(dport));
        info.append(QString("Tos=%1, Flags=%2").arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append(QString("Data (%1 bytes)").arg(udp->len));
        break;
    }
    case 18: {
        nombreProtocolo = "MUX";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Multiplexing");
        break;
    }
    case 19: {
        nombreProtocolo = "DCN-MEAS";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("DCN Measurement Subsystems");
        break;
    }
    case 20: {
        nombreProtocolo = "HMP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Host Monitoring");
        break;
    }
    case 21: {
        nombreProtocolo = "PRM";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Packet Radio Measurement");
        break;
    }
    case 22: {
        nombreProtocolo = "XNS-IDP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("XEROX NS IDP");
        break;
    }
    case 23: {
        nombreProtocolo = "TRUNK-1";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Trunk-1");
        break;
    }
    case 24: {
        nombreProtocolo = "TRUNK-2";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Trunk-2");
        break;
    }
    case 25: {
        nombreProtocolo = "LEAF-1";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Leaf-1");
        break;
    }
    case 26: {
        nombreProtocolo = "LEAF-2";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("LEAF-2");
        break;
    }
    case 27: {
        nombreProtocolo = "RDP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Reliable Data Protocol");
        break;
    }
    case 28: {
        nombreProtocolo = "IRTP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Internet Reliable Transaction");
        break;
    }
    case 29: {
        nombreProtocolo = "ISO-TP4";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("ISO Transport Protocol Class 4");
        break;
    }
    case 30: {
        nombreProtocolo = "NETBLT";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Bulk Data Transfer Protocol");
        break;
    }
    case 31: {
        nombreProtocolo = "MFE-MSP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("MFE Network Services Protocol");
        break;
    }
    case 32: {
        nombreProtocolo = "MERIT-INP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("MERIT Internodal Protocol");
        break;
    }
    case 33: {
        nombreProtocolo = "DCCP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Datagram Congestion Control Protocol");
        break;
    }
    case 34: {
        nombreProtocolo = "3PC";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Third Party Connect Protocol");
        break;
    }
    case 35: {
        nombreProtocolo = "IDPR";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Inter-Domain Policy Routing Protocol");
        break;
    }
    case 36: {
        nombreProtocolo = "XTP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("XTP");
        break;
    }
    case 37: {
        nombreProtocolo = "DDP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Datagram Delivery Protocol");
        break;
    }
    case 38: {
        nombreProtocolo = "IDPR-CMTP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("IDPR Control Message Transport Protocol");
        break;
    }
    case 39: {
        nombreProtocolo = "TP++";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("TP++ Transport Protocol");
        break;
    }
    case 40: {
        nombreProtocolo = "IL";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("IL Transport Protocol");
        break;
    }
    case 41: {
        nombreProtocolo = "IPv6";
        structInfo.append("Internet Protocol version 6 Encapsulation");
        break;
    }
    case 42: {
        nombreProtocolo = "SDRP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Source Demand Routing Protocol");
        break;
    }
    case 43: {
        nombreProtocolo = "IPv6-Route";
        structInfo.append("Routing Header for IPv6");
        break;
    }
    case 44: {
        nombreProtocolo = "IPv6-Frag";
        structInfo.append("Fragment Header for IPv6");
        break;
    }
    case 45: {
        nombreProtocolo = "IDRP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Inter-Domain Routing Protocol");
        break;
    }
    case 46: {
        nombreProtocolo = "RSVP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Reservation Protocol");
        break;
    }
    case 47: {
        nombreProtocolo = "GRE";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Generic Routing Encapsulation");
        break;
    }
    case 48: {
        nombreProtocolo = "DSR";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Dynamic SOurce Routing Protocol");
        break;
    }
    case 49: {
        nombreProtocolo = "BNA";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("BNA");
        break;
    }
    case 50: {
        nombreProtocolo = "ESP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Encap Security Payload");
        break;
    }
    case 51: {
        nombreProtocolo = "AH";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Authentication Header");
        break;
    }
    case 52: {
        nombreProtocolo = "I-NLSP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Integrated Net Layer Security TUBA");
        break;
    }
    case 53: {
        nombreProtocolo = "SWIPE";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("IP with Encryption");
        break;
    }
    case 54: {
        nombreProtocolo = "NARP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("NBMA Address Resolution Protocol");
        break;
    }
    case 55: {
        nombreProtocolo = "Min-IPv4";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Minimal IPv4 Encapsulation");
        break;
    }
    case 56: {
        nombreProtocolo = "TLSP";
        cabecera_tls* tls = (cabecera_tls*)(pkt_data + offset);
        cabecera_tcp* tcp = (cabecera_tcp*)((u_char*)ih + ((ih->ver_ihl & 0x0F) * 4));
        info.append(QString("Type: %1").arg(tls->content_type));
        info.append(QString("Version: %1.%2").arg((ntohs(tls->version) >> 8) & 0xFF).arg(ntohs(tls->version) & 0xFF));
        info.append(QString("Length: %1 ").arg(ntohs(tls->length)));
        info.append(QString("Tos=%1, Flags=%2").arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append(QString("Transmission Control Protocol, src Port: %1, dst Port: %2, Seq: %3, Ack: %4, Len: %5").arg(ntohs(tcp->sport))
                              .arg(ntohs(tcp->dport)).arg(tcp->sq).arg(tcp->ack).arg(ih->tlen - ih->ver_ihl - ((tcp->data_offset >> 4) * 4)));
        structInfo.append("Transport Layer Security");
        break;
    }
    case 57: {
        nombreProtocolo = "SKIP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("SKIP");
        break;
    }
    case 58: {
        nombreProtocolo = "IPv6-ICMP";
        structInfo.append("ICMP for IPv6");
        break;
    }
    case 59: {
        nombreProtocolo = "IPv6-NoNxt";
        structInfo.append("No Next Header for IPv6");
        break;
    }
    case 60: {
        nombreProtocolo = "IPv6-Opts";
        structInfo.append("Destination Options for IPV6");
        break;
    }
    case 62: {
        nombreProtocolo = "CFTP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("CFTP");
        break;
    }
    case 64: {
        nombreProtocolo = "SAT-EXPAK";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("SATNET and Backroom EXPAK");
        break;
    }
    case 65: {
        nombreProtocolo = "KRYPTOLAN";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Kryptolan");
        break;
    }
    case 66: {
        nombreProtocolo = "RVD";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("MIT Remote Virtual Disk Protocol");
        break;
    }
    case 67: {
        nombreProtocolo = "IPPC";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Internet Pluribus Packet Core");
        break;
    }
    case 69: {
        nombreProtocolo = "SAT-MON";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("SATNET Monitoring");
        break;
    }
    case 70: {
        nombreProtocolo = "VISA";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("VISA Protocol");
        break;
    }
    case 71: {
        nombreProtocolo = "IPCV";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Internet Packet Core Utility");
        break;
    }
    case 72: {
        nombreProtocolo = "CPNX";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Computer Protocol Network Executive");
        break;
    }
    case 73: {
        nombreProtocolo = "CPHB";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Computer Protocol Heart Beat");
        break;
    }
    case 74: {
        nombreProtocolo = "WSN";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Wang Span Network");
        break;
    }
    case 75: {
        nombreProtocolo = "PVP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Packet Video Protocol");
        break;
    }
    case 76: {
        nombreProtocolo = "BR-SAT-MON";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Backroom SATNET Monitoring");
        break;
    }
    case 77: {
        nombreProtocolo = "SUN-ND";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("SUN ND PROTOCOL-Temporary");
        break;
    }
    case 78: {
        nombreProtocolo = "WB-MON";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("WIDEBAND Monitoring");
        break;
    }
    case 79: {
        nombreProtocolo = "WB-EXPAK";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("WIDEBAND EXPAK");
        break;
    }
    case 80: {
        nombreProtocolo = "ISO-IP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("ISO Internet Protocol");
        break;
    }
    case 81: {
        nombreProtocolo = "VMTP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("VMTP");
        break;
    }
    case 82: {
        nombreProtocolo = "SECURE-VMTP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("SECURE-VMPT");
        break;
    }
    case 83: {
        nombreProtocolo = "VINES";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("VINES");
        break;
    }
    case 84: {
        nombreProtocolo = "IPTM";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Internet Protocol Traffic Manager");
        break;
    }
    case 85: {
        nombreProtocolo = "NSFNET-IGP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("NSFNET-IGP");
        break;
    }
    case 86: {
        nombreProtocolo = "DGP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Dissimilar Gateway Protocol");
        break;
    }
    case 87: {
        nombreProtocolo = "TCF";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("TCF");
        break;
    }
    case 88: {
        nombreProtocolo = "EIGRP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("EIGRP");
        break;
    }
    case 89: {
        nombreProtocolo = "OSPFIGP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("OSPFIGP");
        break;
    }
    case 90: {
        nombreProtocolo = "Sprite-RPC";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Sprite RPC Protocol");
        break;
    }
    case 91: {
        nombreProtocolo = "LARP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Locus Address Resolution Protocol");
        break;
    }
    case 92: {
        nombreProtocolo = "MTP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Multicast Transport Protocol");
        break;
    }
    case 93: {
        nombreProtocolo = "AX.25";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("AX.25 Frames");
        break;
    }
    case 94: {
        nombreProtocolo = "IPIP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("IP-within-IP Encapsulation Protocol");
        break;
    }
    case 95: {
        nombreProtocolo = "MICP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Mobile Internetworking Control Pro");
        break;
    }
    case 96: {
        nombreProtocolo = "SCC-SP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Sempahore Communication Sec. Pro.");
        break;
    }
    case 97: {
        nombreProtocolo = "ETHERIP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Ethernet-within-IP Encapsultation");
        break;
    }
    case 98: {
        nombreProtocolo = "ENCAP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Encapsulation Header");
        break;
    }
    case 100: {
        nombreProtocolo = "GMTP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("GMTP");
        break;
    }
    case 101: {
        nombreProtocolo = "IFMP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Ipsilon Flow Management Protocol");
        break;
    }
    case 102: {
        nombreProtocolo = "PNNI";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("PNNI over IP");
        break;
    }
    case 103: {
        nombreProtocolo = "PIM";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Protocol Independent Multicast");
        break;
    }
    case 104: {
        nombreProtocolo = "ARIS";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("ARIS");
        break;
    }
    case 105: {
        nombreProtocolo = "SCPS";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("SCPS");
        break;
    }
    case 106: {
        nombreProtocolo = "QNX";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("QNX");
        break;
    }
    case 107: {
        nombreProtocolo = "A/N";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Active Networks");
        break;
    }
    case 108: {
        nombreProtocolo = "IPComp";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("IP Payload Compression Protocol");
        break;
    }
    case 109: {
        nombreProtocolo = "SNP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Sitara Networks Protocol");
        break;
    }
    case 110: {
        nombreProtocolo = "Compaq-Peer";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Compaq Peer Protocol");
        break;
    }
    case 111: {
        nombreProtocolo = "IPX-in-IP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("IPX in IP");
        break;
    }
    case 112: {
        nombreProtocolo = "VRRP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Virtual Router Redundancy Protocol");
        break;
    }
    case 113: {
        nombreProtocolo = "PGM";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("PGM Reliable Transport Protocol");
        break;
    }
    case 115: {
        nombreProtocolo = "L2TP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Layer Two Tunneling Protocol");
        break;
    }
    case 116: {
        nombreProtocolo = "DDX";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("D-II Data Exchange (DDX)");
        break;
    }
    case 117: {
        nombreProtocolo = "IATP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Interactive Agent Transfer Protocol");
        break;
    }
    case 118: {
        nombreProtocolo = "STP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Schedule Transfer Protocol");
        break;
    }
    case 119: {
        nombreProtocolo = "SRP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("SpectraLink Radio Protocol");
        break;
    }
    case 120: {
        nombreProtocolo = "UTI";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("UTI");
        break;
    }
    case 121: {
        nombreProtocolo = "SMP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Simple Message Protocol");
        break;
    }
    case 122: {
        nombreProtocolo = "SM";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Simple Multicast Protocol");
        break;
    }
    case 123: {
        nombreProtocolo = "PTP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Performance Transparency Protocol");
        break;
    }
    case 124: {
        nombreProtocolo = "ISIS over IPv4";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("ISIS");
        break;
    }
    case 125: {
        nombreProtocolo = "FIRE";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("FIRE");
        break;
    }
    case 126: {
        nombreProtocolo = "CRTP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Combat Radio Transport Protocol");
        break;
    }
    case 127: {
        nombreProtocolo = "CRUDP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Combat Radio User Datagram");
        break;
    }
    case 128: {
        nombreProtocolo = "SSCOPMCE";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("SSCOPMCE");
        break;
    }
    case 129: {
        nombreProtocolo = "IPLT";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("IPLT");
        break;
    }
    case 130: {
        nombreProtocolo = "SPS";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Secure Packet Shield");
        break;
    }
    case 131: {
        nombreProtocolo = "PIPE";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Private IP Encapsulation within IP");
        break;
    }
    case 132: {
        nombreProtocolo = "SCTP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Stream Control Transmission Protocol");
        break;
    }
    case 133: {
        nombreProtocolo = "FC";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Fibre Channel");
        break;
    }
    case 134: {
        nombreProtocolo = "RSVP-E2E-IGNORE";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("RSVP E2E IGNORE");
        break;
    }
    case 135: {
        nombreProtocolo = "Mobility Header";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Mobility Header");
        break;
    }
    case 136: {
        nombreProtocolo = "UDPLite";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("UDPLite");
        break;
    }
    case 137: {
        nombreProtocolo = "MPLS-in-IP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("MPLS in IP");
        break;
    }
    case 138: {
        nombreProtocolo = "manet";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("MANET Protocols");
        break;
    }
    case 139: {
        nombreProtocolo = "HIP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Host Identity Protocol");
        break;
    }
    case 140: {
        nombreProtocolo = "Shim6";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Shim6 Protocol");
        break;
    }
    case 141: {
        nombreProtocolo = "WESP";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Wrapped Encapsulating Security Payload");
        break;
    }
    case 142: {
        nombreProtocolo = "ROHC";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Robust Header COmpression");
        break;
    }
    case 143: {
        nombreProtocolo = "Ethernet";
        cabecera_ethernet* eth = (cabecera_ethernet*)pkt_data;
        info.append(QString("Type=%1, Len=%2, Tos=%3, Flags=%4").arg(eth->type).arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Ethernet");
        break;
    }
    case 144: {
        nombreProtocolo = "AGGFRAG";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("AGGFRAG");
        break;
    }
    case 145: {
        nombreProtocolo = "NSH";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Network Service Header");
        break;
    }
    case 146: {
        nombreProtocolo = "Homa";
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        structInfo.append("Homa");
        break;
    }
    default:
        nombreProtocolo = "Otro";
        info.append(QString("No. Protocol=%1 ").arg(protocolo));
        info.append(QString("Len=%1, Tos=%2, Flags=%3").arg(length).arg(tos).arg(((ntohs(ih->flags_fo)) >> 13) & 0x7));
        break;
    }

    emit captureThread->packetCaptured(QString(timestr), srcAddr, destAddr, length, nombreProtocolo, info, rawInfo, structInfo);
}

void packet_sniffer::cargarInterfaz() {
    this->dev = devInterface = this->item->text();
    this->ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    this->ui->dispositivo->setText("Escuchando tráfico desde " + devInterface);
    this->ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    this->ui->tableWidget->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    this->ui->tableWidget->verticalHeader()->setVisible(false);
}

void packet_sniffer::addPacket(QString time, QString srcAddr, QString destAddr, int lenght, QString protocol, QString info, QString rawInfo, QString structInfo) {
    int row = this->ui->tableWidget->rowCount();
    this->ui->tableWidget->insertRow(row);
    this->ui->tableWidget->setItem(row, 0, new QTableWidgetItem(QString::number(no)));
    this->ui->tableWidget->setItem(row, 1, new QTableWidgetItem(time));
    this->ui->tableWidget->setItem(row, 2, new QTableWidgetItem(srcAddr));
    this->ui->tableWidget->setItem(row, 3, new QTableWidgetItem(destAddr));
    this->ui->tableWidget->setItem(row, 4, new QTableWidgetItem(protocol));
    this->ui->tableWidget->setItem(row, 5, new QTableWidgetItem(QString::number(lenght)));
    this->ui->tableWidget->setItem(row, 6, new QTableWidgetItem(info));
    no++;

    this->ui->tableWidget->item(row, 0)->setData(Qt::UserRole + 1, structInfo);
    this->ui->tableWidget->item(row, 0)->setData(Qt::UserRole + 2, rawInfo);

    QScrollBar* vScrollBar = this->ui->tableWidget->verticalScrollBar();
    if (no == 2) {
        QLabel* l = new QLabel(this);
        l->setText(structInfo);
        l->setWordWrap(true);
        l->setAlignment(Qt::AlignLeft | Qt::AlignTop);

        QWidget* oldWidgetLeft = this->ui->scrollArea_2->takeWidget();
        if (oldWidgetLeft) {
            delete oldWidgetLeft;
        }

        this->ui->scrollArea_2->setWidget(l);
        this->ui->scrollArea_2->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

        //Contenido RAW, scrollArea derecha
        QLabel* r = new QLabel(this);
        QFont font("Courier");
        font.setStyleHint(QFont::Monospace); // Asegura una fuente monoespaciada
        r->setFont(font); // Aplica la fuente directamente

        //r->setStyleSheet("font-family: 'Courier'; text-align: justify;");
        r->setText(rawInfo);
        r->setWordWrap(true);
        r->setAlignment(Qt::AlignLeft | Qt::AlignTop);

        QWidget* oldWidgetRight = this->ui->scrollArea->takeWidget();
        if (oldWidgetRight) {
            delete oldWidgetRight;
        }

        this->ui->scrollArea->setWidget(r);
    }

    if (vScrollBar->value() == vScrollBar->maximum()) {
        this->ui->tableWidget->scrollToBottom();
    }

}

void packet_sniffer::comenzarIntercepcion() {
    char errbuf[PCAP_ERRBUF_SIZE];

    if ((adhandle = pcap_open(this->d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
        QMessageBox::information(this, "Error", "No fue posible abrir el dispositivo");
        this->close();
    }
    if (pcap_datalink(adhandle) != DLT_EN10MB) {
        QMessageBox::information(this, "Error", "Este programa solo escucha cuando es Ethernet");
        this->close();
    }

    if (this->d->addresses != NULL) {
        this->netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else {
        this->netmask = 0xffffff;
    }

    //Comenzando a capturar/
    this->captureThread = new PacketCaptureThread(adhandle, this);
    connect(captureThread, &PacketCaptureThread::packetCaptured, this, &packet_sniffer::addPacket);
    this->started = true;
    this->captureThread->start();
}

void packet_sniffer::closeEvent(QCloseEvent *event) {
    if (this->captureThread) {
        this->captureThread->stop();
        this->captureThread->wait();
        delete this->captureThread;
        this->captureThread = nullptr;
    }
    event->accept();
}

void packet_sniffer::on_pushButton_2_clicked() {
    if (this->captureThread) {
        this->captureThread->pause();
    }
}

void packet_sniffer::on_pushButton_3_clicked() {
    if (this->captureThread) {
        this->captureThread->resume();
    }
}

void packet_sniffer::on_pushButton_4_clicked(){
    font = this->ui->tableWidget->font();
    int tamFuente = font.pointSize();
    font.setPointSize(tamFuente + 1);
    this->ui->tableWidget->setFont(font);
    this->ui->scrollArea->setFont(font);
    this->ui->scrollArea_2->setFont(font);
}

void packet_sniffer::on_pushButton_5_clicked(){
    font = ui->tableWidget->font();
    int tamFuente = font.pointSize();
    font.setPointSize(tamFuente - 1);
    this->ui->tableWidget->setFont(font);
    this->ui->scrollArea->setFont(font);
    this->ui->scrollArea_2->setFont(font);
}

void packet_sniffer::on_pushButton_6_clicked(){
    FILE *archCSV;
    QTableWidgetItem *celda;

    QString filePath = QFileDialog::getSaveFileName(this, tr("Guardar captura en CSV"), "", tr("Archivos CSV (*.csv);;Todos los archivos (*)"));

    if (filePath.isEmpty()) {
        QMessageBox::information(this, "Aviso", "Guardado de captura cancelado");
        return;
    }

    errno_t err = fopen_s(&archCSV, filePath.toStdString().c_str(), "w");
    if(err != 0){
        QMessageBox::information(this, "Error", "Error al abrir el archivo");
        return;
    }
    fprintf(archCSV, "No.,Tiempo,Origen,Destino,Protocolo,Tamanio,Info\n");
    for(int row=0; row < this->ui->tableWidget->rowCount(); row++){
        for(int column=0; column < this->ui->tableWidget->columnCount(); column++){
            celda = this->ui->tableWidget->item(row, column);
            QString dato = celda->text();
            fprintf(archCSV, "%s", dato.toStdString().c_str());
            if(column == this->ui->tableWidget->columnCount())
                fprintf(archCSV, "\n");
            else
                fprintf(archCSV, ",");
        }
        fprintf(archCSV, "\n");
    }
    if(archCSV == NULL)
        QMessageBox::information(this, "Error", "Error al crear el archivo");
    else{
        QMessageBox::information(this, "Info", "Archivo creado correctamente");
    }
    fclose(archCSV);
}

void packet_sniffer::on_tableWidget_cellClicked(int row, int column) {
    (VOID)column;
    QTableWidgetItem* item = this->ui->tableWidget->item(row, 0);
    if (item) {
        QLabel* l = new QLabel(this);
        //Contenido Estrucutrado, scrollArea izquierda
        l->setText(item->data(Qt::UserRole + 1).toString());
        l->setWordWrap(true);
        l->setAlignment(Qt::AlignLeft|Qt::AlignTop);

        QWidget* oldWidgetLeft = this->ui->scrollArea_2->takeWidget();
        if (oldWidgetLeft) {
            delete oldWidgetLeft;
        }

        this->ui->scrollArea_2->setWidget(l);
        this->ui->scrollArea_2->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

        //Contenido RAW, scrollArea derecha
        QLabel* r = new QLabel(this);
        QFont font("Courier");
        font.setStyleHint(QFont::Monospace); // Asegura una fuente monoespaciada
        r->setFont(font); // Aplica la fuente directamente
        //r->setStyleSheet("font-family: 'Courier'; text-align: justify;");
        r->setText(item->data(Qt::UserRole + 2).toString());
        r->setWordWrap(true);
        r->setAlignment(Qt::AlignLeft|Qt::AlignTop);

        QWidget* oldWidgetRight = this->ui->scrollArea->takeWidget();
        if (oldWidgetRight) {
            delete oldWidgetRight;
        }

        this->ui->scrollArea->setWidget(r);
    }
}

void packet_sniffer::putFilter() {
    this->ui->plainTextEdit->setPlainText(this->filter);

    if (this->ui->plainTextEdit->toPlainText() != "Introduzca un filtro de captura") {
        QString text = ui->plainTextEdit->toPlainText();
        text = text.toLower();
        QByteArray byteArray = text.toUtf8();
        packet_filter = byteArray;
        if (pcap_compile(this->adhandle, &this->fcode, this->packet_filter, 1, this->netmask) < 0) {
            QMessageBox::information(this, "Error", "No fue posible compilar el filtro");
            this->close();
        }

        // Aplicar el filtro /
        if (pcap_setfilter(this->adhandle, &this->fcode) < 0) {
            QMessageBox::information(this, "Error", "Error al aplicar el filtro");
            this->close();
        }
    }
}

void packet_sniffer::on_pushButton_7_clicked(){
    QString text = ui->plainTextEdit->toPlainText();
    text = text.toLower();
    if (text == "introduzca un filtro de captura") {
        text = "";
    }
    QByteArray byteArray = text.toUtf8();
    packet_filter = byteArray;
    if (pcap_compile(this->adhandle, &this->fcode, this->packet_filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        QMessageBox::information(this, "Error", "No fue posible compilar el filtro");
    }

    // Aplicar el filtro /
    if (pcap_setfilter(this->adhandle, &this->fcode) < 0) {
        QMessageBox::information(this, "Error", "Error al aplicar el filtro");
    }
}

void packet_sniffer::showNotification(const QString &mensaje) {
    this->trayIcon->showMessage("Alerta de red", mensaje, QSystemTrayIcon::Information, 5000);
}

void packet_sniffer::on_pushButton_8_clicked(){
    Notification notificacion;
    notificacion.setModal(true);
    notificacion.exec();
    selection = notificacion.getConectionType();
}

