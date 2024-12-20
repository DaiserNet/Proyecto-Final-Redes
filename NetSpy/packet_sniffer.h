#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <QDialog>
#include <QObject>
#include <QThread>
#include <QListWidgetItem>
#include <pcap.h>
#include <tchar.h>
#include <time.h>
#include <winsock2.h>
#include <QMutex>
#include <QWaitCondition>
#include <QFont>
#include <QSystemTrayIcon>

/* Los 4 octetos de las direcciones de IP */
typedef struct direccion_ip {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}direccion_ip;

//Cabecera Ethernet
typedef struct cabecera_ethernet {
    u_char dest[6];
    u_char src[6];
    u_short type;
}cabecera_ethernet;

/* La cabecera de las direcciones de IP */
typedef struct cabecera_ip {
    u_char ver_ihl; // Version(4bits) + Cabecera(4 bits) /
    u_char tos; // Tipo de servicio /
    u_short tlen; // Tamanio total /
    u_short identification; // Identificador /
    u_short flags_fo; // Banderas(3 bits) + Fragmentos(13 bits) /
    u_char ttl; // Tiempo de vida /
    u_char proto; // Protocolo /
    u_short crc; // Checksum de la cabecera /
    direccion_ip saddr; // Direccion fuente /
    direccion_ip daddr; // Direccion de destion /
    u_int op_pad; // Option + Padding /
}cabecera_ip;

/* Cabecera UDP*/
typedef struct cabecera_udp {
    u_short sport; // Puerto fuente /
    u_short dport; // Puerto de destino /
    u_short len; // Tamanio del datagrama /
    u_short crc; // Checksum /
}cabecera_udp;

//Cabecera TCP
typedef struct cabecera_tcp {
    u_short sport;
    u_short dport;
    u_int sq;
    u_int ack;
    u_char data_offset;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short ur_ptr;
}cabecera_tcp;

//Cabecera IGMP
typedef struct cabecera_igmp {
    u_char type;
    u_char max_response_time;
    u_short checksum;
    direccion_ip group_addr;
}cabecera_igmp;

//Cabecera TLS
typedef struct cabecera_tls {
    uint8_t content_type;     // Tipo de contenido (0x14 Handshake, 0x15 Alert, 0x16 Application Data, etc.)
    uint16_t version;         // Versión del protocolo (0x0303 para TLS 1.2)
    uint16_t length;          // Longitud del contenido
    uint8_t payload[];        // Datos (puede ser handshake, datos de aplicación, etc.)
} cabecera_tls;

///////////////////////////////////////////////////////////

namespace Ui {
class packet_sniffer;
}

class PacketCaptureThread : public QThread {
    Q_OBJECT

public:
    explicit PacketCaptureThread(pcap_t* adhandle, QObject* parent = nullptr);
    void pause();
    void resume();
    void stop();
    bool isRunning();

signals:
    void packetCaptured(QString time, QString srcAddr, QString destAddr, int length, QString protocol, QString info, QString rawInfo, QString structInfo);
    void connectionDetected(const QString &mensaje);

protected:
    void run() override;

private:
    static void packetHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
    pcap_t* adhandle;
    bool paused;
    bool stopped;
    QMutex mutex;
    QWaitCondition condition;
    void processPackets();
};

/////////////////////////////////////////////////////////////

class packet_sniffer : public QDialog {
    Q_OBJECT

public:
    explicit packet_sniffer(QWidget *parent = nullptr, QListWidgetItem *item = nullptr, pcap_if_t *d = nullptr, QString filter = "Introduzca un filtro de captura");
    ~packet_sniffer();
    void addPacket(QString time, QString srcAddr, QString destAddr, int lenght, QString protocol, QString info, QString rawInfo, QString structInfo);

private slots:
    void on_pushButton_2_clicked();

    void on_pushButton_3_clicked();

    void on_pushButton_6_clicked();

    void on_tableWidget_cellClicked(int row, int column);

    void on_pushButton_4_clicked();

    void on_pushButton_5_clicked();

    void on_pushButton_7_clicked();

    void showNotification(const QString &mensaje);

    void on_pushButton_8_clicked();

private:
    Ui::packet_sniffer *ui;
    QListWidgetItem *item;
    pcap_if_t *d;
    pcap_t* adhandle;
    u_int netmask;
    const char* packet_filter;
    struct bpf_program fcode;
    PacketCaptureThread* captureThread;
    void cargarInterfaz();
    void comenzarIntercepcion();
    void closeEvent(QCloseEvent *event) override;
    void putFilter();
    bool started;
    QString dev;
    QFont font;
    QString filter;
    QSystemTrayIcon *trayIcon;
};

#endif // PACKET_SNIFFER_H
