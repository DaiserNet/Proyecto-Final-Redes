#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "packet_sniffer.h"
#include <QMessageBox>
#include <QString>
using namespace std;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    populateInterfaces();

    connect(ui->listWidget, &QListWidget::itemClicked, this, &MainWindow::onItemClicked);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::populateInterfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Obtener la lista de dispositivos de red
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &this->alldevs, errbuf) == -1) {
        QMessageBox::critical(this, "Error", QString("Error en pcap_findalldevs_ex: %1").arg(errbuf));
        return;
    }

    int i = 0;
    for (this->d = alldevs; this->d != nullptr; this->d = this->d->next) {
        QString description;

        if (d->description) {
            description = QString("%1: %2").arg(++i).arg(d->description);
        } else {
            description = QString("%1: (sin descripción)").arg(++i);
        }

        // Agregar el texto al QListWidget definido en mainWindow.ui
        ui->listWidget->addItem(description);
    }

    if (i == 0) {
        QMessageBox::information(this, "Información", "No se encontraron interfaces.");
    }
}

void MainWindow::onItemClicked(QListWidgetItem *item) {
    QString iTxt = item->text();
    const char *texto = iTxt.toStdString().c_str();
    int num = texto[0] - '0';
    int i = 0;
    for (this->d = this->alldevs, i = 0; i < num - 1; this->d = this->d->next, i++);

    // Liberar la lista de dispositivos
    pcap_freealldevs(this->alldevs);

    QString filtro = this->ui->plainTextEdit->toPlainText();

    packet_sniffer ps(this, item, this->d, filtro);
    ps.setModal(true);
    ps.exec();
    this->~MainWindow();
}
