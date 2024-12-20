#include "notification.h"
#include "ui_notification.h"
#include <QComboBox>
#include <QMessageBox>

Notification::Notification(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::Notification) {
    ui->setupUi(this);
    ui->comboBox->addItem("1194 - UDP (OpenVPN)");
    ui->comboBox->addItem("1701 - TCP (L2TP)");
    ui->comboBox->addItem("1723 - TCP (PPTP)");
    ui->comboBox->addItem("   22 - SSH");
    ui->comboBox->addItem("   23 - TELNET");
    ui->comboBox->addItem("3389 - RDP");

    //ui->comboBox->setCurrentIndex(0);
}

int Notification::getConectionType() {
    return this->ui->comboBox->currentIndex();
}

Notification::~Notification() {
    delete ui;
}
int Notification::on_buttonBox_accepted()
{
    int selectedIndex = this->ui->comboBox->currentIndex();
    QString selectedItem = QString::number(selectedIndex);
    if(selectedIndex == -1){
        QMessageBox::information(this, "Opción No Seleccionada", "No se seleccionó ninguna opción");
    }else{
        QMessageBox::information(this, "Opción Seleccionada", "La ocpión fue seleccionada exitosamente");
    }
    accept();
    return selectedIndex;
}


void Notification::on_buttonBox_rejected()
{
    reject();
}

