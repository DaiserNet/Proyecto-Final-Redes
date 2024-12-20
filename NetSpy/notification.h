#ifndef NOTIFICATION_H
#define NOTIFICATION_H

#include <QDialog>

namespace Ui {
class Notification;
}

class Notification : public QDialog {
    Q_OBJECT

public:
    explicit Notification(QWidget *parent = nullptr);
    ~Notification();
    int getConectionType();

private slots:
    int on_buttonBox_accepted();

    void on_buttonBox_rejected();

private:
    Ui::Notification *ui;
};

#endif // NOTIFICATION_H
