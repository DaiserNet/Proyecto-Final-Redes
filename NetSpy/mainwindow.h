#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidget>
#include <pcap.h>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onItemClicked(QListWidgetItem *item);

private:
    Ui::MainWindow *ui;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    void populateInterfaces();
};

#endif // MAINWINDOW_H
