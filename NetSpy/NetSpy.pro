QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

INCLUDEPATH += "$$PWD\Include"
LIBS += "-L$$PWD\Lib\x64" -lwpcap -lPacket
LIBS += -lws2_32

DEFINES += WPCAP
DEFINES += HAVE_REMOTE

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    myplaintextedit.cpp \
    notification.cpp \
    packet_sniffer.cpp

HEADERS += \
    mainwindow.h \
    myplaintextedit.h \
    notification.h \
    packet_sniffer.h

FORMS += \
    mainwindow.ui \
    notification.ui \
    packet_sniffer.ui

RC_ICONS = img/image.ico

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
