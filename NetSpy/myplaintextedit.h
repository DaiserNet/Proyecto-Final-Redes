#ifndef MYPLAINTEXTEDIT_H
#define MYPLAINTEXTEDIT_H

#include <QPlainTextEdit>
#include <QFocusEvent>
#include <QString>

class MyPlainTextEdit : public QPlainTextEdit {
    Q_OBJECT

public:
    MyPlainTextEdit(QWidget* parent = nullptr);

protected:
    void focusInEvent(QFocusEvent *e) override;
    void focusOutEvent(QFocusEvent *e) override;

private:
    QString defaultText;
};

#endif // MYPLAINTEXTEDIT_H
