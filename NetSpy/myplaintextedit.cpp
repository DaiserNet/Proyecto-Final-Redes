#include "myplaintextedit.h"

MyPlainTextEdit::MyPlainTextEdit(QWidget *parent) : QPlainTextEdit(parent), defaultText("Introduzca un filtro de captura") {
    setPlainText(defaultText);
}

void MyPlainTextEdit::focusInEvent(QFocusEvent *e) {
    if (toPlainText() == defaultText) {
        setPlainText("");
    }
    QPlainTextEdit::focusInEvent(e);
}

void MyPlainTextEdit::focusOutEvent(QFocusEvent *e) {
    if (toPlainText().isEmpty()) {
        setPlainText(defaultText);
    }
    QPlainTextEdit::focusOutEvent(e);
}
