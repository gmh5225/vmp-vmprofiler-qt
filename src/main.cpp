#include <QtWidgets/QApplication>
#include <QFile>
#include <QTextStream>
#include "QVMProfiler.h"

#include "framelesswindow.h"
#include "DarkStyle.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setStyle(new DarkStyle);
    FramelessWindow framelessWindow;
    framelessWindow.setContent(new QVMProfiler);
    framelessWindow.setWindowIcon(QIcon("icon.ico"));
    framelessWindow.show();
    return app.exec();
}