#pragma once
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMessageBox.h>
#include <QtWidgets/QInputDialog.h>
#include <Windows.h>
#include <filesystem>
#include <fstream>

#include "ui_QVMProfiler.h"
#include "vmp2.hpp"
#include "vm.h"
#include "vmctx.h"
#include "ia32.hpp"

class QVMProfiler : public QMainWindow
{
    Q_OBJECT

public:
    QVMProfiler(QWidget *parent = Q_NULLPTR);

private slots:
    void on_actionOpen_VMTrace_triggered();
    void on_actionCloseProgram_triggered();
    void on_VirtualInstructionTree_itemSelectionChanged();

private:
    void DbgPrint(QString DbgOutput);
    void DbgMessage(QString DbgOutput);
    void UpdateUI();
    bool InitTraceData();

    Ui::QVMProfilerClass ui;
    QString TraceFilePath;
    QString VMProtectedFilePath;
    std::uint64_t ImageBase, VMEntryRva, ModuleBase;

    std::vector<vm::handler_t> VMHandlers;
    zydis_routine_t VMEntry;

    std::uintptr_t* VMHandlerTable;
    vm::vmctx_t* VMCtx;

    void* TraceFileBlob;
    vmp2::file_header* TraceFileHeader;
    vmp2::entry_t* TraceEntryList;
};
