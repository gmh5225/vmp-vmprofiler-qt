#include "QVMProfiler.h"

QVMProfiler::QVMProfiler(QWidget *parent)
    : QMainWindow(parent),
    TraceFileBlob(nullptr),
    VMCtx(nullptr)
{
    ui.setupUi(this);
}

void QVMProfiler::on_actionCloseProgram_triggered()
{ exit(0); }

void QVMProfiler::on_actionOpen_VMTrace_triggered()
{
    if (TraceFileBlob && VMCtx)
    {
        free(TraceFileBlob);
        TraceFileBlob = nullptr;
        TraceFileHeader = nullptr;
        TraceEntryList = nullptr;
        VMHandlerTable = nullptr;

        ImageBase = NULL;
        VMEntryRva = NULL;
        ModuleBase = NULL;

        VMHandlers.clear();
        VMEntry.clear();
        delete VMCtx;
    }

    TraceFilePath = QFileDialog::getOpenFileName(this,
        tr("Open Trace"), "C:\\", tr("VMTrace Files (*.vmp2)"));

    if (TraceFilePath.isEmpty())
    {
        DbgMessage("Invalid Trace File... No File Selected...");
        return;
    }

    if (!std::filesystem::exists(TraceFilePath.toStdString().c_str()))
    {
        DbgMessage("Trace File Doesnt Exist...");
        return;
    }

    VMProtectedFilePath = QFileDialog::getOpenFileName(this,
        tr("Open VMProtected File"), "C:\\");

    if (VMProtectedFilePath.isEmpty())
    {
        DbgMessage("Invalid VMProtected File... No File Selected...");
        return;
    }

    if (!std::filesystem::exists(VMProtectedFilePath.toStdString().c_str()))
    {
        DbgMessage("VMProtected File Doesnt Exist...");
        return;
    }

    bool Success = false;
    auto VMEntryRvaStr = QInputDialog::getText(0, "Input",
        "VMEntry Relative Virtual Address:", QLineEdit::Normal, "", &Success);

    if (!Success || VMEntryRvaStr.isEmpty())
    {
        DbgMessage("Invalid VMEntry Relative Virtual Address...");
        return;
    }

    auto ImageBaseStr = QInputDialog::getText(0, "Input",
        "Image Base:", QLineEdit::Normal, "", &Success);

    if (!Success || ImageBaseStr.isEmpty())
    {
        DbgMessage("Invalid Image Base...");
        return;
    }

    VMEntryRva = VMEntryRvaStr.toULongLong(nullptr, 16);
    ImageBase = ImageBaseStr.toULongLong(nullptr, 16);

    ModuleBase = reinterpret_cast<std::uintptr_t>(
        LoadLibraryExA(VMProtectedFilePath.toStdString().c_str(),
            NULL, DONT_RESOLVE_DLL_REFERENCES));

    const auto TraceFileSize =
        std::filesystem::file_size(
            TraceFilePath.toStdString().c_str());

    if (!TraceFileSize)
    {
        DbgMessage("Invalid Trace File Size...");
        return;
    }

    DbgMessage(QString("Loading Trace File %1...").arg(TraceFilePath));

    // could use a QFile for all of this...
    const auto FileSize = 
        std::filesystem::file_size(
            TraceFilePath.toStdString().c_str());

    // could use a QFile for all of this...
    TraceFileBlob = malloc(FileSize);
    std::ifstream TFile(TraceFilePath.toStdString().c_str(), std::ios::binary);
    TFile.read((char*)TraceFileBlob, FileSize);
    TFile.close();

    if (!InitTraceData())
    {
        DbgMessage("Failed To Init Trace Data...");
        return;
    }

    UpdateUI();
}

void QVMProfiler::DbgPrint(QString DbgOutput)
{
    ui.DbgOutputWindow->appendPlainText(DbgOutput);
}

void QVMProfiler::DbgMessage(QString DbgOutput)
{
    QMessageBox MsgBox;
    MsgBox.setText(DbgOutput);
    MsgBox.exec();
    DbgPrint(DbgOutput);
}

bool QVMProfiler::InitTraceData()
{
    TraceFileHeader =
        reinterpret_cast<vmp2::file_header*>(TraceFileBlob);

    TraceEntryList =
        reinterpret_cast<vmp2::entry_t*>(
            reinterpret_cast<std::uintptr_t>(
                TraceFileBlob) + TraceFileHeader->entry_offset);

    const auto TraceMagicBytes = &TraceFileHeader->magic;
    if (memcmp(TraceMagicBytes, "VMP2", sizeof "VMP2" - 1) != 0)
    {
        DbgMessage("Trace File Magic Bytes Are Invalid...\n");
        return false;
    }

    DbgPrint("Trace File Magic Bytes Are Valid....");
    if (!vm::util::flatten(VMEntry, VMEntryRva + ModuleBase))
    {
        DbgMessage("Failed To Flatten VMEntry...\n");
        return false;
    }

    vm::util::deobfuscate(VMEntry);
    DbgPrint("Flattened VMEntry...");
    DbgPrint("Deobfuscated VMEntry...");

    char buffer[256];
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    for (auto& Instr : VMEntry)
    {
        ZydisFormatterFormatInstruction(&formatter, &Instr.instr, buffer, sizeof(buffer), 
            (Instr.addr - TraceFileHeader->module_base) + ImageBase);

        DbgPrint(QString("> %1 %2").arg(
            QString::number((Instr.addr - TraceFileHeader->module_base) + ImageBase, 16)).arg(buffer));
    }

    VMHandlerTable = vm::handler::table::get(VMEntry);
    if (!vm::handler::get_all(ModuleBase, ImageBase, VMEntry, VMHandlerTable, VMHandlers))
    {
        DbgMessage("Failed To Get All VM Handler Meta Data...\n");
        return false;
    }

    DbgPrint("Located All VM Handlers...");
    VMCtx = new vm::vmctx_t(TraceFileHeader, 
        TraceEntryList, VMHandlers, ModuleBase, ImageBase);

    return true;
}

void QVMProfiler::UpdateUI()
{
    ui.VirtualInstructionTree->clear();
    for (auto [VirtInstr, TraceEntry] = VMCtx->step(); TraceEntry && !VirtInstr.empty();
        std::tie(VirtInstr, TraceEntry) = VMCtx->step())
    {
        auto InstructionTraceData = new QTreeWidgetItem();
        InstructionTraceData->setText(0, QString::number((TraceEntry->vip - TraceFileHeader->module_base) + ImageBase, 16));

        if (VMHandlers[TraceEntry->handler_idx].imm_size)
        {
            QString SecondOperandBytes;
            auto numByteOperand = VMHandlers[TraceEntry->handler_idx].imm_size / 8;
            auto spaceIdx = VirtInstr.find(" ") + 1;
            auto ImmValue = QString(VirtInstr.substr(
                spaceIdx, VirtInstr.size() - spaceIdx).c_str()).toULongLong(nullptr, 16);

            for (auto idx = 0u; idx < numByteOperand; ++idx)
            {
                SecondOperandBytes.append(QString::number(*(
                    reinterpret_cast<std::uint8_t*>(&ImmValue) + idx), 16));

                SecondOperandBytes.append(" ");
            }

            InstructionTraceData->setText(1, QString::number(
                TraceEntry->handler_idx, 16).append(" - ").append(SecondOperandBytes));
        }
        else
        {
            // else we just put the first operand byte (vm handler index)...
            InstructionTraceData->setText(1, QString::number(TraceEntry->handler_idx, 16));
        }

        InstructionTraceData->setText(2, VirtInstr.c_str());
        ui.VirtualInstructionTree->addTopLevelItem(InstructionTraceData);
    }
    ui.VirtualInstructionTree->topLevelItem(0)->setSelected(true);
}

void QVMProfiler::on_VirtualInstructionTree_itemSelectionChanged()
{
    auto SelectedItem = ui.VirtualInstructionTree->selectedItems()[0];
    auto VIPAddr = SelectedItem->data(0, 0).toString().toULongLong(nullptr, 16);
    vmp2::entry_t* Entry = nullptr;

    for (auto idx = 0u; idx < TraceFileHeader->entry_count; ++idx)
    {
        if ((TraceEntryList[idx].vip - TraceFileHeader->module_base) + ImageBase == VIPAddr)
        {
            Entry = &TraceEntryList[idx];
            break;
        }
    }

    ui.VirtualRegisterTree->topLevelItem(0)->setText(1, 
        QString::number((Entry->vip - TraceFileHeader->module_base) + ImageBase, 16));

    ui.VirtualRegisterTree->topLevelItem(1)->setText(1,
        QString::number(Entry->regs.rbp, 16));

    ui.VirtualRegisterTree->topLevelItem(2)->setText(1,
        QString::number(Entry->decrypt_key, 16));

    for (auto idx = 4; idx < 28; ++idx)
        ui.VirtualRegisterTree->topLevelItem(idx)->setText(1,
            QString::number(Entry->vregs.qword[idx - 4], 16));

    for (auto idx = 0u; idx < 15; ++idx)
        ui.NativeRegisterTree->topLevelItem(idx)->setText(1,
            QString::number(Entry->regs.raw[idx], 16));

    ui.NativeRegisterTree->topLevelItem(
        16)->setText(1, QString::number(Entry->regs.rflags, 16));

    rflags flags;
    flags.flags = Entry->regs.rflags;
    ui.NativeRegisterTree->topLevelItem(16)->child(0)->setText(
        1, QString::number(flags.zero_flag));

    ui.NativeRegisterTree->topLevelItem(16)->child(1)->setText(
        1, QString::number(flags.parity_flag));

    ui.NativeRegisterTree->topLevelItem(16)->child(2)->setText(
        1, QString::number(flags.auxiliary_carry_flag));

    ui.NativeRegisterTree->topLevelItem(16)->child(3)->setText(
        1, QString::number(flags.overflow_flag));

    ui.NativeRegisterTree->topLevelItem(16)->child(4)->setText(
        1, QString::number(flags.sign_flag));

    ui.NativeRegisterTree->topLevelItem(16)->child(5)->setText(
        1, QString::number(flags.direction_flag));

    ui.NativeRegisterTree->topLevelItem(16)->child(6)->setText(
        1, QString::number(flags.carry_flag));

    ui.NativeRegisterTree->topLevelItem(16)->child(7)->setText(
        1, QString::number(flags.trap_flag));

    ui.NativeRegisterTree->topLevelItem(16)->child(8)->setText(
        1, QString::number(flags.interrupt_enable_flag));

    ui.VirtualStackTree->clear();
    for (auto idx = 0u; idx < sizeof(Entry->vsp) / 8; ++idx)
    {
        auto newEntry = new QTreeWidgetItem();
        newEntry->setText(0, QString::number(Entry->regs.rbp - (idx * 8), 16));
        newEntry->setText(1, QString::number(Entry->vsp.qword[idx], 16));
        ui.VirtualStackTree->addTopLevelItem(newEntry);
    }

    ui.VMHandlerInstructionsTree->clear();
    auto InstrVec = &VMHandlers[Entry->handler_idx].instrs;

    char buffer[256];
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    for (auto idx = 0u; idx < InstrVec->size(); ++idx)
    {
        auto newEntry = new QTreeWidgetItem();
        newEntry->setText(0, QString::number(
            (InstrVec->at(idx).addr - TraceFileHeader->module_base) + ImageBase, 16));

        ZydisFormatterFormatInstruction(&formatter, &InstrVec->at(idx).instr,
            buffer, sizeof(buffer), (InstrVec->at(idx).addr -
                TraceFileHeader->module_base) + ImageBase);

        newEntry->setText(1, buffer);
        ui.VMHandlerInstructionsTree->addTopLevelItem(newEntry);
    }

    ui.VMHandlerTransformationsTree->clear();
    auto HandlerTransforms = &VMHandlers[Entry->handler_idx].transforms;

    for (auto [TransformType, TransformInstr] : *HandlerTransforms)
    {
        auto newEntry = new QTreeWidgetItem();
        switch (TransformType)
        {
        case vm::transform::type::rolling_key:
        {
            newEntry->setText(0, "Key Transform");
            break;
        }
        case vm::transform::type::generic1:
        case vm::transform::type::generic2:
        case vm::transform::type::generic3:
        {
            newEntry->setText(0, "Generic");
            break;
        }
        case vm::transform::type::update_key:
        {
            newEntry->setText(0, "Update Key");
            break;
        }
        default:
            throw std::invalid_argument("invalid transformation type...");
        }

        ZydisFormatterFormatInstruction(&formatter, &TransformInstr,
            buffer, sizeof(buffer), NULL);

        newEntry->setText(1, buffer);
        ui.VMHandlerTransformationsTree->addTopLevelItem(newEntry);
    }
}