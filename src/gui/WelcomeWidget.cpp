/*
 *  Copyright (C) 2012 Felix Geyer <debfx@fobos.de>
 *  Copyright (C) 2020 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "WelcomeWidget.h"
#include "ui_WelcomeWidget.h"
#include <QAbstractItemView>
#include <QAction>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QListWidget>
#include <QMenu>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>

#include "config-keepassx.h"
#include "core/Config.h"
#include "gui/Icons.h"

WelcomeWidget::WelcomeWidget(QWidget* parent)
    : QWidget(parent)
    , m_ui(new Ui::WelcomeWidget())
{
    m_ui->setupUi(this);

    m_ui->welcomeLabel->setText(tr("Welcome to KeePassXC %1").arg(KEEPASSXC_VERSION));
    QFont welcomeLabelFont = m_ui->welcomeLabel->font();
    welcomeLabelFont.setBold(true);
    welcomeLabelFont.setPointSize(welcomeLabelFont.pointSize() + 4);
    m_ui->welcomeLabel->setFont(welcomeLabelFont);

    m_ui->iconLabel->setPixmap(icons()->applicationIcon().pixmap(64));
    m_ui->buttonNewDatabase->setIcon(icons()->icon("document-new"));
    m_ui->buttonNewDatabase->setStyleSheet("text-align:center;");
    m_ui->buttonOpenDatabase->setIcon(icons()->icon("document-open"));
    m_ui->buttonOpenDatabase->setStyleSheet("text-align:center;");
    m_ui->buttonImport->setIcon(icons()->icon("document-import"));
    m_ui->buttonImport->setStyleSheet("text-align:center;");

    refreshLastDatabases();

    connect(m_ui->buttonNewDatabase, SIGNAL(clicked()), SIGNAL(newDatabase()));
    connect(m_ui->buttonOpenDatabase, SIGNAL(clicked()), SIGNAL(openDatabase()));
    connect(m_ui->buttonImport, SIGNAL(clicked()), SIGNAL(importFile()));
    connect(m_ui->recentListWidget,
            SIGNAL(itemActivated(QListWidgetItem*)),
            this,
            SLOT(openDatabaseFromFile(QListWidgetItem*)));

    // PmVault: right-click a recent database to open its folder or remove it.
    m_ui->recentListWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_ui->recentListWidget, &QListWidget::customContextMenuRequested,
            this, &WelcomeWidget::showRecentContextMenu);
}

WelcomeWidget::~WelcomeWidget()
{
}

void WelcomeWidget::openDatabaseFromFile(QListWidgetItem* item)
{
    if (!item || item->text().isEmpty()) {
        return;
    }
    emit openDatabaseFile(item->text());
}

void WelcomeWidget::openContainingFolder(const QString& filePath)
{
    const QFileInfo fi(filePath);
#ifdef Q_OS_WIN
    // Select the database file in Explorer.
    QProcess::startDetached(QStringLiteral("explorer.exe"),
                            QStringList{QStringLiteral("/select,") +
                                        QDir::toNativeSeparators(fi.absoluteFilePath())});
#else
    QDesktopServices::openUrl(QUrl::fromLocalFile(fi.absolutePath()));
#endif
}

void WelcomeWidget::showRecentContextMenu(const QPoint& pos)
{
    QListWidgetItem* item = m_ui->recentListWidget->itemAt(pos);
    if (!item || item->text().isEmpty()) {
        return;
    }
    QMenu menu(this);
    QAction* openAction = menu.addAction(tr("打开数据库"));
    QAction* openFolderAction = menu.addAction(tr("打开所在文件夹"));
    menu.addSeparator();
    QAction* deleteAction = menu.addAction(tr("删除数据库文件…"));
    QAction* removeAction = menu.addAction(tr("从列表中移除"));
    QAction* chosen = menu.exec(m_ui->recentListWidget->viewport()->mapToGlobal(pos));
    if (chosen == openAction) {
        openDatabaseFromFile(item);
    } else if (chosen == openFolderAction) {
        openContainingFolder(item->text());
    } else if (chosen == deleteAction) {
        confirmDeleteDatabaseFile(item->text(), this);
        refreshLastDatabases();
    } else if (chosen == removeAction) {
        removeFromLastDatabases(item);
    }
}

void WelcomeWidget::removePathFromLastDatabases(const QString& filePath)
{
    if (filePath.isEmpty()) {
        return;
    }
    if (config()->get(Config::RememberLastDatabases).toBool()) {
        QStringList lastDatabases = config()->get(Config::LastDatabases).toStringList();
        lastDatabases.removeAll(filePath);
        config()->set(Config::LastDatabases, lastDatabases);
    }
}

void WelcomeWidget::confirmDeleteDatabaseFile(const QString& filePath, QWidget* parent)
{
    if (filePath.isEmpty()) {
        return;
    }
    const auto answer = QMessageBox::warning(
        parent, tr("删除数据库"),
        tr("确定永久删除该数据库文件吗？\n\n%1\n\n文件及其备份历史条目都将被移除，此操作无法撤销。").arg(filePath),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes) {
        return;
    }
    // Ask the main window to close any tab that still has the database open
    // (synchronous direct connection) before removing the file on disk.
    emit deleteDatabaseFileRequested(filePath);

    bool removed = true;
    if (QFileInfo::exists(filePath)) {
        removed = QFile::remove(filePath);
    }
    if (!removed) {
        QMessageBox::critical(
            parent, tr("删除数据库"),
            tr("文件无法删除，可能正被其他程序打开或受保护。\n\n%1")
                .arg(filePath));
        return;
    }
    removePathFromLastDatabases(filePath);
}

void WelcomeWidget::manageAllDatabases()
{
    QDialog dlg(this);
    dlg.setWindowTitle(tr("管理数据库"));
    dlg.resize(620, 420);
    auto* layout = new QVBoxLayout(&dlg);

    auto* list = new QListWidget(&dlg);
    list->setSelectionMode(QAbstractItemView::SingleSelection);
    list->setContextMenuPolicy(Qt::CustomContextMenu);
    layout->addWidget(list);

    auto populate = [this, list]() {
        list->clear();
        const QStringList lastDatabases = config()->get(Config::LastDatabases).toStringList();
        for (const QString& database : lastDatabases) {
            auto* itm = new QListWidgetItem(database, list);
            itm->setToolTip(database);
        }
    };
    populate();

    auto selectedPath = [list]() -> QString {
        QListWidgetItem* itm = list->currentItem();
        return itm ? itm->text() : QString();
    };

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
    buttons->button(QDialogButtonBox::Close)->setText(tr("关闭"));
    auto* openBtn = buttons->addButton(tr("打开"), QDialogButtonBox::AcceptRole);
    auto* folderBtn = buttons->addButton(tr("打开所在文件夹"), QDialogButtonBox::ActionRole);
    auto* removeBtn = buttons->addButton(tr("从列表中移除"), QDialogButtonBox::ActionRole);
    auto* deleteBtn = buttons->addButton(tr("删除数据库文件…"), QDialogButtonBox::DestructiveRole);
    layout->addWidget(buttons);

    QObject::connect(openBtn, &QPushButton::clicked, &dlg, [&]() {
        const QString path = selectedPath();
        if (!path.isEmpty()) {
            emit openDatabaseFile(path);
            dlg.accept();
        }
    });
    QObject::connect(folderBtn, &QPushButton::clicked, &dlg, [&]() {
        const QString path = selectedPath();
        if (!path.isEmpty()) {
            openContainingFolder(path);
        }
    });
    QObject::connect(removeBtn, &QPushButton::clicked, &dlg, [&]() {
        const QString path = selectedPath();
        if (!path.isEmpty()) {
            removePathFromLastDatabases(path);
            populate();
        }
    });
    QObject::connect(deleteBtn, &QPushButton::clicked, &dlg, [&]() {
        const QString path = selectedPath();
        if (!path.isEmpty()) {
            confirmDeleteDatabaseFile(path, &dlg);
            populate();
            refreshLastDatabases();
        }
    });

    // Right-click menu mirroring the buttons.
    QObject::connect(list, &QListWidget::customContextMenuRequested, &dlg, [&](const QPoint& pos) {
        QListWidgetItem* itm = list->itemAt(pos);
        if (!itm) {
            return;
        }
        QMenu menu(&dlg);
        QAction* openAction = menu.addAction(tr("打开数据库"));
        QAction* folderAction = menu.addAction(tr("打开所在文件夹"));
        menu.addSeparator();
        QAction* deleteAction = menu.addAction(tr("删除数据库文件…"));
        QAction* removeAction = menu.addAction(tr("从列表中移除"));
        QAction* chosen = menu.exec(list->viewport()->mapToGlobal(pos));
        if (chosen == openAction) {
            emit openDatabaseFile(itm->text());
            dlg.accept();
        } else if (chosen == folderAction) {
            openContainingFolder(itm->text());
        } else if (chosen == removeAction) {
            removePathFromLastDatabases(itm->text());
            populate();
        } else if (chosen == deleteAction) {
            confirmDeleteDatabaseFile(itm->text(), &dlg);
            populate();
            refreshLastDatabases();
        }
    });
    QObject::connect(list, &QListWidget::itemActivated, &dlg, [&](QListWidgetItem* itm) {
        if (itm) {
            emit openDatabaseFile(itm->text());
            dlg.accept();
        }
    });
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    dlg.exec();
}

void WelcomeWidget::removeFromLastDatabases(QListWidgetItem* item)
{
    if (!item || item->text().isEmpty()) {
        return;
    }
    removePathFromLastDatabases(item->text());
    refreshLastDatabases();
}

void WelcomeWidget::refreshLastDatabases()
{
    m_ui->recentListWidget->clear();
    const QStringList lastDatabases = config()->get(Config::LastDatabases).toStringList();
    for (const QString& database : lastDatabases) {
        QListWidgetItem* itm = new QListWidgetItem;
        itm->setText(database);
        m_ui->recentListWidget->addItem(itm);
    }

    bool recent_visibility = (m_ui->recentListWidget->count() > 0);
    m_ui->startLabel->setVisible(!recent_visibility);
    m_ui->recentListWidget->setVisible(recent_visibility);
    m_ui->recentLabel->setVisible(recent_visibility);
}

void WelcomeWidget::keyPressEvent(QKeyEvent* event)
{
    if (m_ui->recentListWidget->hasFocus()) {
        if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
            openDatabaseFromFile(m_ui->recentListWidget->currentItem());
        } else if (event->key() == Qt::Key_Delete || event->key() == Qt::Key_Backspace) {
            removeFromLastDatabases(m_ui->recentListWidget->currentItem());
        }
    }

    QWidget::keyPressEvent(event);
}

void WelcomeWidget::showEvent(QShowEvent* event)
{
    refreshLastDatabases();
    QWidget::showEvent(event);
}
