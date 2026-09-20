/*
 *  Copyright (C) 2012 Felix Geyer <debfx@fobos.de>
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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

#ifndef KEEPASSX_WELCOMEWIDGET_H
#define KEEPASSX_WELCOMEWIDGET_H

#include <QListWidgetItem>
#include <QPoint>

namespace Ui
{
    class WelcomeWidget;
}

class WelcomeWidget : public QWidget
{
    Q_OBJECT

public:
    explicit WelcomeWidget(QWidget* parent = nullptr);
    ~WelcomeWidget();
    void refreshLastDatabases();
    // Reveal a database file in the platform file manager.
    static void openContainingFolder(const QString& filePath);

public slots:
    // PmVault: full database manager dialog (open / reveal / remove / delete).
    void manageAllDatabases();

signals:
    void newDatabase();
    void openDatabase();
    void openDatabaseFile(QString);
    void importFile();
    // Emitted when the user asks to permanently delete a database file.
    void deleteDatabaseFileRequested(QString filePath);

protected:
    void keyPressEvent(QKeyEvent* event) override;
    void showEvent(QShowEvent* event) override;

private slots:
    void openDatabaseFromFile(QListWidgetItem* item);
    void showRecentContextMenu(const QPoint& pos);

private:
    const QScopedPointer<Ui::WelcomeWidget> m_ui;
    void removeFromLastDatabases(QListWidgetItem* item);
    void removePathFromLastDatabases(const QString& filePath);
    void confirmDeleteDatabaseFile(const QString& filePath, QWidget* parent);
};

#endif // KEEPASSX_WELCOMEWIDGET_H
