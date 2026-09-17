/*
 * PmVault extensions - GUI wiring and lifecycle manager.
 *
 * Adds a "PmVault" menu to the main window and provides the second-factor gate
 * invoked from the database open flow. All dialogs are built in code (no .ui
 * files) to keep the fork self-contained.
 */

#ifndef PMP_MANAGER_H
#define PMP_MANAGER_H

#include <QObject>

class Database;
class DatabaseWidget;
class QWidget;

class PmpManager : public QObject
{
    Q_OBJECT
public:
    static PmpManager* instance();

    // Call once after the main window exists.
    void install();

    // Second-factor gate for the open-database flow. Returns true if 2FA is not
    // enrolled or if the user passed verification; false to abort the unlock.
    static bool secondFactorGate(QWidget* parent, const QString& filePath);

    // Bind (or refresh) the encrypted audit log to an opened database file.
    static void bindAudit(const QString& filePath);

private slots:
    void enrollTwoFactor();
    void removeTwoFactor();
    void showAuditLog();
    void showSync();

private:
    explicit PmpManager(QObject* parent = nullptr);
    Database* currentDatabase(DatabaseWidget** outWidget = nullptr) const;

    bool m_installed = false;
};

#endif // PMP_MANAGER_H
