/*
 * PmVault extensions - GUI integration manager.
 * Owns the "PmVault" menu, 2FA enrollment, audit-log viewer, LAN sync dialog,
 * database hardening (recycle-bin removal), the post-create 2FA offer, and
 * helpers used by the global quick-access panel.
 */

#ifndef PMP_MANAGER_H
#define PMP_MANAGER_H

#include <QObject>
#include <QEvent>
#include <QString>
#include <QVector>
#include <QPointer>

class Database;
class DatabaseWidget;
class QWidget;
class QMenuBar;

class PmpManager : public QObject
{
    Q_OBJECT

public:
    static PmpManager* instance();
    void install();
    // Idempotently (re)add the PmVault menu; recovers it if the menu bar is rebuilt.
    void ensureMenu();

    // Called by the open-database widget.
    static bool secondFactorGate(QWidget* parent, const QString& filePath);
    static void bindAudit(const QString& filePath);

    struct QuickEntry
    {
        QString uuid;
        QString title;
        QString username;
    };

    // The recycle-bin feature is removed from the product. This forces it off
    // and permanently removes any pre-existing recycle-bin group. It only marks
    // the database modified when something actually changed, so already-hardened
    // databases are not dirtied on every open.
    static void hardenDatabase(Database* db);

    // Helpers consumed by the global quick-access panel.
    static QVector<QuickEntry> quickEntries();
    static void quickCopy(const QString& uuid, bool password);
    static void quickAutoType(const QString& uuid);
    static bool hasUnlockedDatabase();
    static void requestMainWindow();

public slots:
    void removeTwoFactor();
    void showAuditLog();
    void showSync();
    void openDatabaseSecurity();
    void quickAccessSettings();

    // Invoked right after the new-database wizard creates and adds a tab.
    void onDatabaseCreated(DatabaseWidget* widget);

private slots:
    void enrollTwoFactor();

private:
    explicit PmpManager(QObject* parent = nullptr);
    Database* currentDatabase(DatabaseWidget** outWidget = nullptr) const;

    bool m_installed = false;
    // Cached at install time; never re-derived via QMainWindow::menuBar()
    // during teardown (that call dereferences the already-deleted layout and
    // crashes in QLayout::menuBar while the menu bar is being destroyed).
    QPointer<QMenuBar> m_menuBar;
    bool m_appShuttingDown = false;

protected:
    // Re-adds the PmVault menu if Qt ever removes it while rebuilding the menu bar.
    bool eventFilter(QObject* watched, QEvent* event) override;
};

#endif // PMP_MANAGER_H
