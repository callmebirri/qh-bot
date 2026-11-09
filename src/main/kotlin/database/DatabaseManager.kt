package database

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import java.io.File
import java.sql.Connection

class DatabaseManager(
    private val dbPath: String = "./data/accounts.db",
    maxPoolSize: Int = 1,
    connectionTimeoutMs: Long = 5000L,
) : AutoCloseable {

    private val dataSource: HikariDataSource

    init {
        val dbFile = File(dbPath)
        dbFile.parentFile?.mkdirs()

        val config = HikariConfig().apply {
            jdbcUrl = "jdbc:sqlite:$dbPath"
            driverClassName = "org.sqlite.JDBC"
            maximumPoolSize = maxPoolSize
            connectionTimeout = connectionTimeoutMs
            isAutoCommit = true
        }
        dataSource = HikariDataSource(config)
        initSchema()
        Runtime.getRuntime().addShutdownHook(Thread { close() })
    }

    private fun initSchema() {
        dataSource.connection.use { conn ->
            conn.createStatement().use { stmt ->
                stmt.execute(
                    """
                    CREATE TABLE IF NOT EXISTS recovered_accounts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_email TEXT NOT NULL,
                        current_primary_email TEXT NOT NULL,
                        password TEXT NOT NULL,
                        recovery_code TEXT,
                        owns_minecraft INTEGER DEFAULT 0,
                        status TEXT NOT NULL DEFAULT 'PENDING',
                        fail_reason TEXT,
                        created_at INTEGER,
                        updated_at INTEGER
                    );
                    CREATE INDEX IF NOT EXISTS idx_recovered_accounts_email ON recovered_accounts(original_email);
                    CREATE INDEX IF NOT EXISTS idx_recovered_accounts_primary ON recovered_accounts(current_primary_email);
                    """.trimIndent(),
                )
            }
            ensureColumnExists(conn, "recovered_accounts", "status", "TEXT NOT NULL DEFAULT 'PENDING'")
            ensureColumnExists(conn, "recovered_accounts", "fail_reason", "TEXT")
        }
    }

    private fun ensureColumnExists(conn: Connection, tableName: String, columnName: String, columnDef: String) {
        val existingColumns = mutableSetOf<String>()
        conn.createStatement().use { stmt ->
            stmt.executeQuery("PRAGMA table_info($tableName)").use { rs ->
                while (rs.next()) {
                    existingColumns.add(rs.getString("name").lowercase())
                }
            }
            if (!existingColumns.contains(columnName.lowercase())) {
                stmt.execute("ALTER TABLE $tableName ADD COLUMN $columnName $columnDef")
            }
        }
    }

    fun getConnection(): Connection = dataSource.connection

    override fun close() {
        if (!dataSource.isClosed) {
            dataSource.close()
        }
    }
}
