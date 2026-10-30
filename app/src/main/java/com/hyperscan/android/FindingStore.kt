package com.hyperscan.android

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Local persistent database for scan history and redacted findings.
 * Complete matched credentials are deliberately never written to disk.
 */
class FindingStore(context: Context) : SQLiteOpenHelper(context, "hyperscan.db", null, 2) {
    override fun onCreate(db: SQLiteDatabase) {
        createSchema(db)
    }

    private fun createSchema(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo TEXT NOT NULL,
                branch TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                files_seen INTEGER NOT NULL DEFAULT 0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'running',
                error_summary TEXT
            )
        """.trimIndent())
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo TEXT NOT NULL,
                branch TEXT NOT NULL,
                path TEXT NOT NULL,
                kind TEXT NOT NULL,
                line_no INTEGER NOT NULL,
                masked TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                confidence TEXT NOT NULL DEFAULT 'medium',
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT 'open',
                UNIQUE(repo, path, kind, line_no, fingerprint)
            )
        """.trimIndent())
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_scans_repo_started ON scan_runs(repo, started_at DESC)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            db.beginTransaction()
            try {
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS scan_runs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        repo TEXT NOT NULL,
                        branch TEXT NOT NULL,
                        started_at INTEGER NOT NULL,
                        finished_at INTEGER,
                        files_seen INTEGER NOT NULL DEFAULT 0,
                        findings_count INTEGER NOT NULL DEFAULT 0,
                        status TEXT NOT NULL DEFAULT 'running',
                        error_summary TEXT
                    )
                """.trimIndent())
                db.execSQL("ALTER TABLE findings ADD COLUMN branch TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE findings ADD COLUMN confidence TEXT NOT NULL DEFAULT 'medium'")
                db.execSQL("ALTER TABLE findings ADD COLUMN first_seen INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE findings ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE findings ADD COLUMN state TEXT NOT NULL DEFAULT 'open'")
                db.execSQL("UPDATE findings SET first_seen = created_at, last_seen = created_at")
                db.execSQL("ALTER TABLE findings RENAME TO findings_old")
                db.execSQL("""
                    CREATE TABLE findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        repo TEXT NOT NULL, branch TEXT NOT NULL, path TEXT NOT NULL,
                        kind TEXT NOT NULL, line_no INTEGER NOT NULL, masked TEXT NOT NULL,
                        fingerprint TEXT NOT NULL, confidence TEXT NOT NULL DEFAULT 'medium',
                        first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                        state TEXT NOT NULL DEFAULT 'open',
                        UNIQUE(repo, path, kind, line_no, fingerprint)
                    )
                """.trimIndent())
                db.execSQL("""
                    INSERT OR IGNORE INTO findings
                    (id,repo,branch,path,kind,line_no,masked,fingerprint,confidence,first_seen,last_seen,state)
                    SELECT id,repo,branch,path,kind,line_no,masked,fingerprint,confidence,first_seen,last_seen,state
                    FROM findings_old
                """.trimIndent())
                db.execSQL("DROP TABLE findings_old")
                createIndexes(db)
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        }
    }

    private fun createIndexes(db: SQLiteDatabase) {
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_scans_repo_started ON scan_runs(repo, started_at DESC)")
    }

    @Synchronized
    fun startScan(repo: String, branch: String): Long {
        val now = System.currentTimeMillis()
        val values = ContentValues().apply {
            put("repo", repo); put("branch", branch); put("started_at", now); put("status", "running")
        }
        return writableDatabase.insertOrThrow("scan_runs", null, values)
    }

    @Synchronized
    fun finishScan(id: Long, filesSeen: Int, findingsCount: Int, error: String? = null) {
        val values = ContentValues().apply {
            put("finished_at", System.currentTimeMillis())
            put("files_seen", filesSeen)
            put("findings_count", findingsCount)
            put("status", if (error == null) "completed" else "failed")
            put("error_summary", error?.take(300))
        }
        writableDatabase.update("scan_runs", values, "id=?", arrayOf(id.toString()))
    }

    @Synchronized
    fun save(repo: String, branch: String, path: String, finding: SecretScanner.Finding) {
        val now = System.currentTimeMillis()
        val values = ContentValues().apply {
            put("repo", repo); put("branch", branch); put("path", path)
            put("kind", finding.kind); put("line_no", finding.line)
            put("masked", finding.masked); put("fingerprint", finding.fingerprint)
            put("confidence", "medium"); put("first_seen", now); put("last_seen", now)
            put("state", "open")
        }
        val db = writableDatabase
        val updated = ContentValues().apply { put("last_seen", now); put("masked", finding.masked) }
        val where = "repo=? AND path=? AND kind=? AND line_no=? AND fingerprint=?"
        val args = arrayOf(repo, path, finding.kind, finding.line.toString(), finding.fingerprint)
        if (db.update("findings", updated, where, args) == 0) {
            db.insertWithOnConflict("findings", null, values, SQLiteDatabase.CONFLICT_IGNORE)
        }
    }

    fun recent(limit: Int = 200): List<String> {
        val out = mutableListOf<String>()
        readableDatabase.rawQuery(
            "SELECT repo,path,kind,line_no,masked,state FROM findings ORDER BY last_seen DESC LIMIT ?",
            arrayOf(limit.coerceIn(1, 1000).toString())
        ).use { c ->
            while (c.moveToNext()) {
                out += "${c.getString(0)}\n${c.getString(1)}:${c.getInt(3)} · ${c.getString(2)} · ${c.getString(4)} · ${c.getString(5)}"
            }
        }
        return out
    }

    fun scanHistory(limit: Int = 50): List<String> {
        val out = mutableListOf<String>()
        readableDatabase.rawQuery(
            "SELECT repo,branch,started_at,files_seen,findings_count,status FROM scan_runs ORDER BY started_at DESC LIMIT ?",
            arrayOf(limit.coerceIn(1, 500).toString())
        ).use { c ->
            while (c.moveToNext()) out += "${c.getString(0)} (${c.getString(1)}) · ${c.getInt(3)} files · ${c.getInt(4)} findings · ${c.getString(5)}"
        }
        return out
    }
}