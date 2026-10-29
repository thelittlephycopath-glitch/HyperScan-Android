package com.hyperscan.android

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class FindingStore(context: Context) : SQLiteOpenHelper(context, "hyperscan.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, repo TEXT NOT NULL, path TEXT NOT NULL, kind TEXT NOT NULL, line_no INTEGER NOT NULL, masked TEXT NOT NULL, fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(repo,path,kind,line_no,fingerprint))")
    }
    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) { }

    @Synchronized fun save(repo: String, path: String, finding: SecretScanner.Finding) {
        val values = ContentValues().apply {
            put("repo", repo); put("path", path); put("kind", finding.kind); put("line_no", finding.line)
            put("masked", finding.masked); put("fingerprint", finding.fingerprint); put("created_at", System.currentTimeMillis())
        }
        writableDatabase.insertWithOnConflict("findings", null, values, SQLiteDatabase.CONFLICT_IGNORE)
    }

    fun recent(limit: Int = 200): List<String> {
        val out = mutableListOf<String>()
        readableDatabase.rawQuery("SELECT repo,path,kind,line_no,masked FROM findings ORDER BY created_at DESC LIMIT ?", arrayOf(limit.toString())).use { c ->
            while (c.moveToNext()) out += "${c.getString(0)}\n${c.getString(1)}:${c.getInt(3)} · ${c.getString(2)} · ${c.getString(4)}"
        }
        return out
    }
}