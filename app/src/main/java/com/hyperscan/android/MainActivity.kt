package com.hyperscan.android

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val client = OkHttpClient.Builder().connectTimeout(10, TimeUnit.SECONDS).readTimeout(15, TimeUnit.SECONDS).callTimeout(20, TimeUnit.SECONDS).build()
    private lateinit var input: EditText
    private lateinit var status: TextView
    private lateinit var results: TextView
    private lateinit var store: FindingStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = FindingStore(this)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 28, 24, 16) }
        root.addView(TextView(this).apply { text = "HyperScan"; textSize = 28f; gravity = Gravity.CENTER_VERTICAL })
        root.addView(TextView(this).apply { text = "Fast secret scanning for repositories you own or are authorized to audit."; textSize = 14f; setPadding(0, 8, 0, 12) })
        input = EditText(this).apply { hint = "owner/repository"; singleLine = true }
        root.addView(input)
        root.addView(Button(this).apply { text = "Scan repository"; setOnClickListener { startScan() } })
        status = TextView(this).apply { text = "Ready. Public GitHub repositories only; API limits apply."; setPadding(0, 12, 0, 8) }
        root.addView(status)
        results = TextView(this).apply { textSize = 13f; setTextIsSelectable(true) }
        val scroll = ScrollView(this).apply { addView(results) }
        root.addView(scroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)
        showRecent()
    }

    private fun startScan() {
        val repo = input.text.toString().trim().trim('/')
        if (!repo.matches(Regex("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"))) { status.text = "Enter a valid owner/repository."; return }
        status.text = "Fetching repository metadata…"
        results.text = ""
        scope.launch {
            try {
                val count = withContext(Dispatchers.IO) { scanRepository(repo) }
                status.text = "Finished: $count finding(s). Full credential values are never saved."
                showRecent()
            } catch (e: CancellationException) { throw e }
            catch (e: Exception) { status.text = "Scan failed: ${e.message ?: "network or API error"}" }
        }
    }

    private fun scanRepository(repo: String): Int {
        fun get(url: String): String {
            val req = Request.Builder().url(url).header("Accept", "application/vnd.github+json").header("User-Agent", "HyperScan-Android").build()
            client.newCall(req).execute().use { response ->
                if (!response.isSuccessful) throw IllegalStateException("GitHub HTTP ${response.code}; check repository, connectivity, or rate limit")
                return response.body?.string() ?: ""
            }
        }
        val metadata = JSONObject(get("https://api.github.com/repos/$repo"))
        val branch = metadata.optString("default_branch", "main")
        val tree = JSONObject(get("https://api.github.com/repos/$repo/git/trees/$branch?recursive=1"))
        val items = tree.optJSONArray("tree") ?: return 0
        val paths = (0 until items.length()).mapNotNull { i -> items.optJSONObject(i) }
            .filter { it.optString("type") == "blob" && it.optLong("size", Long.MAX_VALUE) in 1..500_000 }
            .map { it.optString("path") }
            .filter { p -> !p.startsWith(".git/") && !listOf(".png", ".jpg", ".jpeg", ".zip", ".jar", ".pdf", ".webp", ".gif").any { p.endsWith(it, true) } }
            .take(300)
        val sem = Semaphore(6)
        val found = AtomicInteger(0)
        runBlocking {
            val jobs = paths.map { path ->
                async(Dispatchers.IO) {
                    sem.withPermit {
                        try {
                            val encoded = path.split("/").joinToString("/") { java.net.URLEncoder.encode(it, "UTF-8").replace("+", "%20") }
                            val raw = get("https://raw.githubusercontent.com/$repo/$branch/$encoded")
                            if (raw.length > 600_000) return@withPermit
                            SecretScanner.scan(raw).forEach { finding ->
                                store.save(repo, path, finding)
                                found.incrementAndGet()
                            }
                        } catch (_: Exception) {
                            // One inaccessible or binary-like file must not abort the scan.
                        }
                    }
                }
            }
            jobs.forEach { it.await() }
        }
        return found.get()
    }

    private fun showRecent() { results.text = store.recent().joinToString("\n\n").ifBlank { "No findings saved yet." } }
    override fun onDestroy() { scope.cancel(); store.close(); super.onDestroy() }
}