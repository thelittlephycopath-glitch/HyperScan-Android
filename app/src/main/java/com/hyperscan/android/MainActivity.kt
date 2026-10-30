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
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.net.URLEncoder
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .callTimeout(20, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()
    private lateinit var input: EditText
    private lateinit var status: TextView
    private lateinit var results: TextView
    private lateinit var store: FindingStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = FindingStore(this)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 28, 24, 16) }
        root.addView(TextView(this).apply { text = "HyperScan"; textSize = 28f; gravity = Gravity.CENTER_VERTICAL })
        root.addView(TextView(this).apply {
            text = "Fast secret scanning for repositories you own or are authorized to audit."
            textSize = 14f
            setPadding(0, 8, 0, 12)
        })
        input = EditText(this).apply {
            hint = "owner/repository"
            setSingleLine(true)
        }
        root.addView(input)
        root.addView(Button(this).apply { text = "Scan repository"; setOnClickListener { startScan() } })
        status = TextView(this).apply {
            text = "Ready. Public GitHub repositories only; API limits apply."
            setPadding(0, 12, 0, 8)
        }
        root.addView(status)
        results = TextView(this).apply { textSize = 13f; setTextIsSelectable(true) }
        val scroll = ScrollView(this).apply { addView(results) }
        root.addView(scroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)
        showRecent()
    }

    private fun startScan() {
        val repo = input.text.toString().trim().trim('/')
        if (!repo.matches(Regex("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"))) {
            status.text = "Enter a valid owner/repository."
            return
        }
        status.text = "Fetching repository metadata…"
        results.text = ""
        scope.launch {
            try {
                val count = withContext(Dispatchers.IO) { scanRepository(repo) }
                status.text = "Finished: $count finding(s). Full credential values are never saved."
                showRecent()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                status.text = "Scan failed: ${e.message ?: "network or API error"}"
            }
        }
    }

    private suspend fun scanRepository(repo: String): Int {
        fun get(url: String): String {
            val request = Request.Builder()
                .url(url)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "HyperScan-Android")
                .build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val hint = when (response.code) {
                        403, 429 -> "GitHub rate limit reached; wait and retry"
                        404 -> "Repository or branch not found"
                        else -> "GitHub HTTP ${response.code}"
                    }
                    throw IllegalStateException(hint)
                }
                return response.body?.string() ?: ""
            }
        }

        val metadata = JSONObject(get("https://api.github.com/repos/$repo"))
        val branch = metadata.optString("default_branch", "main")
        val scanId = store.startScan(repo, branch)
        val found = AtomicInteger(0)
        val seen = AtomicInteger(0)
        try {
            val tree = JSONObject(get("https://api.github.com/repos/$repo/git/trees/${URLEncoder.encode(branch, "UTF-8")}"))
            if (tree.optBoolean("truncated", false)) {
                throw IllegalStateException("Repository tree is too large for a complete scan; narrow the scan scope.")
            }
            val items = tree.optJSONArray("tree") ?: throw IllegalStateException("Repository tree unavailable")
            val ignoredExtensions = setOf(
                ".png", ".jpg", ".jpeg", ".zip", ".jar", ".pdf", ".webp", ".gif", ".ico",
                ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".class", ".so", ".aar", ".apk"
            )
            val ignoredDirectories = setOf(".git", "node_modules", "build", ".gradle", "vendor")
            val paths = (0 until items.length()).mapNotNull { i -> items.optJSONObject(i) }
                .asSequence()
                .filter { it.optString("type") == "blob" && it.optLong("size", Long.MAX_VALUE) in 1..500_000 }
                .map { it.optString("path") }
                .filter { path ->
                    val parts = path.split('/')
                    parts.none { it in ignoredDirectories } &&
                        ignoredExtensions.none { path.endsWith(it, ignoreCase = true) }
                }
                .take(1_000)
                .toList()

            coroutineScope {
                // At most six requests/jobs exist at once; no unbounded async job list.
                paths.chunked(6).forEach { batch ->
                    batch.map { path ->
                        async(Dispatchers.IO) {
                            try {
                                val encodedPath = path.split('/').joinToString("/") {
                                    URLEncoder.encode(it, "UTF-8").replace("+", "%20")
                                }
                                val encodedBranch = URLEncoder.encode(branch, "UTF-8").replace("+", "%20")
                                val raw = get("https://raw.githubusercontent.com/$repo/$encodedBranch/$encodedPath")
                                if (raw.length <= 500_000) {
                                    seen.incrementAndGet()
                                    SecretScanner.scan(raw).forEach { finding ->
                                        store.save(repo, branch, path, finding)
                                        found.incrementAndGet()
                                    }
                                }
                            } catch (e: CancellationException) {
                                throw e
                            } catch (_: Exception) {
                                // One unavailable file must not abort the repository scan.
                            }
                        }
                    }.awaitAll()
                }
            }
            store.finishScan(scanId, seen.get(), found.get())
            return found.get()
        } catch (e: Exception) {
            store.finishScan(scanId, seen.get(), found.get(), e.message ?: "Scan failed")
            throw e
        }
    }

    private fun showRecent() {
        results.text = "RECENT FINDINGS\n\n" +
            store.recent().joinToString("\n\n").ifBlank { "No findings saved yet." } +
            "\n\nSCAN HISTORY\n\n" +
            store.scanHistory().joinToString("\n").ifBlank { "No scans yet." }
    }

    override fun onDestroy() {
        scope.cancel()
        store.close()
        client.dispatcher.executorService.shutdown()
        client.connectionPool.evictAll()
        super.onDestroy()
    }
}
