package com.hyperscan.android

import java.security.MessageDigest

/** Detects likely secrets but never returns or persists a full matched value. */
object SecretScanner {
    data class Finding(val kind: String, val line: Int, val masked: String, val fingerprint: String)
    private data class Rule(val kind: String, val regex: Regex)
    private val rules = listOf(
        Rule("AWS access key ID", Regex("""\bAKIA[0-9A-Z]{16}\b""")),
        Rule("GitHub token", Regex("""\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b""")),
        Rule("Google API key", Regex("""\bAIza[0-9A-Za-z_-]{30,}\b""")),
        Rule("Stripe secret key", Regex("""\b(?:sk_live|rk_live)_[0-9A-Za-z]{16,}\b""")),
        Rule("Slack token", Regex("""\bxox[baprs]-[0-9A-Za-z-]{15,}\b""")),
        Rule("Private key marker", Regex("""-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----""")),
        Rule("Generic secret assignment", Regex("""(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{16,})"""))
    )

    fun scan(text: String): List<Finding> {
        val out = mutableListOf<Finding>()
        text.lineSequence().forEachIndexed { idx, line ->
            for (rule in rules) {
                val match = rule.regex.find(line) ?: continue
                val candidate = if (rule.kind == "Generic secret assignment") match.groups[1]?.value else match.value
                if (candidate.isNullOrBlank()) continue
                val digest = sha256(candidate)
                val mask = if (candidate.length <= 8) "[REDACTED]" else candidate.take(3) + "…" + candidate.takeLast(3)
                out += Finding(rule.kind, idx + 1, mask, digest)
            }
        }
        return out.distinctBy { Triple(it.kind, it.line, it.fingerprint) }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}