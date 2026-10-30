package com.hyperscan.android

import java.security.MessageDigest

/** Detects likely secrets but never returns or persists a full matched value. */
object SecretScanner {
    data class Finding(val kind: String, val line: Int, val masked: String, val fingerprint: String)
    private data class Rule(val kind: String, val regex: Regex, val group: Int = 0)

    // Keep patterns specific enough to reduce noise; generic assignments are a last-resort rule.
    private val rules = listOf(
        Rule("AWS access key ID", Regex("""\b(?:AKIA|ASIA)[0-9A-Z]{16}\b""")),
        Rule("GitHub token", Regex("""\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b""")),
        Rule("Google API key", Regex("""\bAIza[0-9A-Za-z_-]{30,}\b""")),
        Rule("Stripe secret key", Regex("""\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b""")),
        Rule("Slack token", Regex("""\bxox[baprs]-[0-9A-Za-z-]{15,}\b""")),
        Rule("Discord bot token", Regex("""\b(?:mfa\.[A-Za-z0-9_-]{20,}|[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{20,})\b""")),
        Rule("SendGrid API key", Regex("""\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b""")),
        Rule("npm access token", Regex("""\bnpm_[A-Za-z0-9]{30,}\b""")),
        Rule("PyPI API token", Regex("""\bpypi-[A-Za-z0-9_-]{50,}\b""")),
        Rule("Twilio API key", Regex("""\bSK[0-9a-fA-F]{32}\b""")),
        Rule("Azure storage key assignment", Regex("""(?i)AccountKey\s*=\s*([A-Za-z0-9+/]{40,}={0,2})"""), 1),
        Rule("Private key marker", Regex("""-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----""")),
        Rule(
            "Generic secret assignment",
            Regex("""(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{16,})"""),
            1
        )
    )

    fun scan(text: String): List<Finding> {
        val out = ArrayList<Finding>()
        text.lineSequence().forEachIndexed { idx, line ->
            for (rule in rules) {
                rule.regex.findAll(line).forEach { match ->
                    val candidate = if (rule.group == 0) match.value else match.groups[rule.group]?.value
                    if (candidate.isNullOrBlank()) return@forEach
                    out += Finding(
                        kind = rule.kind,
                        line = idx + 1,
                        masked = mask(candidate),
                        fingerprint = sha256(candidate)
                    )
                }
            }
        }
        return out.distinctBy { Triple(it.kind, it.line, it.fingerprint) }
    }

    private fun mask(value: String): String =
        if (value.length <= 8) "[REDACTED]" else value.take(3) + "…" + value.takeLast(3)

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
