# HyperScan Android

A fast defensive secret-scanning Android app for repositories you own or are authorized to assess. It identifies likely credential exposure and stores only redacted findings locally. It does not collect or export complete third-party API keys.

## Features
- Scan a public GitHub repository by owner/name.
- Bounded concurrent fetching, pattern detection, local SQLite findings, and deduplication.
- APK build through GitHub Actions.

## Build
Use Android Studio with JDK 17 and Android SDK 35, or run Gradle 8.9+: `gradle :app:assembleDebug`. GitHub Actions builds a debug APK on pushes and pull requests; download it from the workflow Artifacts section.

## Safety
Use only on repositories you own or are authorized to audit. Findings are redacted; complete matched values are not persisted or exported. Detection is heuristic and may produce false positives or miss secrets. Never test credentials without authorization. Rotate any credential you own that has been exposed.

## Privacy
No telemetry is implemented. Repository contents are fetched from GitHub to scan the repository entered. Findings remain on-device.

MIT License.