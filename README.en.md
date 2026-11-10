# Antigravity Context & Token Viewer (Fork)

<p align="center">
  <a href="README.md">简体中文</a> | <b>English</b>
</p>

## 📌 Upstream Project

This repository is a secondary development (fork) based on [elviscjn-cjn/antigravity-context-viewer](https://github.com/elviscjn-cjn/antigravity-context-viewer) (`v0.8.0`). Please refer to the upstream repository for original features and documentation.

---

## 🛠️ What's Added in This Fork

1. **Visual Local Context Compaction Cap Configuration (Windows x64)**
   - Added a **"🔓 Local Compaction Cap Configuration"** section inside the Session Context panel, allowing users to inspect the current local compaction threshold and switch between presets directly from the UI:
     - `256K Default`
     - `512K (v4)`
     - `1M (1000K)`
     - `Unlimited Local Cap (v3)`
     - `Custom Tier (64K–4096K)`
2. **Pre-check, In-App Apply & One-Click Original Restore**
   - Supports dry-run inspection, applying tiers while the client is running, full restoration to the original backup, and interrupted action recovery (restart the Antigravity client after applying for changes to take effect).
   - Added the `unlock` CLI subcommand (`status`, `256k`, `512k`, `1m`, `unlimited`, custom `<K>`, `restore`, `recover`, and `--dry-run`).
3. **Repository & Documentation Cleanup**
   - Removed the `assets/` directory and image references.
   - Kept only Simplified Chinese (`README.md`) and English (`README.en.md`) documentation.

---

## 🚀 Basic Usage

```bash
# Install plugin
node cli.js install

# Check or change local compaction cap via CLI (or use the in-app panel directly)
node cli.js unlock status
node cli.js unlock 512k
node cli.js unlock restore

# Restore original client archive
node cli.js restore
```
