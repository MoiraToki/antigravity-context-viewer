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

> **Prerequisites**: `Node.js >= 22.4.0` (Python is optional for office/PDF attachment scanning; Local Compaction Cap Configuration supports Windows x64 desktop only).

```bash
# Clone repository and install the context viewer plugin
git clone https://github.com/MoiraToki/antigravity-context-viewer.git
cd antigravity-context-viewer
node cli.js install

# Local compaction cap configuration (can also be operated directly from the in-app panel)
node cli.js unlock status           # Check current compaction cap status
node cli.js unlock 512k --dry-run   # Dry-run pre-check for 512K tier (no files modified)
node cli.js unlock 512k             # Apply 512K tier (or custom tier like 768k; restart client to take effect)
node cli.js unlock restore          # Restore ONLY the local compaction cap to original default

# Uninstall the context viewer plugin (restore original client archive)
node cli.js restore
```
