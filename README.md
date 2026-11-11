# Antigravity Context & Token Viewer（二次开发版）

<p align="center">
  <b>简体中文</b> | <a href="README.en.md">English</a>
</p>

## 📌 原项目来源

本仓库基于 [elviscjn-cjn/antigravity-context-viewer](https://github.com/elviscjn-cjn/antigravity-context-viewer)（`v0.8.0`）进行二次开发。原项目的基础功能与说明请参阅上游仓库。

---

## 🛠️ 二次开发工作内容

1. **新增本地上下文压缩上限可视化配置（Windows x64）**
   - 在「会话上下文」面板内新增 **「🔓 本地压缩上限配置」** 折叠区，支持直接在界面中查看当前状态并切换本地压缩阈值档位：
     - `256K 默认`
     - `512K (v4)`
     - `1M (1000K)`
     - `取消本地封顶 (v3)`
     - `自定义档位（64K–4096K）`
2. **支持预检、在线替换与一键还原原版**
   - 支持在客户端运行期间直接执行档位预检、应用所选档位、从原版备份完整还原以及异常中断恢复（应用修改后重启 Antigravity 客户端即可生效）。
   - 命令行同步新增 `unlock` 子命令（支持 `status`、`256k`、`512k`、`1m`、`unlimited`、自定义 `<K>`、`restore`、`recover` 及 `--dry-run`）。
3. **仓库与文档精简**
   - 移除 `assets/` 静态预览图目录及相关引用。
   - 移除多余语种说明文档，仅保留简体中文（`README.md`）与英文（`README.en.md`）。

---

## 🚀 基本使用

> **前置要求**：`Node.js >= 22.4.0`（可选安装 Python 以支持本地办公文档附件深度解析；「本地压缩上限配置」仅支持 Windows x64 桌面端）。

```bash
# 克隆仓库并安装上下文看板插件
git clone https://github.com/MoiraToki/antigravity-context-viewer.git
cd antigravity-context-viewer
node cli.js install

# 本地压缩上限配置（也可直接在客户端上下文面板内点击操作）
node cli.js unlock status           # 查看当前压缩上限状态
node cli.js unlock 512k --dry-run   # 预检 512K 档位（不修改文件）
node cli.js unlock 512k             # 应用 512K 档位（也可填 768k 等自定义档位，重启客户端生效）
node cli.js unlock restore          # 仅还原「本地压缩上限」至原版默认

# 卸载上下文看板插件（还原客户端原包）
node cli.js restore
```
