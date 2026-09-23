# ⚡ vpn2qr Web - 纯前端零知识 VPS 节点一键搭建工具

> 📌 **项目溯源声明与致谢**：  
> 本项目是开源项目 [**vpn2qr (https://github.com/www222fff/vpn2qr)**](https://github.com/www222fff/vpn2qr) 的纯前端/Web 端无服务器（Serverless）增强版本。核心的 VLESS + XTLS-Vision + REALITY 协议配置、自动化部署逻辑及免重装快速提取工具均基于 **[www222fff/vpn2qr](https://github.com/www222fff/vpn2qr)** 实现。本项目致力于让不了解 SSH 终端操作的小白用户能够在浏览器中通过零知识安全通道一键完成节点部署与扫码。

---

## 🛡️ 重点中的重点：零知识隐私安全架构 (Zero-Knowledge Architecture)

很多小白用户不敢在第三方网站输入服务器密码，本项目的核心优势在于**彻底消除了中心化服务器窃取凭证的可能**：

```
[用户浏览器]
   │ 
   ├── 1. 用户输入 IP、root 密码（仅存留于浏览器运行时内存）
   ├── 2. 浏览器内 WebAssembly (WASM) 运行原生 Go SSH 引擎
   │       (在浏览器内部完成密钥协商、证书校验、AES/ChaCha20 握手加解密)
   │
   ▼ (纯密文 WebSocket 数据帧)
[Cloudflare Worker 盲中继 (Blind Relay)]
   │ 
   ├── 使用官方 connect() API 直连目标 VPS 22 端口
   └── ⚠️ 仅做底层二进制数据流转发，无解密私钥，绝无可能解密或截获明文！
   │
   ▼ (原生 TCP 流量)
[用户的目标 VPS (端口 22)]
   │
   └── 执行 install.sh 脚本，配置 Xray Reality，返回节点
```

* **端侧加解密 (E2EE)**：SSH 协议的密码学认证和指令交互 **100% 在用户浏览器的 WASM 进程内**完成。
* **盲管道中继**：Cloudflare Worker 不存储任何数据，不解析协议，无数据库，无日志保留。
* **本地矢量绘制**：最终的二维码由前端 JavaScript 本地 Canvas/SVG 直接渲染，不调用任何第三方图床或外部 API。
* **随用随销**：页面关闭或刷新后，浏览器内存立即释放，不留下任何历史痕迹。

---

## 📁 目录结构

```tree
1click2VPN/
├── public/                 # 静态前端资源（直接部署到 Cloudflare Pages）
│   ├── index.html          # 现代化交互界面 (Tailwind CSS)
│   ├── app.js              # 前端调度与状态机控制逻辑
│   ├── vpn2qr.wasm         # 编译后的 Go WebAssembly SSH 核心引擎
│   └── wasm_exec.js        # Go 官方 WebAssembly 运行时桥接
├── wasm/                   # 端侧 SSH WebAssembly 源码 (Go 语言)
│   ├── main.go             # WASM 入口、JS 导出函数与输出流式监听
│   ├── conn.go             # 将浏览器 WebSocket 包装为 Go net.Conn
│   ├── go.mod              # Go 依赖配置
│   └── build.sh            # 一键编译生成 WASM 的自动化脚本
├── worker/                 # Cloudflare Worker 盲中继服务源码
│   ├── worker.js           # 基于 cloudflare:sockets 的 WebSocket ⇄ TCP 中继与 SSRF 防护
│   └── wrangler.toml       # Cloudflare Wrangler 配置文件
└── README.md
```

---

## 🚀 部署到 Cloudflare 极速指南（3 分钟完成）

本项目采用 **Cloudflare Pages（托管前端） + Cloudflare Worker（盲中继）** 的纯 Serverless 模式，完全享受 Cloudflare 免费配额。

### 第一步：部署中继 Worker (`worker/`)

1. 安装并登录 Cloudflare CLI（如果尚未登录）：
   ```bash
   npx wrangler login
   ```
2. 进入 `worker` 目录并一键部署：
   ```bash
   cd worker
   npx wrangler deploy
   ```
3. 部署完成后，控制台将输出你的 Worker 域名，例如：
   `https://vpn2qr-relay.<你的子域名>.workers.dev`

---

### 第二步：部署前端页面至 Cloudflare Pages (`public/`)

#### 方式 A：通过 GitHub 自动构建部署（推荐）
1. 将当前项目推送到你的 GitHub 仓库。
2. 打开 [Cloudflare 控制台](https://dash.cloudflare.com/) -> **Workers & Pages** -> **Create application** -> **Pages**。
3. 连接 GitHub 仓库，选择本项目。
4. 构建设置：
   * **Framework preset**：`None`
   * **Build command**：留空
   * **Build output directory**：`public`
5. 点击 **Save and Deploy** 即可完成！

#### 方式 B：使用 Wrangler 命令行直接上传
在项目根目录下执行：
```bash
npx wrangler pages deploy public --project-name vpn2qr-web
```

---

## 🛠️ 自行修改与二次编译 WASM (可选)

如果你对 `wasm/main.go` 源码做了调整，需要重新编译 WASM：

```bash
# 确保本地已安装 Go 1.21+
bash wasm/build.sh
```
编译产物 `vpn2qr.wasm` 将自动输出到 `public/` 目录下。

---

## 📱 支持一键扫码导入的客户端

| 操作系统 | 推荐客户端 | 备注 |
| :--- | :--- | :--- |
| **iOS** | **Shadowrocket (小火箭)**、**OneXray** | 2023 年后的小火箭版本原生支持 Reality |
| **Android** | **v2rayNG**、**Clash Meta (Mihomo)** | 扫描页面二维码直接添加 |
| **Windows** | **Clash Verge Rev**、**v2rayN** | 支持扫码或复制链接直接导入 |
| **macOS** | **Clash Verge Rev**、**FlClash** | 支持一键导入与分流设置 |

---

## ⚖️ 免责声明与安全准则

1. 本工具仅供个人服务器管理与合规网络运维学习之用，请严格遵守所在国家及服务商的相关法律法规。
2. 节点的 UUID、私钥、二维码具有唯一使用权限，请勿截屏发送到公共社交网络或群聊中。
