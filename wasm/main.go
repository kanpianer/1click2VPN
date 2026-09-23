package main

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"syscall/js"
	"time"

	"golang.org/x/crypto/ssh"
)

var vlessRegex = regexp.MustCompile(`(vless://[^\s\r\n]+)`)

func main() {
	c := make(chan struct{}, 0)

	// 注册全局 JavaScript 导出函数
	js.Global().Set("vpn2qrDeploy", js.FuncOf(vpn2qrDeploy))
	fmt.Println("[WASM] vpn2qr zero-knowledge SSH engine initialized.")

	<-c
}

// vpn2qrDeploy 在浏览器本地 WASM 中执行端到端加密 SSH 操作
// 参数由 JavaScript 传入:
// options: {
//   wsUrl: "wss://...",
//   user: "root",
//   password: "...",
//   privateKey: "...",
//   port: 443,
//   sni: "gateway.icloud.com",
//   nodeName: "VPS-Reality"
// }
// onStatus(statusText)
// onLog(logLine)
// onSuccess(vlessUrl)
// onError(errMsg)
func vpn2qrDeploy(this js.Value, args []js.Value) any {
	if len(args) < 5 {
		fmt.Println("[WASM] Insufficient arguments for vpn2qrDeploy")
		return nil
	}

	opts := args[0]
	onStatus := args[1]
	onLog := args[2]
	onSuccess := args[3]
	onError := args[4]

	go func() {
		reportStatus := func(msg string) {
			onStatus.Invoke(msg)
		}
		reportLog := func(line string) {
			onLog.Invoke(line)
		}
		reportError := func(err string) {
			onError.Invoke(err)
		}

		wsUrl := opts.Get("wsUrl").String()
		user := opts.Get("user").String()
		password := opts.Get("password").String()
		privateKey := opts.Get("privateKey").String()
		nodePort := opts.Get("nodePort").String()
		sni := opts.Get("sni").String()
		nodeName := opts.Get("nodeName").String()

		if user == "" {
			user = "root"
		}
		if nodePort == "" {
			nodePort = "443"
		}
		if sni == "" {
			sni = "gateway.icloud.com"
		}
		if nodeName == "" {
			nodeName = "VPS-Reality"
		}

		reportStatus("正在通过安全隧道连接服务器...")
		reportLog("==> 初始化端侧 WebAssembly 加密环境")
		reportLog(fmt.Sprintf("==> 建立 WebSocket 盲中继管道: %s", wsUrl))

		// 1. 创建浏览器端的 WebSocket
		ws := js.Global().Get("WebSocket").New(wsUrl)
		netConn := newWSConn(ws)

		// 等待 WebSocket 握手完毕
		wsOpenCh := make(chan bool, 1)
		onOpen := js.FuncOf(func(this js.Value, args []js.Value) any {
			wsOpenCh <- true
			return nil
		})
		wsErrCh := make(chan string, 1)
		onWsError := js.FuncOf(func(this js.Value, args []js.Value) any {
			wsErrCh <- "WebSocket 连接失败"
			return nil
		})
		ws.Set("onopen", onOpen)
		ws.Set("onerror", onWsError)

		select {
		case <-wsOpenCh:
			reportLog("==> WebSocket 盲中继管道握手成功，开始 SSH 端到端加密握手...")
		case errStr := <-wsErrCh:
			reportError(errStr)
			netConn.Close()
			return
		case <-time.After(15 * time.Second):
			reportError("连接中继超时，请检查网络或 VPS IP")
			netConn.Close()
			return
		}

		// 2. 配置 SSH 身份认证（端到端，私钥/密码不离浏览器内存）
		var authMethods []ssh.AuthMethod
		if privateKey != "" {
			signer, err := ssh.ParsePrivateKey([]byte(privateKey))
			if err != nil {
				reportError("私钥格式解析失败: " + err.Error())
				netConn.Close()
				return
			}
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		} else if password != "" {
			authMethods = append(authMethods, ssh.Password(password))
		} else {
			reportError("请提供 VPS 的 root 密码或 SSH 私钥")
			netConn.Close()
			return
		}

		sshConfig := &ssh.ClientConfig{
			User:            user,
			Auth:            authMethods,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 浏览器端首次动态连接忽略主机密钥指纹
			Timeout:         20 * time.Second,
		}

		reportStatus("正在验证 SSH 身份凭证...")
		sshConn, chans, reqs, err := ssh.NewClientConn(netConn, "vps:22", sshConfig)
		if err != nil {
			reportError("SSH 认证失败: " + err.Error())
			netConn.Close()
			return
		}
		defer sshConn.Close()

		client := ssh.NewClient(sshConn, chans, reqs)
		defer client.Close()

		reportStatus("SSH 认证成功，准备执行一键搭建脚本...")
		reportLog("==> SSH 登录成功！开始执行部署任务...")

		// 3. 开启会话执行一键安装指令
		session, err := client.NewSession()
		if err != nil {
			reportError("开启 SSH 会话失败: " + err.Error())
			return
		}
		defer session.Close()

		stdout, err := session.StdoutPipe()
		if err != nil {
			reportError("绑定标准输出失败: " + err.Error())
			return
		}

		stderr, err := session.StderrPipe()
		if err != nil {
			reportError("绑定错误输出失败: " + err.Error())
			return
		}

		// 组装执行指令：若开启 quickMode 则直接运行 reprint-link.sh 快速提取已有节点（1~2秒）
		quickMode := false
		if opts.Get("quickMode").Truthy() {
			quickMode = true
		}

		var execCmd string
		if quickMode {
			reportStatus("正在尝试快速提取已有节点信息 (免重装模式)...")
			reportLog("==> 检测到快速恢复模式，直接执行 reprint-link.sh 提取密钥...")
			execCmd = fmt.Sprintf("export NODE_NAME=%s && curl -fsSL https://raw.githubusercontent.com/www222fff/vpn2qr/main/reprint-link.sh | bash", nodeName)
		} else {
			execCmd = fmt.Sprintf("export PORT=%s SNI=%s NODE_NAME=%s && curl -fsSL https://raw.githubusercontent.com/www222fff/vpn2qr/main/install.sh | bash",
				nodePort, sni, nodeName)
		}

		if err := session.Start(execCmd); err != nil {
			reportError("启动远程命令失败: " + err.Error())
			return
		}

		if !quickMode {
			reportStatus("正在安装 Xray 与配置 Reality (约需 40~80 秒)...")
		}

		// 合并读取 stdout 和 stderr 并实时回传
		multiReader := io.MultiReader(stdout, stderr)
		scanner := bufio.NewScanner(multiReader)
		vlessLink := ""

		for scanner.Scan() {
			line := scanner.Text()
			cleanLine := strings.TrimSpace(line)
			if cleanLine == "" {
				continue
			}

			// 实时推送日志
			reportLog(cleanLine)

			// 状态文本友好转换
			if strings.Contains(cleanLine, "安装依赖") {
				reportStatus("正在更新软件源并安装基础依赖...")
			} else if strings.Contains(cleanLine, "安装 / 更新 Xray") {
				reportStatus("正在下载并配置 Xray-core 内核...")
			} else if strings.Contains(cleanLine, "生成 UUID") {
				reportStatus("正在生成 X25519 密钥对与安全配置...")
			} else if strings.Contains(cleanLine, "配置防火墙") {
				reportStatus("正在配置防火墙并放行端口...")
			}

			// 抓取 vless 节点链接
			matches := vlessRegex.FindStringSubmatch(cleanLine)
			if len(matches) > 1 {
				vlessLink = matches[1]
			}
		}

		session.Wait()

		if vlessLink != "" {
			reportStatus("部署成功！")
			reportLog("==> 节点搭建完毕，正在生成二维码...")
			onSuccess.Invoke(vlessLink)
		} else {
			reportError("脚本执行完毕，但在输出中未检测到有效节点链接，请检查终端日志排查原因。")
		}
	}()

	return nil
}
