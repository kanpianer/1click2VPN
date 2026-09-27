// Package main implements a zero-knowledge WebAssembly SSH client for 1click2VPN.
// Core VLESS installation and retrieval logic is derived from vpn2qr (https://github.com/www222fff/vpn2qr).
// Licensed under the MIT License.
package main

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"golang.org/x/crypto/ssh"
)

var vlessRegex = regexp.MustCompile(`(vless://[^\s\r\n]+)`)

func main() {
	c := make(chan struct{}, 0)

	// 注册全局 JavaScript 导出函数
	js.Global().Set("vpn2qrDeploy", js.FuncOf(vpn2qrDeploy))
	js.Global().Set("vpn2qrInteractiveSession", js.FuncOf(vpn2qrInteractiveSession))
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

// vpn2qrInteractiveSession 启动全功能伪终端 (PTY) 交互式 SSH 会话
// 参数由 JavaScript 传入:
// options: {
//   wsUrl: "wss://...",
//   user: "root",
//   password: "...",
//   privateKey: "...",
//   cols: 80,
//   rows: 24,
//   cmd: "sh -c ..." // 可选，启动后自动执行的脚本指令
// }
// callbacks: {
//   onStatus: func(status string),
//   onData: func(data string),
//   onClose: func(),
//   onError: func(errMsg string)
// }
// 返回操作控制器对象: {
//   send: func(data string),
//   resize: func(cols int, rows int),
//   close: func()
// }
func vpn2qrInteractiveSession(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		fmt.Println("[WASM] Insufficient arguments for vpn2qrInteractiveSession")
		return nil
	}

	opts := args[0]
	cb := args[1]

	onStatus := cb.Get("onStatus")
	onData := cb.Get("onData")
	onClose := cb.Get("onClose")
	onError := cb.Get("onError")

	reportStatus := func(msg string) {
		if !onStatus.IsUndefined() && !onStatus.IsNull() {
			onStatus.Invoke(msg)
		}
	}
	reportData := func(chunk string) {
		if !onData.IsUndefined() && !onData.IsNull() {
			onData.Invoke(chunk)
		}
	}
	reportClose := func() {
		if !onClose.IsUndefined() && !onClose.IsNull() {
			onClose.Invoke()
		}
	}
	reportError := func(err string) {
		if !onError.IsUndefined() && !onError.IsNull() {
			onError.Invoke(err)
		}
	}

	wsUrl := opts.Get("wsUrl").String()
	user := opts.Get("user").String()
	password := opts.Get("password").String()
	privateKey := opts.Get("privateKey").String()
	cmd := ""
	if !opts.Get("cmd").IsUndefined() && !opts.Get("cmd").IsNull() {
		cmd = opts.Get("cmd").String()
	}
	cols := 80
	if !opts.Get("cols").IsUndefined() && !opts.Get("cols").IsNull() && opts.Get("cols").Int() > 0 {
		cols = opts.Get("cols").Int()
	}
	rows := 24
	if !opts.Get("rows").IsUndefined() && !opts.Get("rows").IsNull() && opts.Get("rows").Int() > 0 {
		rows = opts.Get("rows").Int()
	}

	if user == "" {
		user = "root"
	}

	writeCh := make(chan []byte, 1024)
	doneCh := make(chan struct{})
	var closeOnce sync.Once

	var currentSession *ssh.Session
	var sessionMu sync.Mutex
	var netConn *wsConn
	var client *ssh.Client

	cleanup := func() {
		closeOnce.Do(func() {
			close(doneCh)
			sessionMu.Lock()
			if currentSession != nil {
				_ = currentSession.Close()
			}
			if client != nil {
				_ = client.Close()
			}
			if netConn != nil {
				_ = netConn.Close()
			}
			sessionMu.Unlock()
			reportClose()
		})
	}

	// 暴露给 JS 的控制器对象
	controller := js.Global().Get("Object").New()

	sendFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) == 0 {
			return nil
		}
		data := args[0].String()
		select {
		case <-doneCh:
			return nil
		default:
			select {
			case writeCh <- []byte(data):
			default:
			}
		}
		return nil
	})

	resizeFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return nil
		}
		newCols := args[0].Int()
		newRows := args[1].Int()
		sessionMu.Lock()
		if currentSession != nil {
			_ = currentSession.WindowChange(newRows, newCols)
		}
		sessionMu.Unlock()
		return nil
	})

	closeFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		cleanup()
		return nil
	})

	controller.Set("send", sendFn)
	controller.Set("resize", resizeFn)
	controller.Set("close", closeFn)

	go func() {
		reportStatus("正在通过安全隧道连接服务器...")

		ws := js.Global().Get("WebSocket").New(wsUrl)
		netConn = newWSConn(ws)

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
			reportStatus("WebSocket 隧道建立成功，正在进行 SSH 握手...")
		case errStr := <-wsErrCh:
			reportError(errStr)
			cleanup()
			return
		case <-time.After(15 * time.Second):
			reportError("连接中继超时，请检查网络或 VPS IP")
			cleanup()
			return
		case <-doneCh:
			cleanup()
			return
		}

		var authMethods []ssh.AuthMethod
		if privateKey != "" {
			signer, err := ssh.ParsePrivateKey([]byte(privateKey))
			if err != nil {
				reportError("私钥格式解析失败: " + err.Error())
				cleanup()
				return
			}
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		} else if password != "" {
			authMethods = append(authMethods, ssh.Password(password))
		} else {
			reportError("请提供 VPS 的 root 密码或 SSH 私钥")
			cleanup()
			return
		}

		sshConfig := &ssh.ClientConfig{
			User:            user,
			Auth:            authMethods,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         20 * time.Second,
		}

		reportStatus("正在验证 SSH 身份凭证...")
		sshConn, chans, reqs, err := ssh.NewClientConn(netConn, "vps:22", sshConfig)
		if err != nil {
			reportError("SSH 认证失败: " + err.Error())
			cleanup()
			return
		}

		sessionMu.Lock()
		client = ssh.NewClient(sshConn, chans, reqs)
		session, err := client.NewSession()
		if err != nil {
			sessionMu.Unlock()
			reportError("开启 SSH 会话失败: " + err.Error())
			cleanup()
			return
		}
		currentSession = session
		sessionMu.Unlock()

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
			reportError("分配伪终端 (PTY) 失败: " + err.Error())
			cleanup()
			return
		}

		stdinPipe, err := session.StdinPipe()
		if err != nil {
			reportError("绑定输入流失败: " + err.Error())
			cleanup()
			return
		}

		stdoutPipe, err := session.StdoutPipe()
		if err != nil {
			reportError("绑定输出流失败: " + err.Error())
			cleanup()
			return
		}

		stderrPipe, err := session.StderrPipe()
		if err != nil {
			reportError("绑定错误输出流失败: " + err.Error())
			cleanup()
			return
		}

		if err := session.Shell(); err != nil {
			reportError("启动 Shell 失败: " + err.Error())
			cleanup()
			return
		}

		reportStatus("connected")

		// 启动 goroutine 将 writeCh 数据写入 stdinPipe
		go func() {
			for {
				select {
				case <-doneCh:
					return
				case data, ok := <-writeCh:
					if !ok {
						return
					}
					if _, err := stdinPipe.Write(data); err != nil {
						return
					}
				}
			}
		}()

		// 如果指定了初始命令，稍等 shell 就绪后自动灌入执行
		if cmd != "" {
			go func() {
				time.Sleep(300 * time.Millisecond)
				select {
				case <-doneCh:
					return
				case writeCh <- []byte(cmd + "\n"):
				}
			}()
		}

		// 合并读取 stdout 和 stderr 实时输出
		multiReader := io.MultiReader(stdoutPipe, stderrPipe)
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := multiReader.Read(buf)
				if n > 0 {
					reportData(string(buf[:n]))
				}
				if err != nil {
					break
				}
			}
			cleanup()
		}()

		_ = session.Wait()
		cleanup()
	}()

	return controller
}
