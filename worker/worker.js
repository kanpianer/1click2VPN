/**
 * Cloudflare Worker: Zero-Knowledge WebSocket-to-TCP Blind Relay
 * 
 * 核心设计原理：
 * 1. 本 Worker 仅作为一个纯粹的"双向管道 (Blind Pipe)"，负责将浏览器端的 WebSocket 流量
 *    透明中继到目标 VPS 的 SSH 端口 (22)。
 * 2. 所有的 SSH 握手、密码认证、端到端加解密均在用户浏览器的 WebAssembly (WASM) 中完成。
 * 3. Worker 无解密密钥，绝无可能解密或窃取任何用户凭证或节点数据。
 */

import { connect } from 'cloudflare:sockets';

// [FIX #2] 端口白名单：默认只允许常见 SSH 端口，防止被用于任意端口扫描
// 常见 VPS SSH 端口：标准 22、部分面板/系统使用 80/443/2222/8022/8080/8443
// 可通过环境变量 ALLOWED_PORTS 自定义（逗号分隔）
const DEFAULT_ALLOWED_PORTS = new Set([22, 80, 443, 2222, 8022, 8080, 8443]);

// [FIX #4] 简单内存速率限制（基于当前 isolate 生命周期，非持久化）
// 注意：Cloudflare Worker isolate 是短生命周期的，重启后计数归零。
// 生产环境建议在 Cloudflare Dashboard → Security → WAF → Rate Limiting Rules 中
// 配置持久化速率限制，以 CF-Connecting-IP 为键，每分钟最多 10 次连接。
const rateLimitMap = new Map(); // IP -> { count, resetAt }
const RATE_LIMIT_MAX = 10;       // 每个 isolate 生命周期内最多允许 10 次连接
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 分钟窗口

function checkRateLimit(clientIp) {
  const now = Date.now();
  const entry = rateLimitMap.get(clientIp);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(clientIp, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) {
    return false;
  }
  entry.count++;
  return true;
}

// [FIX #3] 防范 SSRF：禁止访问内网/私有保留 IP 地址段（加强版）
function isPrivateOrReservedIP(rawIp) {
  if (!rawIp || typeof rawIp !== 'string') return true;
  const ip = rawIp.trim().replace(/^\[|\]$/g, '');

  // 拒绝纯数字整数 IP（如 2130706433）或十六进制 IP（如 0x7f000001），防止解析为环回地址
  if (/^\d+$/.test(ip) || /^0x[0-9a-fA-F]+$/.test(ip)) {
    return true;
  }

  // [FIX #3a] 处理 IPv6 mapped IPv4 地址（如 ::ffff:192.168.1.1）
  const ipv6MappedRegex = /^::ffff:([0-9a-fA-F.:]+)$/i;
  const mappedMatch = ip.match(ipv6MappedRegex);
  if (mappedMatch) {
    // 递归检查内嵌的 IPv4 地址
    return isPrivateOrReservedIP(mappedMatch[1]);
  }

  // 点分十进制 IPv4
  const parts = ip.split('.');
  if (parts.length === 4 && parts.every(p => /^\d+$/.test(p))) {
    // [FIX #3d] 拒绝段内前导零（防止八进制解释歧义，如 0177.0.0.1）或超出 3 位数
    if (parts.some(p => (p.length > 1 && p.startsWith('0')) || p.length > 3)) {
      return true;
    }

    const octets = parts.map(Number);
    // [FIX #3b] 每段必须在 0-255 之间，防止 "999.0.0.1" 等超范围绕过
    if (octets.some(o => o > 255)) return true;

    if (octets[0] === 10) return true; // 10.0.0.0/8
    if (octets[0] === 127) return true; // 127.0.0.0/8 (Loopback)
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true; // 172.16.0.0/12
    if (octets[0] === 192 && octets[1] === 168) return true; // 192.168.0.0/16
    if (octets[0] === 169 && octets[1] === 254) return true; // 169.254.0.0/16 (Link-local)
    if (octets[0] === 0 || octets[0] >= 224) return true; // 0.0.0.0, 组播与保留
    // [FIX #3c] 补充缺失的 RFC 保留段
    if (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) return true; // 100.64.0.0/10 (CGNAT 共享地址)
    if (octets[0] === 198 && (octets[1] === 18 || octets[1] === 19)) return true; // 198.18.0.0/15 (基准测试)
    if (octets[0] === 198 && octets[1] === 51 && octets[2] === 100) return true; // 198.51.100.0/24 (文档用)
    if (octets[0] === 203 && octets[1] === 0 && octets[2] === 113) return true;  // 203.0.113.0/24 (文档用)
  }

  const lower = ip.toLowerCase();
  if (
    lower === '::' ||
    lower === '::1' ||
    lower === 'localhost' ||
    lower.startsWith('fc') ||
    lower.startsWith('fd') ||
    lower.startsWith('fe80') ||
    lower.startsWith('fe8') ||
    lower.startsWith('fe9') ||
    lower.startsWith('fea') ||
    lower.startsWith('feb') ||
    lower === '0:0:0:0:0:0:0:0' ||
    lower === '0:0:0:0:0:0:0:1'
  ) {
    return true;
  }

  return false;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 获取客户端 IP（用于速率限制）
    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';

    // 1. 健康检查与跨域预检
    if (request.method === 'OPTIONS') {
      // [FIX #1] OPTIONS 预检只允许 GET（WebSocket 升级使用 GET 请求）
      return new Response(null, {
        status: 204,
        headers: {
          // 风险说明：对于 WebSocket 中继工具，此处 * 是设计需求，允许任意网站发起 WS 连接。
          // 如需限制来源，可通过 env.ALLOWED_ORIGIN 配置。
          'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
          'Access-Control-Allow-Methods': 'GET', // [FIX #1] 仅允许 GET，拒绝其他方法
          'Access-Control-Allow-Headers': 'Upgrade, Connection',
        },
      });
    }

    if (url.pathname === '/health' || url.pathname === '/') {
      // [FIX #1] /health 接口的 CORS Origin 可通过环境变量配置，默认 * 但附加风险注释
      // 在 Cloudflare Worker 环境变量中设置 ALLOWED_ORIGIN 可限制访问来源
      const allowedOrigin = env.ALLOWED_ORIGIN || '*';
      return new Response(
        JSON.stringify({
          status: 'ok',
          service: 'vpn2qr-zero-knowledge-relay',
          timestamp: new Date().toISOString(),
        }),
        {
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': allowedOrigin,
          },
        }
      );
    }

    // 2. WebSocket 升级处理：/ws?host=<vps_ip>&port=<vps_port>
    if (url.pathname === '/ws') {
      const upgradeHeader = request.headers.get('Upgrade');
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        return new Response('Expected WebSocket upgrade connection', { status: 426 });
      }

      const targetHost = url.searchParams.get('host');
      const targetPort = parseInt(url.searchParams.get('port') || '22', 10);

      if (!targetHost) {
        return new Response('Missing required parameter: host', { status: 400 });
      }

      if (isNaN(targetPort) || targetPort < 1 || targetPort > 65535) {
        return new Response('Invalid port parameter', { status: 400 });
      }

      const cleanHost = targetHost.trim().replace(/^\[|\]$/g, '');

      // [FIX #2] 端口白名单校验（支持环境变量覆盖）
      const allowedPorts = env.ALLOWED_PORTS
        ? new Set(env.ALLOWED_PORTS.split(',').map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p) && p > 0 && p <= 65535))
        : DEFAULT_ALLOWED_PORTS;

      if (!allowedPorts.has(targetPort)) {
        return new Response(
          `Forbidden: Port ${targetPort} is not allowed. Permitted SSH ports: ${[...allowedPorts].join(', ')}`,
          { status: 403 }
        );
      }

      // 安全防线：防止内部 SSRF 探测
      if (isPrivateOrReservedIP(cleanHost)) {
        return new Response('Forbidden: Access to private or reserved IP ranges is prohibited', {
          status: 403,
        });
      }

      // [FIX #4] 简单内存速率限制检查
      if (!checkRateLimit(clientIp)) {
        return new Response('Too Many Requests: rate limit exceeded. Please wait before reconnecting.', {
          status: 429,
          headers: { 'Retry-After': '60' },
        });
      }

      // 创建 WebSocketPair 用于代理
      const [clientWs, serverWs] = Object.values(new WebSocketPair());
      serverWs.accept();

      let tcpSocket = null;
      let tcpWriter = null;
      let tcpReader = null;

      try {
        // 使用 Cloudflare 官方 Sockets API 直连目标 VPS 的 SSH 端口
        tcpSocket = connect({
          hostname: cleanHost,
          port: targetPort,
        });

        tcpWriter = tcpSocket.writable.getWriter();
        tcpReader = tcpSocket.readable.getReader();

        // [FIX #5] 30 分钟连接超时保护，防止空闲连接长期占用 Worker 资源
        const CONNECTION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
        const timeoutId = setTimeout(() => {
          try {
            serverWs.close(1001, 'Connection timeout: 30-minute idle limit reached');
          } catch (_) {}
          try {
            tcpWriter.close();
          } catch (_) {}
        }, CONNECTION_TIMEOUT_MS);

        // 管道 A：WebSocket (浏览器) -> TCP (VPS)
        serverWs.addEventListener('message', async (event) => {
          try {
            let chunk;
            if (event.data instanceof ArrayBuffer) {
              chunk = new Uint8Array(event.data);
            } else if (typeof event.data === 'string') {
              chunk = new TextEncoder().encode(event.data);
            } else {
              chunk = new Uint8Array(await event.data.arrayBuffer());
            }
            await tcpWriter.write(chunk);
          } catch (err) {
            try {
              serverWs.close(1011, `TCP write error: ${err.message}`);
            } catch (_) {}
          }
        });

        serverWs.addEventListener('close', () => {
          clearTimeout(timeoutId);
          try {
            tcpWriter.close();
          } catch (_) {}
        });

        // 管道 B：TCP (VPS) -> WebSocket (浏览器)
        (async () => {
          try {
            while (true) {
              const { value, done } = await tcpReader.read();
              if (done) break;
              if (value && value.byteLength > 0) {
                serverWs.send(value);
              }
            }
          } catch (err) {
            // TCP 读取异常或连接正常关闭
          } finally {
            clearTimeout(timeoutId);
            try {
              serverWs.close(1000, 'TCP connection closed');
            } catch (_) {}
          }
        })();

        return new Response(null, {
          status: 101,
          webSocket: clientWs,
          headers: {
            // 风险说明：WebSocket 中继工具必须允许任意来源，这是设计需求。
            // 可通过 env.ALLOWED_ORIGIN 环境变量配置限制（建议生产环境设置）。
            'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
          },
        });
      } catch (err) {
        return new Response(`Failed to establish TCP connection: ${err.message}`, { status: 502 });
      }
    }

    return new Response('Not Found', { status: 404 });
  },
};
