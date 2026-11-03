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

// 内存速率限制（基于当前 isolate 生命周期，防范高频端口探测与暴力扫描）
// 正常的 SSH 客户端几分钟才发起 1 次连接；而恶意端口扫描需要 1 秒发起成百上千次。
const rateLimitMap = new Map(); // IP -> { count, resetAt }
const RATE_LIMIT_MAX = 15;       // 每个 IP 窗口内最多允许 15 次新建连接
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 分钟窗口

function checkRateLimit(clientIp) {
  const now = Date.now();
  // 防内存泄漏：当表项超过 2000 时，清理所有过期表项
  if (rateLimitMap.size > 2000) {
    for (const [ip, item] of rateLimitMap.entries()) {
      if (now > item.resetAt) {
        rateLimitMap.delete(ip);
      }
    }
    if (rateLimitMap.size > 5000) {
      rateLimitMap.clear(); // 极端防爆
    }
  }

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

// 高危滥用端口黑名单（禁止作为代理连接 SMTP 垃圾邮件、SMB 蠕虫攻击及已知危险端口）
const BLOCKED_PORTS = new Set([
  23,   // Telnet 明文
  25,   // SMTP
  135,  // RPC
  137,  // NetBIOS
  138,  // NetBIOS
  139,  // NetBIOS
  161,  // SNMP
  445,  // SMB
  465,  // SMTPS
  587,  // SMTP Submission
]);

// 规范点分十进制 IPv4 解析器
function parseIPv4(ipStr) {
  const parts = ipStr.split('.');
  if (parts.length !== 4) return null;
  const octets = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    if (part.length > 1 && part.startsWith('0')) return null; // 拒绝八进制歧义 (如 0177)
    const num = Number(part);
    if (num < 0 || num > 255) return null;
    octets.push(num);
  }
  return octets;
}

// 规范 IPv6 解析器（支持 :: 压缩展开与嵌入式 IPv4 映射）
function parseIPv6(ipStr) {
  let s = ipStr.toLowerCase();
  
  // 处理嵌入式 IPv4，如 ::ffff:192.168.1.1
  const lastColon = s.lastIndexOf(':');
  if (lastColon !== -1 && s.includes('.')) {
    const ipv4Part = s.slice(lastColon + 1);
    const parsedV4 = parseIPv4(ipv4Part);
    if (!parsedV4) return null;
    const h1 = ((parsedV4[0] << 8) | parsedV4[1]).toString(16);
    const h2 = ((parsedV4[2] << 8) | parsedV4[3]).toString(16);
    s = s.slice(0, lastColon + 1) + h1 + ':' + h2;
  }

  const doubleColonCount = (s.match(/::/g) || []).length;
  if (doubleColonCount > 1) return null;

  let parts;
  if (doubleColonCount === 1) {
    const [left, right] = s.split('::');
    const leftParts = left ? left.split(':') : [];
    const rightParts = right ? right.split(':') : [];
    const missing = 8 - (leftParts.length + rightParts.length);
    if (missing < 1) return null;
    parts = [...leftParts, ...Array(missing).fill('0'), ...rightParts];
  } else {
    parts = s.split(':');
    if (parts.length !== 8) return null;
  }

  if (parts.length !== 8) return null;
  const words = [];
  for (const p of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(p)) return null;
    words.push(parseInt(p, 16));
  }
  return words;
}

// [FIX #3] 防范 SSRF：禁止访问内网/私有保留 IP 地址段（深度防御版）
function isPrivateOrReservedIP(rawIp) {
  if (!rawIp || typeof rawIp !== 'string') return true;
  const clean = rawIp.trim().replace(/^\[|\]$/g, '');

  // 1. 尝试作为规范 IPv4 验证
  const v4 = parseIPv4(clean);
  if (v4) {
    const [a, b, c, d] = v4;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // 127.0.0.0/8 (Loopback)
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 (Link-local / 云元数据)
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24
    if (a === 192 && b === 0 && c === 2) return true; // 192.0.2.0/24 (TEST-NET-1)
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15
    if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24 (TEST-NET-2)
    if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24 (TEST-NET-3)
    if (a >= 224) return true; // 224.0.0.0/4 (组播与保留)
    return false;
  }

  // 2. 尝试作为规范 IPv6 验证
  const v6 = parseIPv6(clean);
  if (v6) {
    if (v6.every(w => w === 0)) return true; // :: (未指定)
    if (v6.slice(0, 7).every(w => w === 0) && v6[7] === 1) return true; // ::1 (Loopback)
    if ((v6[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 (Unique Local)
    if ((v6[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 (Link-Local)
    if ((v6[0] & 0xff00) === 0xff00) return true; // ff00::/8 (Multicast)
    if (v6[0] === 0x2001 && v6[1] === 0x0db8) return true; // 2001:db8::/32 (文档)
    if (v6[0] === 0x0100 && v6[1] === 0 && v6[2] === 0 && v6[3] === 0) return true; // 100::/64 (Discard)

    // IPv4-mapped (::ffff:x.x.x.x)
    if (v6.slice(0, 5).every(w => w === 0) && v6[5] === 0xffff) {
      const v4a = (v6[6] >> 8) & 0xff;
      const v4b = v6[6] & 0xff;
      const v4c = (v6[7] >> 8) & 0xff;
      const v4d = v6[7] & 0xff;
      return isPrivateOrReservedIP(`${v4a}.${v4b}.${v4c}.${v4d}`);
    }

    // NAT64 (64:ff9b::x.x.x.x)
    if (v6[0] === 0x0064 && v6[1] === 0xff9b && v6.slice(2, 6).every(w => w === 0)) {
      const v4a = (v6[6] >> 8) & 0xff;
      const v4b = v6[6] & 0xff;
      const v4c = (v6[7] >> 8) & 0xff;
      const v4d = v6[7] & 0xff;
      return isPrivateOrReservedIP(`${v4a}.${v4b}.${v4c}.${v4d}`);
    }

    // IPv4-compatible (::x.x.x.x)
    if (v6.slice(0, 6).every(w => w === 0) && (v6[6] !== 0 || v6[7] > 1)) {
      const v4a = (v6[6] >> 8) & 0xff;
      const v4b = v6[6] & 0xff;
      const v4c = (v6[7] >> 8) & 0xff;
      const v4d = v6[7] & 0xff;
      return isPrivateOrReservedIP(`${v4a}.${v4b}.${v4c}.${v4d}`);
    }

    return false;
  }

  // 3. 非合法 IP：如果是纯数字整数、十六进制、含特殊伪造字符，一律拦截
  if (/^\d+$/.test(clean) || /^0x[0-9a-f]+$/i.test(clean)) return true;
  if (clean.includes('/') || clean.includes(' ') || clean.includes('@')) return true;

  // 4. 拦截非规范点分 IPv4 变体（如 127.1, 127.0.1, 0177.0.0.1 等）
  if (/^[\d.]+$/.test(clean) && !v4) {
    return true;
  }

  // 5. 域名检查：拦截内网保留域名及常见 DNS 重新绑定服务
  const lower = clean.toLowerCase();
  if (
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower.endsWith('.local') ||
    lower.endsWith('.internal') ||
    lower.endsWith('.lan') ||
    lower.endsWith('.home') ||
    lower.endsWith('.corp') ||
    lower.endsWith('.arpa') ||
    lower.endsWith('.test') ||
    lower.endsWith('.invalid') ||
    lower.endsWith('.example') ||
    lower.endsWith('.onion') ||
    lower.includes('nip.io') ||
    lower.includes('sslip.io') ||
    lower.includes('xip.io') ||
    lower.includes('vcap.me') ||
    lower.includes('traefik.me')
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

      // [FIX CSWSH] 校验 Origin 标头，防范恶意跨站 WebSocket 劫持
      const origin = request.headers.get('Origin');
      if (env.ALLOWED_ORIGIN && env.ALLOWED_ORIGIN !== '*') {
        const allowedOrigins = env.ALLOWED_ORIGIN.split(',').map(s => s.trim().toLowerCase());
        const originLower = (origin || '').toLowerCase();
        if (!origin || !allowedOrigins.includes(originLower)) {
          return new Response('Forbidden: Cross-origin WebSocket request rejected', { status: 403 });
        }
      }

      const targetHost = url.searchParams.get('host');
      const targetPort = parseInt(url.searchParams.get('port') || '22', 10);

      if (!targetHost) {
        return new Response('Missing required parameter: host', { status: 400 });
      }

      if (isNaN(targetPort) || targetPort < 1 || targetPort > 65535) {
        return new Response('Invalid port parameter', { status: 400 });
      }

      // [FIX PORT ABUSE] 禁止中继到高危滥用端口（SMTP 邮件、SMB 蠕虫攻击等）
      if (BLOCKED_PORTS.has(targetPort)) {
        return new Response(`Forbidden: Port ${targetPort} is blocked for security and anti-abuse protection`, {
          status: 403,
        });
      }

      const cleanHost = targetHost.trim().replace(/^\[|\]$/g, '');

      // 支持 1-65535 任意自定义 SSH 端口；若管理员通过环境变量配置了 ALLOWED_PORTS 则按白名单校验
      if (env.ALLOWED_PORTS) {
        const allowedPorts = new Set(
          env.ALLOWED_PORTS.split(',')
            .map(p => parseInt(p.trim(), 10))
            .filter(p => !isNaN(p) && p > 0 && p <= 65535)
        );
        if (!allowedPorts.has(targetPort)) {
          return new Response(
            `Forbidden: Port ${targetPort} is not in the configured ALLOWED_PORTS whitelist`,
            { status: 403 }
          );
        }
      }

      // 安全防线：防止内部 SSRF 探测
      if (isPrivateOrReservedIP(cleanHost)) {
        return new Response('Forbidden: Access to private or reserved IP ranges is prohibited', {
          status: 403,
        });
      }

      // [FIX #4] 内存速率限制检查（含自动清理防泄漏）
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
      let isCleanedUp = false;

      try {
        // 使用 Cloudflare 官方 Sockets API 直连目标 VPS 的 SSH 端口
        tcpSocket = connect({
          hostname: cleanHost,
          port: targetPort,
        });

        tcpWriter = tcpSocket.writable.getWriter();
        tcpReader = tcpSocket.readable.getReader();

        // 统一清理释放函数，确保 WebSocket 与底层 TCP 读写器双向彻底关闭
        const cleanupRelay = () => {
          if (isCleanedUp) return;
          isCleanedUp = true;
          clearTimeout(timeoutId);
          try { tcpReader.cancel(); } catch (_) {}
          try { tcpWriter.close(); } catch (_) {}
          try { serverWs.close(); } catch (_) {}
        };

        // [FIX #5] 30 分钟连接超时保护，防止空闲连接长期占用 Worker 资源
        const CONNECTION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
        const timeoutId = setTimeout(() => {
          try {
            serverWs.close(1001, 'Connection timeout: 30-minute idle limit reached');
          } catch (_) {}
          cleanupRelay();
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
            cleanupRelay();
          }
        });

        serverWs.addEventListener('close', cleanupRelay);
        serverWs.addEventListener('error', cleanupRelay);

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
            cleanupRelay();
          }
        })();

        return new Response(null, {
          status: 101,
          webSocket: clientWs,
          headers: {
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
