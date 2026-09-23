/**
 * Cloudflare Worker: Zero-Knowledge WebSocket-to-TCP Blind Relay
 * 
 * 核心设计原理：
 * 1. 本 Worker 仅作为一个纯粹的“双向管道 (Blind Pipe)”，负责将浏览器端的 WebSocket 流量
 *    透明中继到目标 VPS 的 SSH 端口 (22)。
 * 2. 所有的 SSH 握手、密码认证、端到端加解密均在用户浏览器的 WebAssembly (WASM) 中完成。
 * 3. Worker 无解密密钥，绝无可能解密或窃取任何用户凭证或节点数据。
 */

import { connect } from 'cloudflare:sockets';

// 防范 SSRF：禁止访问内网/私有保留 IP 地址段
function isPrivateOrReservedIP(ip) {
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = ip.match(ipv4Regex);
  if (match) {
    const octets = match.slice(1).map(Number);
    if (octets[0] === 10) return true; // 10.0.0.0/8
    if (octets[0] === 127) return true; // 127.0.0.0/8 (Loopback)
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true; // 172.16.0.0/12
    if (octets[0] === 192 && octets[1] === 168) return true; // 192.168.0.0/16
    if (octets[0] === 169 && octets[1] === 254) return true; // 169.254.0.0/16 (Link-local)
    if (octets[0] === 0 || octets[0] >= 224) return true; // 0.0.0.0, 组播与保留
  }

  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === 'localhost' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80')) {
    return true;
  }

  return false;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. 健康检查与跨域预检
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': '*',
        },
      });
    }

    if (url.pathname === '/health' || url.pathname === '/') {
      return new Response(
        JSON.stringify({
          status: 'ok',
          service: 'vpn2qr-zero-knowledge-relay',
          timestamp: new Date().toISOString(),
        }),
        {
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
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

      // 安全防线：防止内部 SSRF 探测
      if (isPrivateOrReservedIP(targetHost)) {
        return new Response('Forbidden: Access to private or reserved IP ranges is prohibited', {
          status: 403,
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
          hostname: targetHost,
          port: targetPort,
        });

        tcpWriter = tcpSocket.writable.getWriter();
        tcpReader = tcpSocket.readable.getReader();

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
            try {
              serverWs.close(1000, 'TCP connection closed');
            } catch (_) {}
          }
        })();

        return new Response(null, {
          status: 101,
          webSocket: clientWs,
          headers: {
            'Access-Control-Allow-Origin': '*',
          },
        });
      } catch (err) {
        return new Response(`Failed to establish TCP connection: ${err.message}`, { status: 502 });
      }
    }

    return new Response('Not Found', { status: 404 });
  },
};
