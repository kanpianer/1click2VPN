/**
 * vpn2qr Web - 前端核心业务逻辑
 * 纯客户端端到端加密与状态机调度
 */

let wasmLoaded = false;
let authMode = 'password'; // 'password' | 'key'
let currentVlessUrl = '';

// 初始化 Go WebAssembly 运行时
async function initWasm() {
  if (wasmLoaded) return;
  try {
    const go = new Go();
    const result = await WebAssembly.instantiateStreaming(
      fetch('vpn2qr.wasm'),
      go.importObject
    );
    go.run(result.instance);
    wasmLoaded = true;
    console.log('[Frontend] WebAssembly SSH 核心引擎就绪');
  } catch (err) {
    console.error('[Frontend] WASM 加载失败:', err);
    appendLog('⚠️ 警告: WebAssembly 加载较慢或失败，请确保使用现代浏览器并允许加载 .wasm 文件: ' + err.message);
  }
}

// 页面加载完成后预加载 WASM 并支持 #test-success 本地快速预览
window.addEventListener('DOMContentLoaded', () => {
  initWasm();
  if (window.location.hash === '#test-success') {
    setTimeout(() => {
      showSuccessResult('vless://12345678-1234-1234-1234-123456789abc@198.51.100.23:443?security=reality#VPS-Reality');
    }, 200);
  }
});

// 切换认证模式
function switchAuthMode(mode) {
  authMode = mode;
  const tabPwd = document.getElementById('tab-pwd');
  const tabKey = document.getElementById('tab-key');
  const pwdContainer = document.getElementById('auth-pwd-container');
  const keyContainer = document.getElementById('auth-key-container');

  if (mode === 'password') {
    tabPwd.className = 'font-semibold text-blue-400 border-b-2 border-blue-500 pb-0.5';
    tabKey.className = 'text-zinc-400 hover:text-zinc-200 pb-0.5';
    pwdContainer.classList.remove('hidden');
    keyContainer.classList.add('hidden');
  } else {
    tabKey.className = 'font-semibold text-blue-400 border-b-2 border-blue-500 pb-0.5';
    tabPwd.className = 'text-zinc-400 hover:text-zinc-200 pb-0.5';
    keyContainer.classList.remove('hidden');
    pwdContainer.classList.add('hidden');
  }
}

// 切换密码可见性
function togglePasswordVisibility() {
  const pwdInput = document.getElementById('vps-password');
  const eyeIcon = document.getElementById('eye-icon');
  if (pwdInput.type === 'password') {
    pwdInput.type = 'text';
    eyeIcon.innerText = '🙈';
  } else {
    pwdInput.type = 'password';
    eyeIcon.innerText = '👁️';
  }
}

// 展开/收起高级设置
function toggleAdvancedSettings() {
  const advContainer = document.getElementById('advanced-container');
  const advArrow = document.getElementById('adv-arrow');
  if (advContainer.classList.contains('hidden')) {
    advContainer.classList.remove('hidden');
    advArrow.style.transform = 'rotate(180deg)';
  } else {
    advContainer.classList.add('hidden');
    advArrow.style.transform = 'rotate(0deg)';
  }
}

// 终端日志追加
function appendLog(line) {
  const logs = document.getElementById('terminal-logs');
  const div = document.createElement('div');
  div.textContent = line;
  logs.appendChild(div);
  logs.scrollTop = logs.scrollHeight;
}

function clearLogs() {
  document.getElementById('terminal-logs').innerHTML = '';
}

// 更新界面步骤状态 (1 ~ 4)
function updateStep(stepNumber) {
  for (let i = 1; i <= 4; i++) {
    const stepEl = document.getElementById(`step-${i}`);
    if (!stepEl) continue;
    const icon = stepEl.querySelector('.step-icon');
    const text = stepEl.querySelector('span');

    if (i < stepNumber) {
      // 已完成
      icon.className = 'step-icon w-6 h-6 rounded-full bg-emerald-500 text-white flex items-center justify-center font-bold';
      icon.innerHTML = '✓';
      text.className = 'font-medium text-zinc-300';
    } else if (i === stepNumber) {
      // 进行中
      icon.className = 'step-icon w-6 h-6 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold animate-pulse';
      icon.innerHTML = i;
      text.className = 'font-bold text-blue-400';
    } else {
      // 未到达
      icon.className = 'step-icon w-6 h-6 rounded-full bg-zinc-800 text-zinc-400 flex items-center justify-center font-bold';
      icon.innerHTML = i;
      text.className = 'font-medium text-zinc-500';
    }
  }
}

// 处理表单提交与部署
async function handleDeploy() {
  const host = document.getElementById('vps-host').value.trim();
  const port = parseInt(document.getElementById('vps-port').value.trim() || '22', 10);
  const user = document.getElementById('vps-user').value.trim() || 'root';
  const password = document.getElementById('vps-password').value;
  const privateKey = document.getElementById('vps-key').value;

  const sni = document.getElementById('adv-sni').value.trim() || 'gateway.icloud.com';
  const nodePort = document.getElementById('adv-nodeport').value.trim() || '443';
  const nodeName = document.getElementById('adv-nodename').value.trim() || 'VPS-Reality';
  let workerDomain = document.getElementById('adv-worker').value.trim();

  // 基础校验
  if (!host) {
    alert('请输入 VPS IP 地址');
    return;
  }
  if (authMode === 'password' && !password) {
    alert('请输入 VPS root 密码');
    return;
  }
  if (authMode === 'key' && !privateKey) {
    alert('请粘贴 SSH 私钥');
    return;
  }

  // 确保 WASM 已完成加载
  if (!wasmLoaded || typeof window.vpn2qrDeploy !== 'function') {
    appendLog('==> 正在等待 WebAssembly 模块载入...');
    await initWasm();
    if (typeof window.vpn2qrDeploy !== 'function') {
      alert('WebAssembly 引擎未能成功载入，请检查网络或刷新页面重试');
      return;
    }
  }

  await executeDeploy(false);
}

// 核心执行逻辑 (支持 quickMode)
async function executeDeploy(quickMode = false) {
  const host = document.getElementById('vps-host').value.trim();
  const port = parseInt(document.getElementById('vps-port').value.trim() || '22', 10);
  const user = document.getElementById('vps-user').value.trim() || 'root';
  const password = document.getElementById('vps-password').value;
  const privateKey = document.getElementById('vps-key').value;

  const sni = document.getElementById('adv-sni').value.trim() || 'gateway.icloud.com';
  const nodePort = document.getElementById('adv-nodeport').value.trim() || '443';
  const nodeName = document.getElementById('adv-nodename').value.trim() || 'VPS-Reality';
  const DEFAULT_WORKER_RELAY = 'vpn2qr-relay.qstizi.workers.dev';
  let workerDomain = document.getElementById('adv-worker').value.trim() || DEFAULT_WORKER_RELAY;

  let wsUrl = '';
  if (workerDomain) {
    workerDomain = workerDomain.replace(/^https?:\/\//, '').replace(/^wss?:\/\//, '').replace(/\/+$/, '');
    wsUrl = `wss://${workerDomain}/ws?host=${encodeURIComponent(host)}&port=${port}`;
  } else {
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    wsUrl = `${wsProto}//${window.location.host}/ws?host=${encodeURIComponent(host)}&port=${port}`;
  }

  // 切换 UI 状态至进度展示
  document.getElementById('card-form').classList.add('hidden');
  document.getElementById('card-diagnostic').classList.add('hidden');
  document.getElementById('card-progress').classList.remove('hidden');

  // 点击搭建后隐藏上方的绝对隐私保障提示
  const privacyBanner = document.getElementById('banner-privacy');
  if (privacyBanner) {
    privacyBanner.classList.add('hidden');
  }

  clearLogs();
  updateStep(1);

  if (quickMode) {
    appendLog(`==> 启动快速恢复模式 (运行 reprint-link.sh)...`);
  } else {
    appendLog(`==> 准备连接中继并执行端侧握手...`);
  }

  // 调用 Go WASM 导出的核心方法
  window.vpn2qrDeploy(
    {
      wsUrl: wsUrl,
      user: user,
      password: authMode === 'password' ? password : '',
      privateKey: authMode === 'key' ? privateKey : '',
      nodePort: nodePort,
      sni: sni,
      nodeName: nodeName,
      quickMode: quickMode,
    },
    // onStatus 回调
    (statusText) => {
      document.getElementById('progress-title').innerText = statusText;
      if (statusText.includes('正在更新') || statusText.includes('安装基础依赖')) {
        updateStep(2);
      } else if (statusText.includes('Xray-core') || statusText.includes('密钥对')) {
        updateStep(3);
      } else if (statusText.includes('防火墙') || statusText.includes('部署成功')) {
        updateStep(4);
      }
    },
    // onLog 回调 (逐行推送)
    (logLine) => {
      appendLog(logLine);
    },
    // onSuccess 回调 (获取到 vless:// 链接)
    (vlessUrl) => {
      currentVlessUrl = vlessUrl;
      setTimeout(() => {
        showSuccessResult(vlessUrl);
      }, 500);
    },
    // onError 回调：触发智能诊断卡片
    (errMsg) => {
      showDiagnosticCard(errMsg);
    }
  );
}

// 智能诊断分析与卡片展示
function showDiagnosticCard(errMsg) {
  document.getElementById('card-progress').classList.add('hidden');
  document.getElementById('card-diagnostic').classList.remove('hidden');

  const diagPort = document.getElementById('diag-port');
  const diagAuth = document.getElementById('diag-auth');
  const diagRelay = document.getElementById('diag-relay');
  const diagReason = document.getElementById('diag-reason');
  const diagAdvice = document.getElementById('diag-advice');

  diagReason.innerText = errMsg;

  const errLower = (errMsg || '').toLowerCase();

  // 1. 密码或身份验证失败
  if (errLower.includes('认证失败') || errLower.includes('handshake failed') || errLower.includes('unable to authenticate') || errLower.includes('password')) {
    diagPort.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-500 mr-1.5"></span> 正常连通';
    diagPort.className = 'font-medium text-emerald-600 flex items-center';
    diagAuth.innerHTML = '<span class="w-2 h-2 rounded-full bg-rose-500 mr-1.5"></span> 密码/凭证被拒绝';
    diagAuth.className = 'font-medium text-rose-600 flex items-center';
    diagAdvice.innerHTML = `
      1. 请仔细检查 VPS 的 root 密码是否拼写错误（注意大小写与特殊符号）；<br>
      2. 部分云厂商（如 AWS EC2、甲骨文、部分 Debian 镜像）默认<strong>关闭了密码登录</strong>，仅允许使用私钥，请切换到【SSH 私钥】模式；<br>
      3. 若使用密码，可检查 VPS 的 <code>/etc/ssh/sshd_config</code> 中是否设置了 <code>PermitRootLogin yes</code> 与 <code>PasswordAuthentication yes</code>。
    `;
  }
  // 2. 端口不通或网络超时
  else if (errLower.includes('超时') || errLower.includes('timeout') || errLower.includes('refused') || errLower.includes('dial tcp')) {
    diagPort.innerHTML = '<span class="w-2 h-2 rounded-full bg-rose-500 mr-1.5"></span> 无法连通 22 端口';
    diagPort.className = 'font-medium text-rose-600 flex items-center';
    diagAuth.innerHTML = '<span class="w-2 h-2 rounded-full bg-slate-300 mr-1.5"></span> 未到达此步骤';
    diagAuth.className = 'font-medium text-slate-400 flex items-center';
    diagAdvice.innerHTML = `
      1. 请登录云厂商控制台，确认该 VPS 处于<strong>运行中 (Running)</strong> 状态；<br>
      2. 检查云厂商后台的<strong>安全组 (Security Group) / 防火墙</strong>，是否已放行入站 <code>TCP 22</code> 端口；<br>
      3. 确认该 VPS 的公网 IP 是否输入正确；若修改过默认 SSH 端口，请在上方填写对应端口。
    `;
  }
  // 3. 中继异常
  else if (errLower.includes('websocket') || errLower.includes('中继')) {
    diagRelay.innerHTML = '<span class="w-2 h-2 rounded-full bg-rose-500 mr-1.5"></span> 连接受阻';
    diagRelay.className = 'font-medium text-rose-600 flex items-center';
    diagAdvice.innerHTML = `
      1. Cloudflare 边缘节点握手受阻，请检查当前本地网络是否可正常连接；<br>
      2. 若自行部署了 Worker，请确认高级设置中的 Worker 域名配置无误且状态为 Active。
    `;
  }
  // 4. 其他中断（如 apt lock 或依赖下载慢）
  else {
    diagPort.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-500 mr-1.5"></span> 正常连通';
    diagPort.className = 'font-medium text-emerald-600 flex items-center';
    diagAuth.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-500 mr-1.5"></span> 认证通过';
    diagAuth.className = 'font-medium text-emerald-600 flex items-center';
    diagAdvice.innerHTML = `
      1. 脚本执行被中断。若 VPS 之前已安装过部分组件，可直接点击下方的<strong>【快速取回已有节点】</strong>（免重新下载，约 1 秒提取）；<br>
      2. 可能是海外软件源临时抖动或 VPS 后台正在执行自动更新，稍等片刻点击【一键重新连接】重试。
    `;
  }
}

// 一键重连 (支持选择是否快速取回)
async function retryDeploy(quickMode = false) {
  await executeDeploy(quickMode);
}

// 返回修改表单
function returnToForm() {
  document.getElementById('card-diagnostic').classList.add('hidden');
  document.getElementById('card-form').classList.remove('hidden');
  const privacyBanner = document.getElementById('banner-privacy');
  if (privacyBanner) {
    privacyBanner.classList.remove('hidden');
  }
}

// 页面中间洒花特效
function triggerCelebrationConfetti() {
  if (typeof confetti !== 'function') return;

  // 居中多波段爆发洒花
  const count = 180;
  const defaults = {
    origin: { x: 0.5, y: 0.5 },
    zIndex: 9999,
  };

  function fire(particleRatio, opts) {
    confetti(Object.assign({}, defaults, opts, {
      particleCount: Math.floor(count * particleRatio),
    }));
  }

  fire(0.25, {
    spread: 30,
    startVelocity: 55,
  });
  fire(0.2, {
    spread: 60,
  });
  fire(0.35, {
    spread: 100,
    decay: 0.91,
    scalar: 0.8,
  });
  fire(0.1, {
    spread: 120,
    startVelocity: 25,
    decay: 0.92,
    scalar: 1.2,
  });
  fire(0.1, {
    spread: 120,
    startVelocity: 45,
  });
}

// 播放胜利/庆祝音效 (纯端侧 Web Audio API 合成，零外部音频资源依赖)
function playCelebrationSound() {
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return;
    const ctx = new AudioContext();
    if (ctx.state === 'suspended') {
      ctx.resume();
    }

    // 悦耳清脆的胜利和弦音序 (C5 - E5 - G5 - C6 - E6)
    const notes = [
      { freq: 523.25, time: 0.00, dur: 0.20 }, // C5
      { freq: 659.25, time: 0.08, dur: 0.20 }, // E5
      { freq: 783.99, time: 0.16, dur: 0.24 }, // G5
      { freq: 1046.50, time: 0.26, dur: 0.60 }, // C6 (胜利主音)
      { freq: 1318.51, time: 0.28, dur: 0.65 }, // E6 (和声泛音)
    ];

    notes.forEach((n) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle'; // 柔和温润的八音盒/木琴音色
      osc.frequency.setValueAtTime(n.freq, ctx.currentTime + n.time);

      gain.gain.setValueAtTime(0.001, ctx.currentTime + n.time);
      gain.gain.exponentialRampToValueAtTime(0.35, ctx.currentTime + n.time + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + n.time + n.dur);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(ctx.currentTime + n.time);
      osc.stop(ctx.currentTime + n.time + n.dur);
    });
  } catch (err) {
    console.warn('[Audio] 播放庆祝音效失败:', err);
  }
}

// 成功状态展示与二维码本地绘制
function showSuccessResult(vlessUrl) {
  document.getElementById('card-form')?.classList.add('hidden');
  document.getElementById('card-diagnostic')?.classList.add('hidden');
  document.getElementById('card-progress')?.classList.add('hidden');
  document.getElementById('card-result')?.classList.remove('hidden');

  document.getElementById('vless-link').value = vlessUrl;

  const qrBox = document.getElementById('qrcode-box');
  qrBox.innerHTML = ''; // 清空可能存在的旧二维码

  // 浏览器本地直接通过 JavaScript Canvas/SVG 绘制高清晰度二维码，无任何第三方接口泄密风险
  new QRCode(qrBox, {
    text: vlessUrl,
    width: 220,
    height: 220,
    colorDark: '#0f172a',
    colorLight: '#ffffff',
    correctLevel: QRCode.CorrectLevel.M,
  });

  // 触发页面中间洒花特效与庆祝音效
  setTimeout(() => {
    triggerCelebrationConfetti();
    playCelebrationSound();
  }, 100);
}

// 一键复制 VLESS 链接
function copyVlessLink() {
  const linkInput = document.getElementById('vless-link');
  linkInput.select();
  navigator.clipboard.writeText(linkInput.value).then(() => {
    alert('已复制节点链接！您可直接在代理客户端（如小火箭、v2rayNG 等）中选择“从剪贴板导入”。');
  }).catch(() => {
    document.execCommand('copy');
    alert('链接已复制到剪贴板！');
  });
}

// 保存二维码图片至本地
function downloadQRCode() {
  const img = document.querySelector('#qrcode-box img') || document.querySelector('#qrcode-box canvas');
  if (!img) return;

  const link = document.createElement('a');
  link.download = 'reality-node-qrcode.png';
  if (img.tagName.toLowerCase() === 'img') {
    link.href = img.src;
  } else {
    link.href = img.toDataURL('image/png');
  }
  link.click();
}

// 重置并回到主页 (点击 LOGO 触发)
function resetApp() {
  document.getElementById('card-result')?.classList.add('hidden');
  document.getElementById('card-diagnostic')?.classList.add('hidden');
  document.getElementById('card-progress')?.classList.add('hidden');
  document.getElementById('card-form')?.classList.remove('hidden');

  // 恢复显示绝对隐私保障提示
  const privacyBanner = document.getElementById('banner-privacy');
  if (privacyBanner) {
    privacyBanner.classList.remove('hidden');
  }

  document.getElementById('vps-password').value = '';
  document.getElementById('vps-key').value = '';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
