#!/usr/bin/env python3
"""Run real xterm/app code in Chromium without SSH, npm dependencies or a server."""
import pathlib
import re
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
html = (ROOT / 'public/index.html').read_text()
# Keep local production scripts/styles, avoid network and WASM in this fixture.
html = re.sub(r'<script\b[^>]*src="https?://[^>]*>.*?</script>', '', html, flags=re.S)
html = re.sub(r'<link\b[^>]*href="https?://[^>]*>', '', html)
html = html.replace('<head>', '<head><base href="' + (ROOT / 'public').as_uri() + '/"><style>.hidden{display:none} #xterm-container{height:320px;width:350px}</style>')
test = r'''
<script>
initWasm = () => {};
window.addEventListener('DOMContentLoaded', async () => {
  const results = [];
  const check = (ok, name) => { results.push(`${ok ? 'PASS' : 'FAIL'}: ${name}`); };
  const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  try {
    const repos = {
      builtin: 'www222fff/vpn2qr', snell: 'jinqians/snell',
      'v2ray-agent': 'mack-a/v2ray-agent', shlii: '0xdabiaoge/singbox-lite',
      '3x-ui': 'mhsanaei/3x-ui'
    };
    const options = [...document.querySelectorAll('.script-option')];
    check(options.length === Object.keys(SCRIPT_DEFS).length && options.length === 5, 'every configured script has a menu entry');
    for (const option of options) {
      const key = option.dataset.script;
      const link = option.parentElement.querySelector('a');
      check(link && !option.contains(link) && link.href === 'https://github.com/' + repos[key] && link.target === '_blank' && link.relList.contains('noopener') && link.relList.contains('noreferrer'), key + ' has independent safe GitHub link');
      if (link) {
        link.addEventListener('click', e => e.preventDefault(), {once:true});
        const before = currentScriptKey;
        document.getElementById('script-dropdown').classList.remove('hidden');
        link.click();
        check(currentScriptKey === before && !document.getElementById('script-dropdown').classList.contains('hidden'), key + ' GitHub click does not change script or close menu');
      }
      option.click();
      check(currentScriptKey === key && option.classList.contains('bg-white/15') && document.getElementById('script-dropdown').classList.contains('hidden'), key + ' selection updates mode and highlight');
    }
    check(document.getElementById('active-script-badge').textContent.includes('3X-UI') && document.getElementById('btn-submit-text').textContent.includes('3X-UI'), '3X-UI selection updates badge and submit label');
    validateInputs = () => true;
    document.getElementById('vps-host').value = '192.0.2.1';
    document.getElementById('vps-password').value = 'fixture';
    let callbacks;
    let sessionOptions;
    window.vpn2qrInteractiveSession = (opts, cb) => { sessionOptions = opts; callbacks = cb; return { close() {}, send() {} }; };
    await executeInteractiveTerminal('3x-ui');
    check(SCRIPT_DEFS['3x-ui'].interactive && sessionOptions.cmd === 'bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)', '3X-UI passes exact requested command to interactive SSH session');
    await pause(150);
    activeXterm.reset();
    const sample = 'vless://fixture@example.test:443?security=reality#测试';
    await new Promise(resolve => activeXterm.write('\x1b[32m' + sample + '\x1b[0m\r\n<script>literal</' + 'script>\r\n', resolve));
    const screen = document.querySelector('.xterm-screen');
    const touch = new Touch({identifier: 1, target: screen, clientX: 30, clientY: 50});
    const emit = (type, touches) => screen.dispatchEvent(new TouchEvent(type, {bubbles:true, cancelable:true, touches, changedTouches:[touch]}));
    emit('touchstart', [touch]);
    await pause(650);
    emit('touchend', []);
    const dialog = document.getElementById('terminal-copy-dialog');
    check(dialog && dialog.open, 'long press opens native selectable terminal text');
    if (dialog && dialog.open) {
      const text = document.getElementById('terminal-copy-text');
      check(text.readOnly && text.value.includes(sample), 'ANSI-free text preserves wrapped URL and Unicode');
      text.select();
      check(getComputedStyle(text).userSelect === 'text' && text.selectionEnd - text.selectionStart === text.value.length, 'native text control permits selecting output');
      check(text.value.includes('<script>literal</' + 'script>'), 'terminal output remains literal text');
      const frozen = text.value;
      callbacks.onData('new output\r\n');
      await pause(50);
      check(text.value === frozen, 'incoming output does not disturb selection');
      closeTerminalCopy();
      check(!dialog.open && text.value === '', 'closing clears sensitive snapshot');
      emit('touchstart', [touch]);
      emit('touchmove', [new Touch({identifier:1,target:screen,clientX:30,clientY:100})]);
      await pause(650);
      emit('touchend', []);
      check(!dialog.open, 'scroll gesture does not open copy dialog');
      emit('touchstart', [touch]);
      emit('touchcancel', []);
      await pause(650);
      check(!dialog.open, 'cancelled gesture does not open copy dialog');
      emit('touchstart', [touch]);
      emit('touchend', []);
      await pause(650);
      check(!dialog.open, 'short tap does not open copy dialog');
      emit('touchstart', [touch]);
      emit('touchstart', [touch, new Touch({identifier:2,target:screen,clientX:60,clientY:50})]);
      await pause(650);
      emit('touchend', []);
      check(!dialog.open, 'multi-touch cancels long press');
      openTerminalCopy();
      check(dialog.open, 'explicit copy button path opens snapshot');
      closeInteractiveTerminal();
      check(!dialog.open && text.value === '', 'session disposal clears copy UI');
    }
  } catch (error) { results.push('FAIL: ' + error.stack); }
  const report = document.createElement('pre');
  report.id = 'test-results'; report.textContent = results.join('\n'); document.body.appendChild(report);
});
</script>
'''
html = html.replace('</body>', test + '</body>')
with tempfile.TemporaryDirectory(prefix='terminal-copy-') as directory:
    fixture = pathlib.Path(directory) / 'fixture.html'
    fixture.write_text(html)
    run = subprocess.run(['chromium', '--headless', '--user-data-dir=' + directory + '/profile', '--no-sandbox', '--disable-gpu', '--allow-file-access-from-files', '--no-proxy-server', '--virtual-time-budget=4000', '--dump-dom', fixture.as_uri()], capture_output=True, text=True, timeout=30)
    if run.returncode:
        print(run.stderr)
        raise SystemExit(run.returncode)
    match = re.search(r'<pre id="test-results">(.*?)</pre>', run.stdout, re.S)
    if not match:
        print('FAIL: browser did not finish fixture\n' + run.stderr[-2000:])
        raise SystemExit(1)
    import html as html_module
    report = html_module.unescape(match.group(1))
    print(report)
    raise SystemExit(1 if 'FAIL:' in report else 0)
