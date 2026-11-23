'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const MIN_CDP_PORT = 9301;
const MAX_CDP_PORT = 9399;
const DEFAULT_START_URL = 'https://photos.google.com/';
const DEFAULT_COMMAND_TIMEOUT_MS = 15000;
const DEFAULT_READY_TIMEOUT_MS = 25000;
const DEFAULT_POLL_INTERVAL_MS = 250;

const FORBIDDEN_DEFAULT_PROFILE_PATTERNS = [
  /\/appdata\/local\/google\/chrome(?:\s+(?:beta|dev|sxs|canary))?\/user data(?:\/|$)/i,
  /\/appdata\/local\/chromium\/user data(?:\/|$)/i,
  /\/appdata\/local\/microsoft\/edge(?:\s+(?:beta|dev|sxs))?\/user data(?:\/|$)/i,
  /\/library\/application support\/google\/chrome(?:\/|$)/i,
  /\/\.config\/google-chrome(?:\/|$)/i,
  /\/\.config\/chromium(?:\/|$)/i
];

const DEFAULT_CHROME_CANDIDATES = process.platform === 'win32'
  ? [
      path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(process.env.LOCALAPPDATA || '', 'Google', 'Chrome', 'Application', 'chrome.exe')
    ].filter(Boolean)
  : process.platform === 'darwin'
    ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome']
    : ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser'];

function sleep(ms) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (typeof t.unref === 'function') t.unref();
  });
}

function normalizePathForCheck(p) {
  return String(p || '')
    .replace(/\\/g, '/')
    .replace(/\/+$/, '')
    .toLowerCase();
}

/**
 * Strictly validates that cdpPort is an integer in the dedicated CloudVault range [9301..9399].
 * Avoids colliding with developer/user personal debugging ports such as 9222.
 */
function validateCdpPort(cdpPort) {
  if (typeof cdpPort === 'boolean' || cdpPort === null || cdpPort === undefined || cdpPort === '') {
    throw new RangeError(`Invalid cdpPort: expected integer in ${MIN_CDP_PORT}..${MAX_CDP_PORT}`);
  }
  const strVal = String(cdpPort).trim();
  if (!/^\d+$/.test(strVal)) {
    throw new RangeError(`Invalid cdpPort "${cdpPort}": expected integer in ${MIN_CDP_PORT}..${MAX_CDP_PORT}`);
  }
  const port = Number(strVal);
  if (!Number.isSafeInteger(port) || port < MIN_CDP_PORT || port > MAX_CDP_PORT) {
    throw new RangeError(`cdpPort ${port} is out of allowed isolated range (${MIN_CDP_PORT}..${MAX_CDP_PORT})`);
  }
  return port;
}

/**
 * Returns true if the given path points to (or inside) a user's default system browser User Data folder.
 */
function isForbiddenDefaultBrowserProfilePath(profileDir) {
  if (typeof profileDir !== 'string' || !profileDir.trim() || profileDir.includes('\0')) {
    return true;
  }
  const resolved = path.resolve(profileDir.trim());
  const normalized = normalizePathForCheck(resolved);

  // Reject filesystem roots (e.g. "c:" or "")
  if (!normalized || /^[a-z]:$/.test(normalized)) {
    return true;
  }

  // Check against dynamic LOCALAPPDATA paths on Windows
  if (process.env.LOCALAPPDATA) {
    const localNorm = normalizePathForCheck(path.resolve(process.env.LOCALAPPDATA));
    const dynamicForbidden = [
      `${localNorm}/google/chrome/user data`,
      `${localNorm}/google/chrome beta/user data`,
      `${localNorm}/google/chrome sxs/user data`,
      `${localNorm}/chromium/user data`,
      `${localNorm}/microsoft/edge/user data`
    ];
    for (const forbidden of dynamicForbidden) {
      if (normalized === forbidden || normalized.startsWith(`${forbidden}/`)) {
        return true;
      }
    }
  }

  for (const rx of FORBIDDEN_DEFAULT_PROFILE_PATTERNS) {
    if (rx.test(normalized)) {
      return true;
    }
  }

  return false;
}

/**
 * Validates that profileDir is a dedicated isolated directory and never the user's personal Chrome profile.
 */
function validateIsolatedProfileDir(profileDir) {
  if (typeof profileDir !== 'string' || !profileDir.trim()) {
    throw new Error('profileDir is required and must be a non-empty string');
  }
  if (profileDir.includes('\0')) {
    throw new Error('profileDir contains illegal null byte');
  }
  const resolved = path.resolve(profileDir.trim());
  if (isForbiddenDefaultBrowserProfilePath(resolved)) {
    throw new Error(
      `Refusing to use default/system browser profile directory "${resolved}". ` +
      'Each CloudVault job must use an isolated per-job --user-data-dir.'
    );
  }
  return resolved;
}

/**
 * Validates startUrl to permit only safe http(s) or about:blank targets.
 */
function validateStartUrl(startUrl = DEFAULT_START_URL) {
  const raw = String(startUrl || DEFAULT_START_URL).trim();
  if (raw === 'about:blank') return raw;
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`Invalid startUrl "${raw}"`);
  }
  const isHttps = parsed.protocol === 'https:';
  const isLocalHttp =
    parsed.protocol === 'http:' &&
    (parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost');
  if (!isHttps && !isLocalHttp) {
    throw new Error(`Disallowed startUrl protocol "${parsed.protocol}": only https://, http://127.0.0.1, or about:blank allowed`);
  }
  return parsed.toString();
}

/**
 * Builds deterministic, shell-free Chrome launch argument array for a dedicated job profile.
 * Using an isolated --user-data-dir with --remote-debugging-port allows direct CDP attachment
 * with 0 "Allow" consent popups (Golden Rule #11.2.3).
 */
function buildDedicatedChromeLaunchArgs({
  profileDir,
  cdpPort,
  startUrl = DEFAULT_START_URL,
  extraArgs = []
} = {}) {
  const resolvedProfileDir = validateIsolatedProfileDir(profileDir);
  const port = validateCdpPort(cdpPort);
  const validatedUrl = validateStartUrl(startUrl);

  const safeExtraArgs = [];
  if (Array.isArray(extraArgs)) {
    for (const arg of extraArgs) {
      const s = String(arg || '').trim();
      if (!s) continue;
      const lower = s.toLowerCase();
      if (
        lower.startsWith('--user-data-dir') ||
        lower.startsWith('--remote-debugging-port') ||
        lower.startsWith('--remote-debugging-pipe')
      ) {
        throw new Error(`extraArgs must not override isolated flag "${s}"`);
      }
      safeExtraArgs.push(s);
    }
  }

  return [
    `--user-data-dir=${resolvedProfileDir}`,
    `--remote-debugging-port=${port}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-default-apps',
    ...safeExtraArgs,
    validatedUrl
  ];
}

function resolveChromeExecutablePath(chromePath = '') {
  if (chromePath && String(chromePath).trim()) {
    return String(chromePath).trim();
  }
  if (process.env.CLOUDVAULT_CHROME_PATH && fs.existsSync(process.env.CLOUDVAULT_CHROME_PATH)) {
    return process.env.CLOUDVAULT_CHROME_PATH;
  }
  for (const candidate of DEFAULT_CHROME_CANDIDATES) {
    if (candidate && fs.existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error('Could not locate Google Chrome executable. Pass chromePath or set CLOUDVAULT_CHROME_PATH.');
}

async function pollCdpVersionEndpoint(cdpPort, options = {}) {
  const port = validateCdpPort(cdpPort);
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : DEFAULT_READY_TIMEOUT_MS;
  const pollIntervalMs = Number.isFinite(options.pollIntervalMs) ? options.pollIntervalMs : DEFAULT_POLL_INTERVAL_MS;
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const isAborted = typeof options.isAborted === 'function' ? options.isAborted : () => null;

  if (typeof fetchImpl !== 'function') {
    throw new Error('Native fetch is unavailable in this Node runtime');
  }

  const endpoint = `http://127.0.0.1:${port}/json/version`;
  const deadline = Date.now() + timeoutMs;
  let lastError = null;

  while (Date.now() < deadline) {
    const abortReason = isAborted();
    if (abortReason) {
      throw abortReason instanceof Error ? abortReason : new Error(String(abortReason));
    }

    try {
      const controller = new AbortController();
      const perReqTimer = setTimeout(() => controller.abort(), Math.min(3000, Math.max(500, deadline - Date.now())));
      if (typeof perReqTimer.unref === 'function') perReqTimer.unref();
      let res;
      try {
        res = await fetchImpl(endpoint, { signal: controller.signal });
      } finally {
        clearTimeout(perReqTimer);
      }

      if (res && res.ok) {
        const payload = await res.json();
        const wsUrl = payload && typeof payload.webSocketDebuggerUrl === 'string'
          ? payload.webSocketDebuggerUrl.trim()
          : '';
        if (wsUrl && /^wss?:\/\/(127\.0\.0\.1|localhost)(:\d+)?\//i.test(wsUrl)) {
          return {
            webSocketDebuggerUrl: wsUrl,
            browser: payload.Browser || '',
            protocolVersion: payload['Protocol-Version'] || '',
            raw: payload
          };
        }
      }
    } catch (err) {
      lastError = err;
    }

    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await sleep(Math.min(pollIntervalMs, remaining));
  }

  throw new Error(
    `Timed out waiting for Chrome CDP endpoint ${endpoint} after ${timeoutMs}ms` +
    (lastError ? ` (last error: ${lastError.message})` : '')
  );
}

/**
 * Spawns an isolated Chrome instance with zero shell execution and polls /json/version
 * until webSocketDebuggerUrl is ready.
 */
async function launchDedicatedChrome({
  chromePath,
  profileDir,
  cdpPort,
  startUrl = DEFAULT_START_URL,
  readyTimeoutMs = DEFAULT_READY_TIMEOUT_MS,
  pollIntervalMs = DEFAULT_POLL_INTERVAL_MS,
  extraArgs = [],
  spawnImpl = spawn,
  fetchImpl = globalThis.fetch,
  ensureDir = true
} = {}) {
  const args = buildDedicatedChromeLaunchArgs({ profileDir, cdpPort, startUrl, extraArgs });
  const resolvedProfileDir = validateIsolatedProfileDir(profileDir);
  const port = validateCdpPort(cdpPort);
  const executable = resolveChromeExecutablePath(chromePath);

  if (spawnImpl === spawn && !fs.existsSync(executable)) {
    throw new Error(`Chrome executable not found at "${executable}"`);
  }

  if (ensureDir) {
    fs.mkdirSync(resolvedProfileDir, { recursive: true });
  }

  const child = spawnImpl(executable, args, {
    detached: false,
    shell: false,
    stdio: 'ignore',
    windowsHide: false
  });

  let startupFailure = null;
  let exited = false;

  const onError = (err) => {
    startupFailure = new Error(`Failed to spawn dedicated Chrome: ${err.message}`);
  };
  const onExit = (code, signal) => {
    exited = true;
    if (!startupFailure) {
      startupFailure = new Error(`Dedicated Chrome exited prematurely before CDP was ready (code=${code}, signal=${signal})`);
    }
  };

  if (child && typeof child.once === 'function') {
    child.once('error', onError);
    child.once('exit', onExit);
  }

  let versionInfo;
  try {
    versionInfo = await pollCdpVersionEndpoint(port, {
      timeoutMs: readyTimeoutMs,
      pollIntervalMs,
      fetchImpl,
      isAborted: () => startupFailure
    });
  } catch (err) {
    try {
      if (child && !exited && typeof child.kill === 'function') {
        child.kill('SIGTERM');
      }
    } catch {}
    throw err;
  } finally {
    if (child && typeof child.off === 'function') {
      child.off('error', onError);
      child.off('exit', onExit);
    } else if (child && typeof child.removeListener === 'function') {
      child.removeListener('error', onError);
      child.removeListener('exit', onExit);
    }
  }

  let shutdownDone = false;
  async function shutdown(graceMs = 3000) {
    if (shutdownDone) return;
    shutdownDone = true;
    if (!child || exited || child.exitCode !== null || child.killed) {
      return;
    }

    await new Promise((resolve) => {
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        clearTimeout(killTimer);
        clearTimeout(hardTimer);
        resolve();
      };

      if (typeof child.once === 'function') {
        child.once('exit', done);
        child.once('close', done);
      }

      try {
        child.kill('SIGTERM');
      } catch {
        done();
        return;
      }

      const killTimer = setTimeout(() => {
        try {
          if (child.exitCode === null && !child.killed) {
            child.kill('SIGKILL');
          }
        } catch {}
      }, Math.max(200, graceMs));
      if (typeof killTimer.unref === 'function') killTimer.unref();

      const hardTimer = setTimeout(done, Math.max(500, graceMs + 1000));
      if (typeof hardTimer.unref === 'function') hardTimer.unref();
    });
  }

  return {
    child,
    wsUrl: versionInfo.webSocketDebuggerUrl,
    cdpPort: port,
    profileDir: resolvedProfileDir,
    args,
    browserVersion: versionInfo.browser,
    shutdown
  };
}

/**
 * Lightweight native WebSocket Chrome DevTools Protocol client.
 * - Enforces per-command timeout guard (default 15000ms).
 * - Never closes the browser or user tabs during detach().
 */
class SingleTargetCDP {
  constructor(wsUrl, options = {}) {
    if (typeof wsUrl !== 'string' || !/^wss?:\/\//i.test(wsUrl.trim())) {
      throw new Error(`Invalid CDP WebSocket URL "${wsUrl}"`);
    }
    this.wsUrl = wsUrl.trim();
    this.commandTimeoutMs = Number.isFinite(options.commandTimeoutMs)
      ? options.commandTimeoutMs
      : DEFAULT_COMMAND_TIMEOUT_MS;
    this.WebSocketImpl = options.WebSocketImpl || globalThis.WebSocket;
    this.ws = null;
    this.msgId = 1;
    this.pending = new Map();
    this.eventListeners = new Map();
    this.attachedSessions = new Set();
    this.connected = false;
  }

  connect(timeoutMs = this.commandTimeoutMs) {
    if (typeof this.WebSocketImpl !== 'function') {
      return Promise.reject(new Error('Native WebSocket is unavailable in this Node runtime'));
    }

    return new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        try { this.ws && this.ws.close(); } catch {}
        reject(new Error(`CDP WebSocket connection timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();

      const ws = new this.WebSocketImpl(this.wsUrl);
      this.ws = ws;

      const onOpen = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.connected = true;
        resolve();
      };

      const onError = (err) => {
        const msg = (err && (err.message || (err.error && err.error.message))) || 'WebSocket connection error';
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(new Error(`CDP WebSocket error: ${msg}`));
        }
        this._rejectAllPending(new Error(`CDP WebSocket error: ${msg}`));
      };

      const onClose = () => {
        this.connected = false;
        this._rejectAllPending(new Error('CDP WebSocket closed'));
      };

      const onMessage = (ev) => {
        let data;
        try {
          const raw = typeof ev.data === 'string' ? ev.data : String(ev.data || '');
          data = JSON.parse(raw);
        } catch {
          return;
        }
        if (data && data.id && this.pending.has(data.id)) {
          const entry = this.pending.get(data.id);
          this.pending.delete(data.id);
          clearTimeout(entry.timer);
          if (data.error) {
            entry.reject(new Error(data.error.message || JSON.stringify(data.error)));
          } else {
            entry.resolve(data.result || {});
          }
        } else if (data && data.method) {
          const handlers = this.eventListeners.get(data.method);
          if (handlers && handlers.size > 0) {
            for (const handler of handlers) {
              try {
                handler(data.params || {}, data.sessionId);
              } catch {}
            }
          }
        }
      };

      ws.addEventListener('open', onOpen);
      ws.addEventListener('error', onError);
      ws.addEventListener('close', onClose);
      ws.addEventListener('message', onMessage);
    });
  }

  _rejectAllPending(err) {
    for (const [id, entry] of this.pending.entries()) {
      clearTimeout(entry.timer);
      this.pending.delete(id);
      entry.reject(err);
    }
  }

  on(eventMethod, handler) {
    if (!this.eventListeners.has(eventMethod)) {
      this.eventListeners.set(eventMethod, new Set());
    }
    this.eventListeners.get(eventMethod).add(handler);
  }

  off(eventMethod, handler) {
    const set = this.eventListeners.get(eventMethod);
    if (set) {
      set.delete(handler);
    }
  }

  send(method, params = {}, sessionId = undefined, timeoutMs = this.commandTimeoutMs) {
    if (!this.ws || !this.connected) {
      return Promise.reject(new Error(`Cannot send CDP command "${method}": WebSocket is not connected`));
    }

    return new Promise((resolve, reject) => {
      const id = this.msgId++;
      const effectiveTimeout = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : this.commandTimeoutMs;

      const timer = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`CDP command "${method}" timed out after ${effectiveTimeout}ms`));
        }
      }, effectiveTimeout);
      if (typeof timer.unref === 'function') timer.unref();

      this.pending.set(id, { resolve, reject, timer, method });

      const payload = { id, method, params };
      if (sessionId) {
        payload.sessionId = sessionId;
      }

      try {
        this.ws.send(JSON.stringify(payload));
      } catch (err) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(err);
      }
    });
  }

  async attachToTarget(targetId) {
    const res = await this.send('Target.attachToTarget', { targetId, flatten: true });
    const sessionId = res && res.sessionId;
    if (!sessionId) {
      throw new Error(`Target.attachToTarget returned no sessionId for target "${targetId}"`);
    }
    this.attachedSessions.add(sessionId);
    return sessionId;
  }

  async evalJS(sessionId, expression, options = {}) {
    const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : this.commandTimeoutMs;
    const awaitPromise = options.awaitPromise !== false;
    const res = await this.send(
      'Runtime.evaluate',
      {
        expression,
        returnByValue: true,
        awaitPromise
      },
      sessionId,
      timeoutMs
    );
    if (res && res.exceptionDetails) {
      const desc =
        (res.exceptionDetails.exception && res.exceptionDetails.exception.description) ||
        res.exceptionDetails.text ||
        'Unknown JS evaluation exception';
      throw new Error(`CDP evalJS exception: ${desc}`);
    }
    return res && res.result ? res.result.value : undefined;
  }

  async trustedClick(sessionId, x, y, options = {}) {
    const rx = Math.round(Number(x));
    const ry = Math.round(Number(y));
    if (!Number.isFinite(rx) || !Number.isFinite(ry)) {
      throw new Error(`trustedClick requires finite numeric coordinates, got (${x}, ${y})`);
    }
    const delayMs = Number.isFinite(options.delayMs) ? options.delayMs : 45;
    await this.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: rx, y: ry }, sessionId);
    if (delayMs > 0) await sleep(delayMs);
    await this.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: rx, y: ry, button: 'left', clickCount: 1 }, sessionId);
    if (delayMs > 0) await sleep(delayMs);
    await this.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: rx, y: ry, button: 'left', clickCount: 1 }, sessionId);
  }

  async shiftClick(sessionId, x, y, options = {}) {
    const rx = Math.round(Number(x));
    const ry = Math.round(Number(y));
    if (!Number.isFinite(rx) || !Number.isFinite(ry)) {
      throw new Error(`shiftClick requires finite numeric coordinates, got (${x}, ${y})`);
    }
    const delayMs = Number.isFinite(options.delayMs) ? options.delayMs : 45;
    await this.send(
      'Input.dispatchKeyEvent',
      {
        type: 'keyDown',
        key: 'Shift',
        code: 'ShiftLeft',
        windowsVirtualKeyCode: 16,
        nativeVirtualKeyCode: 16,
        modifiers: 8
      },
      sessionId
    );
    try {
      await this.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: rx, y: ry, modifiers: 8 }, sessionId);
      if (delayMs > 0) await sleep(delayMs);
      await this.send(
        'Input.dispatchMouseEvent',
        { type: 'mousePressed', x: rx, y: ry, button: 'left', clickCount: 1, modifiers: 8 },
        sessionId
      );
      if (delayMs > 0) await sleep(delayMs);
      await this.send(
        'Input.dispatchMouseEvent',
        { type: 'mouseReleased', x: rx, y: ry, button: 'left', clickCount: 1, modifiers: 8 },
        sessionId
      );
      if (delayMs > 0) await sleep(delayMs);
    } finally {
      await this.send(
        'Input.dispatchKeyEvent',
        {
          type: 'keyUp',
          key: 'Shift',
          code: 'ShiftLeft',
          windowsVirtualKeyCode: 16,
          nativeVirtualKeyCode: 16,
          modifiers: 0
        },
        sessionId
      ).catch(() => {});
    }
  }

  /**
   * Safe detach: detaches CDP target session(s) and closes only the WebSocket client.
   * Never sends Browser.close or Target.closeTarget.
   */
  async detach(sessionId = null) {
    if (sessionId) {
      if (this.connected) {
        await this.send('Target.detachFromTarget', { sessionId }, undefined, 2500).catch(() => {});
      }
      this.attachedSessions.delete(sessionId);
      return;
    }

    const sessionsToDetach = Array.from(this.attachedSessions);
    for (const sid of sessionsToDetach) {
      if (this.connected) {
        await this.send('Target.detachFromTarget', { sessionId: sid }, undefined, 2500).catch(() => {});
      }
      this.attachedSessions.delete(sid);
    }

    this._rejectAllPending(new Error('CDP client detached'));
    this.connected = false;
    if (this.ws) {
      try {
        this.ws.close();
      } catch {}
      this.ws = null;
    }
  }
}

module.exports = {
  MIN_CDP_PORT,
  MAX_CDP_PORT,
  DEFAULT_START_URL,
  DEFAULT_COMMAND_TIMEOUT_MS,
  DEFAULT_READY_TIMEOUT_MS,
  validateCdpPort,
  isForbiddenDefaultBrowserProfilePath,
  validateIsolatedProfileDir,
  validateStartUrl,
  resolveChromeExecutablePath,
  buildDedicatedChromeLaunchArgs,
  pollCdpVersionEndpoint,
  launchDedicatedChrome,
  SingleTargetCDP
};
