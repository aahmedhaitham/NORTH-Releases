const { app, BrowserWindow, Menu, dialog, ipcMain, net, protocol, session } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { workspaceOrigin } = require('./workspace.cjs');
const { makeCloudProxy } = require('./cloud-proxy.cjs');
const { makeLocalWorkspace } = require('./local-workspace.cjs');
const { deviceHistory } = require('./device-history.cjs');

let activeWindow;
let setupWindow;
let startupComplete = false;
let cloudProxy;
const icon = path.join(__dirname, 'icons', 'north.ico');
const localAddress = 'north://app/';
const cloudPartition = 'persist:north-cloud';
const localPartition = 'persist:north-local';
const ui = app.isPackaged ? path.join(process.resourcesPath, 'north-ui') : path.join(__dirname, 'ui');
const scripts = app.isPackaged ? path.join(process.resourcesPath, 'north-tools') : path.join(__dirname, '..', 'tools');
const localWorkspace = makeLocalWorkspace(scripts, undefined, deviceHistory(path.join(app.getPath('userData'), 'device-history.json')));

protocol.registerSchemesAsPrivileged([{ scheme: 'north', privileges: {
  standard: true, secure: true, supportFetchAPI: true,
} }]);

async function handleLocalRequest(request, api) {
  const url = new URL(request.url);
  if (url.hostname !== 'app') return new Response(null, { status: 404 });
  if (url.pathname.startsWith('/api/')) {
    return api ? api(request) : Response.json({ detail: 'No workspace selected.' }, { status: 503 });
  }
  if (request.method !== 'GET') return new Response(null, { status: 405 });
  let filename;
  try {
    const requested = decodeURIComponent(['/', '/cloud'].includes(url.pathname) ? '/index.html' : url.pathname);
    filename = path.resolve(ui, '.' + requested);
  } catch {
    return new Response(null, { status: 400 });
  }
  if (!filename.startsWith(ui + path.sep)) return new Response(null, { status: 404 });
  const response = await net.fetch(pathToFileURL(filename).toString());
  if (!filename.endsWith('.html')) return response;
  const headers = new Headers(response.headers);
  headers.set('Content-Security-Policy',
    "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'self'");
  return new Response(response.body, { status: response.status, headers });
}

function settingsPath() {
  return path.join(app.getPath('userData'), 'workspace.json');
}

function show(window) {
  const previous = activeWindow;
  activeWindow = window;
  window.on('closed', () => {
    if (activeWindow === window) activeWindow = undefined;
  });
  if (previous && previous !== window) previous.close();
}

function configureWindow() {
  const window = new BrowserWindow({
    title: 'NORTH — Connect workspace', icon, width: 560, height: 410, minWidth: 400, minHeight: 350,
    backgroundColor: '#0c1018',
    webPreferences: {
      sandbox: true, contextIsolation: true, nodeIntegration: false,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });
  setupWindow = window;
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event) => event.preventDefault());
  window.on('closed', () => { if (setupWindow === window) setupWindow = undefined; });
  show(window);
  void window.loadFile(path.join(__dirname, 'setup.html')).catch(() => {
    dialog.showErrorBox('NORTH', 'The workspace setup screen could not open.');
  });
}

async function openWorkspace(nextOrigin, remember = false) {
  const connected = Boolean(nextOrigin);
  const window = new BrowserWindow({
    title: 'NORTH', icon, width: 1350, height: 850, minWidth: 375, minHeight: 500, show: false,
    backgroundColor: '#0c1018',
    webPreferences: {
      sandbox: true, contextIsolation: true, nodeIntegration: false,
      partition: connected ? cloudPartition : localPartition,
    },
  });
  const contents = window.webContents;
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  contents.session.setPermissionRequestHandler((_contents, _permission, done) => done(false));
  contents.session.setPermissionCheckHandler(() => false);
  const guard = (event) => {
    if (!event.url.startsWith(localAddress)) event.preventDefault();
  };
  contents.on('will-navigate', guard);
  contents.on('will-redirect', guard);
  const previousProxy = cloudProxy;
  if (connected) cloudProxy = makeCloudProxy(nextOrigin);
  try {
    await window.loadURL(localAddress + (connected ? 'cloud' : ''));
    if (remember) {
      await fs.writeFile(settingsPath(), JSON.stringify({ origin: nextOrigin }), 'utf8');
    }
  } catch (error) {
    cloudProxy = previousProxy;
    window.destroy();
    throw error;
  }
  show(window);
  window.show();
}

async function openSavedWorkspace() {
  try {
    const settings = await fs.readFile(settingsPath(), 'utf8').catch(() =>
      fs.readFile(path.join(ui, 'workspace-default.json'), 'utf8'));
    await openWorkspace(workspaceOrigin(JSON.parse(settings).origin));
  } catch {
    configureWindow();
  }
}

ipcMain.handle('north:connect', async (event, value) => {
  if (!setupWindow || event.sender !== setupWindow.webContents) return 'Workspace setup is unavailable.';
  try {
    const nextOrigin = workspaceOrigin(value);
    await openWorkspace(nextOrigin, true);
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : 'Could not open the workspace.';
  }
});

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (activeWindow?.isMinimized()) activeWindow.restore();
    activeWindow?.focus();
  });
  app.whenReady().then(async () => {
    session.fromPartition(localPartition).protocol.handle('north', (request) => handleLocalRequest(request, localWorkspace));
    session.fromPartition(cloudPartition).protocol.handle('north', (request) => handleLocalRequest(request, cloudProxy));
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      { label: 'Workspace', submenu: [
        { label: 'This computer', click: () => void openWorkspace().catch(showStartupError) },
        { label: 'Open cloud workspace', click: openSavedWorkspace },
        { label: 'Connect to a different workspace…', click: configureWindow },
        { label: 'Reload', accelerator: 'Ctrl+R', click: () => activeWindow?.reload() },
        { role: 'quit' },
      ] },
      { label: 'Edit', submenu: [{ role: 'undo' }, { role: 'redo' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
    ]));
    await openWorkspace().catch(showStartupError);
    startupComplete = true;
  });
  app.on('window-all-closed', () => { if (startupComplete) app.quit(); });
}

function showStartupError() {
  dialog.showErrorBox('NORTH', 'The local dashboard could not open.');
}
