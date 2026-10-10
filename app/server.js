const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const DB_FILE = '/data/db.json';

if (!fs.existsSync('/data')) {
  fs.mkdirSync('/data', { recursive: true });
}

function emptyDB() {
  return {
    users: [],
    articles: [],
    typing: [],
    speaking: [],
    nextIds: { user: 1, article: 1, typing: 1, speaking: 1 }
  };
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) return emptyDB();
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {
    return emptyDB();
  }
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function seed() {
  const db = loadDB();
  const hasAdmin = db.users.some(function(u) { return u.username === 'admin'; });
  if (!hasAdmin) {
    db.users.push({
      id: db.nextIds.user++,
      username: 'admin',
      passwordHash: bcrypt.hashSync('admin123', 10),
      role: 'admin',
      createdAt: new Date().toISOString()
    });
  }

  if (db.articles.length === 0) {
    const list = [
      {
        title: 'Hello World',
        difficulty: 1,
        category: 'basic',
        content: 'Hello world. This is a simple text for typing practice. Just type what you see.'
      },
      {
        title: 'Morning Routine',
        difficulty: 2,
        category: 'daily',
        content: 'Every morning I wake up at seven. I brush my teeth and wash my face. Then I make coffee and read the news.'
      },
      {
        title: 'The Power of Habit',
        difficulty: 3,
        category: 'essay',
        content: 'Habits shape our lives more than we realize. A small daily action, repeated over time, can lead to remarkable results.'
      },
      {
        title: 'Technology Today',
        difficulty: 4,
        category: 'tech',
        content: 'Artificial intelligence is transforming industries at an unprecedented pace. From healthcare to finance, machines now assist humans in many new ways.'
      },
      {
        title: 'On Perseverance',
        difficulty: 5,
        category: 'essay',
        content: 'Perseverance is not a long race. It is many short races one after another. The individual who succeeds refuses to give up when others do.'
      }
    ];
    list.forEach(function(a) {
      db.articles.push({
        id: db.nextIds.article++,
        title: a.title,
        content: a.content,
        category: a.category,
        difficulty: a.difficulty,
        createdBy: null,
        createdAt: new Date().toISOString()
      });
    });
  }

  saveDB(db);
  console.log('SEED OK: admin/admin123');
}

seed();

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

app.get('/api/health', function(req, res) {
  res.json({ ok: true, ts: Date.now() });
});

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.indexOf('Bearer ') === 0 ? h.slice(7) : null;
  if (!t) {
    res.status(401).json({ message: '未登录' });
    return;
  }
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ message: '登录已过期' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    res.status(403).json({ message: '需要管理员权限' });
    return;
  }
  next();
}

app.post('/api/auth/register', function(req, res) {
  const b = req.body || {};
  if (!b.username || b.username.length < 3) {
    res.status(400).json({ message: '用户名至少3位' });
    return;
  }
  if (!b.password || b.password.length < 6) {
    res.status(400).json({ message: '密码至少6位' });
    return;
  }
  const db = loadDB();
  const exists = db.users.some(function(u) { return u.username === b.username; });
  if (exists) {
    res.status(409).json({ message: '用户名已存在' });
    return;
  }
  const user = {
    id: db.nextIds.user++,
    username: b.username,
    passwordHash: bcrypt.hashSync(b.password, 10),
    role: 'user',
    createdAt: new Date().toISOString()
  };
  db.users.push(user);
  saveDB(db);
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token: token, user: { id: user.id, username: user.username, role: user.role } });
});

app.post('/api/auth/login', function(req, res) {
  const b = req.body || {};
  const db = loadDB();
  const user = db.users.find(function(u) { return u.username === b.username; });
  if (!user || !bcrypt.compareSync(b.password, user.passwordHash)) {
    res.status(401).json({ message: '用户名或密码错误' });
    return;
  }
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token: token, user: { id: user.id, username: user.username, role: user.role } });
});

app.get('/api/auth/me', auth, function(req, res) {
  const db = loadDB();
  const u = db.users.find(function(x) { return x.id === req.user.id; });
  if (!u) {
    res.status(404).json({ message: '用户不存在' });
    return;
  }
  res.json({ id: u.id, username: u.username, role: u.role, createdAt: u.createdAt });
});

app.get('/api/articles', auth, function(req, res) {
  const db = loadDB();
  const list = db.articles.slice().sort(function(a, b) {
    return a.difficulty - b.difficulty;
  });
  res.json(list);
});

app.get('/api/articles/:id', auth, function(req, res) {
  const db = loadDB();
  const id = Number(req.params.id);
  const a = db.articles.find(function(x) { return x.id === id; });
  if (!a) {
    res.status(404).json({ message: '文章不存在' });
    return;
  }
  res.json(a);
});

app.post('/api/typing/records', auth, function(req, res) {
  const b = req.body || {};
  if (!b.articleId) {
    res.status(400).json({ message: '缺少 articleId' });
    return;
  }
  const db = loadDB();
  const rec = {
    id: db.nextIds.typing++,
    userId: req.user.id,
    articleId: Number(b.articleId),
    wpm: Number(b.wpm) || 0,
    cpm: Number(b.cpm) || 0,
    accuracy: Number(b.accuracy) || 0,
    duration: Number(b.duration) || 0,
    errors: Number(b.errors) || 0,
    mode: b.mode || 'full',
    createdAt: new Date().toISOString()
  };
  db.typing.push(rec);
  saveDB(db);
  res.json(rec);
});

app.get('/api/typing/records', auth, function(req, res) {
  const db = loadDB();
  const mine = db.typing.filter(function(r) { return r.userId === req.user.id; });
  res.json(mine.slice(-50).reverse());
});

app.post('/api/speaking/records', auth, function(req, res) {
  const b = req.body || {};
  if (!b.sentence) {
    res.status(400).json({ message: '缺少 sentence' });
    return;
  }
  const db = loadDB();
  const rec = {
    id: db.nextIds.speaking++,
    userId: req.user.id,
    articleId: b.articleId ? Number(b.articleId) : null,
    sentence: b.sentence,
    recognizedText: b.recognizedText || '',
    score: Number(b.score) || 0,
    createdAt: new Date().toISOString()
  };
  db.speaking.push(rec);
  saveDB(db);
  res.json(rec);
});

app.get('/api/speaking/records', auth, function(req, res) {
  const db = loadDB();
  const mine = db.speaking.filter(function(r) { return r.userId === req.user.id; });
  res.json(mine.slice(-50).reverse());
});

app.get('/api/admin/stats/daily', auth, adminOnly, function(req, res) {
  const db = loadDB();
  const days = [];
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(now.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    const typingToday = db.typing.filter(function(r) { return r.createdAt.slice(0, 10) === key; });
    const speakingToday = db.speaking.filter(function(r) { return r.createdAt.slice(0, 10) === key; });
    const totalWpm = typingToday.reduce(function(s, r) { return s + r.wpm; }, 0);
    const totalScore = speakingToday.reduce(function(s, r) { return s + r.score; }, 0);
    const totalDuration = typingToday.reduce(function(s, r) { return s + (r.duration || 0); }, 0);
    days.push({
      date: key,
      typingCount: typingToday.length,
      speakingCount: speakingToday.length,
      duration: totalDuration,
      avgWpm: typingToday.length ? Number((totalWpm / typingToday.length).toFixed(1)) : 0,
      avgScore: speakingToday.length ? Number((totalScore / speakingToday.length).toFixed(1)) : 0
    });
  }
  res.json(days);
});

app.get('/api/admin/users', auth, adminOnly, function(req, res) {
  const db = loadDB();
  const list = db.users.map(function(u) {
    return {
      id: u.id,
      username: u.username,
      role: u.role,
      createdAt: u.createdAt,
      counts: {
        typing: db.typing.filter(function(r) { return r.userId === u.id; }).length,
        speaking: db.speaking.filter(function(r) { return r.userId === u.id; }).length
      }
    };
  });
  res.json(list);
});

app.post('/api/admin/articles', auth, adminOnly, function(req, res) {
  const b = req.body || {};
  if (!b.title || !b.content) {
    res.status(400).json({ message: '缺少参数' });
    return;
  }
  const db = loadDB();
  const a = {
    id: db.nextIds.article++,
    title: b.title,
    content: b.content,
    category: b.category || 'general',
    difficulty: Number(b.difficulty) || 1,
    createdBy: req.user.id,
    createdAt: new Date().toISOString()
  };
  db.articles.push(a);
  saveDB(db);
  res.json(a);
});

app.put('/api/admin/articles/:id', auth, adminOnly, function(req, res) {
  const id = Number(req.params.id);
  const b = req.body || {};
  const db = loadDB();
  const a = db.articles.find(function(x) { return x.id === id; });
  if (!a) {
    res.status(404).json({ message: '文章不存在' });
    return;
  }
  a.title = b.title;
  a.content = b.content;
  a.category = b.category || 'general';
  a.difficulty = Number(b.difficulty) || 1;
  saveDB(db);
  res.json(a);
});

app.delete('/api/admin/articles/:id', auth, adminOnly, function(req, res) {
  const id = Number(req.params.id);
  const db = loadDB();
  db.articles = db.articles.filter(function(x) { return x.id !== id; });
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/admin/export/typing.csv', auth, adminOnly, function(req, res) {
  const db = loadDB();
  const header = 'id,user,article,wpm,cpm,accuracy,duration,errors,mode,createdAt\n';
  const lines = db.typing.map(function(r) {
    const u = db.users.find(function(x) { return x.id === r.userId; });
    const a = db.articles.find(function(x) { return x.id === r.articleId; });
    const uname = u ? u.username : '';
    const atitle = a ? a.title : '';
    return [r.id, uname, '"' + atitle + '"', r.wpm, r.cpm, r.accuracy, r.duration, r.errors, r.mode, r.createdAt].join(',');
  });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename=typing_records.csv');
  res.send(header + lines.join('\n'));
});

const CSS = [
  '*{box-sizing:border-box;margin:0;padding:0}',
  'body{font-family:-apple-system,sans-serif;background:#f5f7fa;color:#333;min-height:100vh}',
  '.header{background:#1e293b;color:#fff;padding:14px 24px;display:flex;justify-content:space-between;align-items:center}',
  '.header .logo{font-weight:600;font-size:18px}',
  '.btn{background:#409eff;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:14px}',
  '.btn:hover{opacity:.85}',
  '.btn.ghost{background:transparent;border:1px solid #64748b;color:#cbd5e1}',
  '.btn.sm{padding:4px 10px;font-size:13px}',
  '.btn.red{background:#ef4444}',
  '.main{max-width:960px;margin:0 auto;padding:24px}',
  '.card{background:#fff;border-radius:10px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.06);margin-bottom:16px}',
  '.input{width:100%;padding:10px 14px;border:1px solid #e2e8f0;border-radius:6px;font-size:14px;outline:none}',
  '.input:focus{border-color:#409eff}',
  '.mode-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}',
  '.mode-card{cursor:pointer;text-align:center;padding:32px 20px}',
  '.mode-card:hover{box-shadow:0 8px 20px rgba(0,0,0,.1)}',
  '.mode-card h3{font-size:20px;margin-bottom:8px}',
  '.mode-card p{color:#94a3b8;font-size:14px}',
  '.article-row{display:flex;justify-content:space-between;align-items:center;padding:14px 0;border-bottom:1px solid #f1f5f9}',
  '.article-row:last-child{border-bottom:none}',
  '.text-display{background:#0f172a;color:#64748b;padding:24px;border-radius:8px;font-family:Consolas,monospace;font-size:20px;line-height:1.9;margin-bottom:16px}',
  '.pending{color:#64748b}',
  '.current{background:#334155;color:#fff}',
  '.correct{color:#4ade80}',
  '.wrong{color:#f87171}',
  '.stats{display:flex;gap:40px;justify-content:center;margin:24px 0;padding:16px;background:#fff;border-radius:8px;flex-wrap:wrap}',
  '.stat-item{text-align:center}',
  '.stat-item .val{font-size:32px;font-weight:600;color:#1e293b}',
  '.stat-item .lbl{font-size:13px;color:#94a3b8;margin-top:4px}',
  '.toolbar{display:flex;gap:12px;margin-bottom:16px;align-items:center;flex-wrap:wrap}',
  '.toolbar select{padding:8px 12px;border-radius:6px;border:1px solid #e2e8f0;font-size:14px;background:#fff}',
  '.tabs{display:flex;gap:4px;border-bottom:2px solid #f1f5f9;margin-bottom:20px}',
  '.tab{padding:10px 20px;cursor:pointer;font-size:14px;color:#64748b;border-bottom:2px solid transparent;margin-bottom:-2px}',
  '.tab.active{color:#409eff;border-bottom-color:#409eff;font-weight:500}',
  '.sentence{background:#fff;border-radius:8px;padding:16px 20px;margin-bottom:12px;border:2px solid transparent}',
  '.sentence.active{border-color:#409eff}',
  '.sentence-text{font-size:16px;line-height:1.7;color:#1e293b;margin-bottom:10px}',
  '.sentence-actions{display:flex;gap:8px}',
  '.result{background:#f8fafc;border-left:3px solid #409eff;padding:10px 14px;border-radius:4px;margin-top:10px;font-size:14px}',
  '.score-tag{display:inline-block;padding:2px 10px;border-radius:12px;font-size:13px;font-weight:500}',
  '.score-tag.good{background:#dcfce7;color:#16a34a}',
  '.score-tag.mid{background:#fef3c7;color:#d97706}',
  '.score-tag.bad{background:#fee2e2;color:#dc2626}',
  '.table{width:100%;border-collapse:collapse;font-size:14px}',
  '.table th{text-align:left;padding:12px 8px;color:#64748b;font-weight:500;border-bottom:1px solid #f1f5f9}',
  '.table td{padding:12px 8px;border-bottom:1px solid #f8fafc}',
  '.empty{text-align:center;padding:48px 0;color:#94a3b8}',
  '.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#1e293b,#0f172a)}',
  '.login-card{width:380px;background:#fff;border-radius:12px;padding:32px;box-shadow:0 20px 60px rgba(0,0,0,.3)}',
  '.login-card h2{text-align:center;margin-bottom:24px;font-size:22px}',
  '.login-tabs{display:flex;margin-bottom:24px;border-bottom:2px solid #f1f5f9}',
  '.login-tab{flex:1;text-align:center;padding:10px;cursor:pointer;color:#64748b;border-bottom:2px solid transparent;margin-bottom:-2px;font-size:15px}',
  '.login-tab.active{color:#409eff;border-bottom-color:#409eff;font-weight:500}',
  '.login-card .input{margin-bottom:14px}',
  '.login-card .btn{width:100%;padding:12px;font-size:15px}',
  '.login-tip{text-align:center;color:#94a3b8;font-size:12px;margin-top:14px}',
  '.bar-row{display:flex;align-items:center;gap:8px;font-size:13px;padding:4px 0}',
  '.bar-row .date{width:90px;color:#94a3b8}',
  '.bar{height:16px;background:#409eff;border-radius:3px;min-width:2px}',
  '.bar.green{background:#10b981}',
  '.dialog-mask{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;z-index:100}',
  '.dialog{background:#fff;border-radius:12px;padding:24px;width:600px;max-width:90vw;max-height:90vh;overflow-y:auto}',
  '.dialog h3{margin-bottom:16px}',
  '.dialog-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}',
  'textarea.input{resize:vertical;min-height:120px;font-family:inherit;line-height:1.6}'
].join('\n');

const TEMPLATE = [
  '<div v-if="s.page===\'login\'">',
  '<div class="login-wrap"><div class="login-card">',
  '<h2>English Typing Practice</h2>',
  '<div class="login-tabs">',
  '<div class="login-tab" :class="{active: s.loginTab===\'login\'}" @click="s.loginTab=\'login\'">登录</div>',
  '<div class="login-tab" :class="{active: s.loginTab===\'register\'}" @click="s.loginTab=\'register\'">注册</div>',
  '</div>',
  '<input class="input" v-model="s.loginUser" placeholder="用户名" @keyup.enter="doLogin">',
  '<input class="input" type="password" v-model="s.loginPass" placeholder="密码" @keyup.enter="doLogin">',
  '<button class="btn" @click="doLogin" :disabled="s.loading">{{ s.loading ? \'处理中...\' : (s.loginTab===\'login\' ? \'登录\' : \'注册\') }}</button>',
  '<p class="login-tip" v-if="s.loginTab===\'login\'">默认管理员: admin / admin123</p>',
  '<p class="login-tip" style="color:#ef4444" v-if="s.err">{{ s.err }}</p>',
  '</div></div></div>',
  '<div v-else>',
  '<div class="header">',
  '<div class="logo">English Typing Practice</div>',
  '<div><span style="margin-right:14px">{{ s.profile ? s.profile.username : \'\' }}</span>',
  '<button v-if="s.profile && s.profile.role===\'admin\'" class="btn ghost sm" @click="go(\'admin\')" style="margin-right:6px">管理后台</button>',
  '<button class="btn ghost sm" @click="logout">退出</button></div>',
  '</div>',
  '<div class="main" v-if="s.page===\'home\'">',
  '<h2 style="margin-bottom:20px">选择练习模式</h2>',
  '<div class="mode-grid">',
  '<div class="card mode-card" @click="go(\'typing\')"><h3>打字练习</h3><p>照着文章打字，实时统计 WPM 与准确率</p></div>',
  '<div class="card mode-card" @click="go(\'speaking\')"><h3>口语跟读</h3><p>朗读句子，浏览器识别并打分</p></div>',
  '</div>',
  '<h2 style="margin:32px 0 16px">文章列表</h2>',
  '<div class="card"><div v-for="a in s.articles" :key="a.id" class="article-row">',
  '<div><div style="font-weight:500;margin-bottom:4px">{{ a.title }}</div>',
  '<div style="font-size:13px;color:#94a3b8">{{ a.category }} · 难度 {{ a.difficulty }}/5</div></div>',
  '<div style="display:flex;gap:6px"><button class="btn sm" @click="startTyping(a.id)">打字</button>',
  '<button class="btn sm" @click="startSpeaking(a.id)">口语</button></div>',
  '</div></div></div>',
  '<div class="main" v-else-if="s.page===\'typing\'">',
  '<button class="btn ghost sm" @click="go(\'home\')" style="margin-bottom:16px">返回</button>',
  '<div class="toolbar"><select v-model="s.selectedArticleId" @change="loadArticle">',
  '<option v-for="a in s.articles" :key="a.id" :value="a.id">{{ a.title }} (难度 {{ a.difficulty }})</option>',
  '</select><button class="btn sm" @click="resetTyping">重置</button></div>',
  '<div v-if="s.selectedArticle">',
  '<div class="text-display"><span v-for="(ch,i) in s.selectedArticle.content" :key="i" :class="charClass(i)">{{ ch === \' \' ? \'_\' : ch }}</span></div>',
  '<textarea class="input" rows="3" v-model="s.typed" @input="onTyping" :disabled="s.typingDone" placeholder="在此开始输入..." style="font-family:monospace;font-size:16px"></textarea>',
  '<div class="stats">',
  '<div class="stat-item"><div class="val">{{ typingStats.wpm }}</div><div class="lbl">WPM</div></div>',
  '<div class="stat-item"><div class="val">{{ typingStats.cpm }}</div><div class="lbl">CPM</div></div>',
  '<div class="stat-item"><div class="val">{{ typingStats.accuracy }}</div><div class="lbl">准确率%</div></div>',
  '<div class="stat-item"><div class="val">{{ typingStats.errors }}</div><div class="lbl">错误</div></div>',
  '<div class="stat-item"><div class="val">{{ typingStats.duration }}</div><div class="lbl">用时(s)</div></div>',
  '</div>',
  '<div style="text-align:center;margin-top:16px" v-if="s.typingDone">',
  '<button class="btn" @click="resetTyping">再来一次</button>',
  '<span style="margin-left:12px;color:#16a34a;font-weight:500">完成！WPM {{ typingStats.wpm }}，准确率 {{ typingStats.accuracy }}%</span>',
  '</div>',
  '</div>',
  '<div v-else class="empty">请先选择一篇文章</div></div>',
  '<div class="main" v-else-if="s.page===\'speaking\'">',
  '<button class="btn ghost sm" @click="go(\'home\')" style="margin-bottom:16px">返回</button>',
  '<div class="toolbar"><select v-model="s.selectedArticleId" @change="loadArticleForSpeaking">',
  '<option v-for="a in s.articles" :key="a.id" :value="a.id">{{ a.title }} (难度 {{ a.difficulty }})</option>',
  '</select></div>',
  '<div v-if="!speechSupported" class="card" style="background:#fef3c7;color:#92400e">当前浏览器不支持语音识别，请使用 Chrome 或 Edge</div>',
  '<div v-if="s.selectedArticle">',
  '<div v-for="(sentence, idx) in sentences" :key="idx" class="sentence" :class="{active: s.currentSentenceIdx===idx}">',
  '<div class="sentence-text">{{ sentence }}</div>',
  '<div class="sentence-actions">',
  '<button class="btn ghost sm" @click="speakSentence(sentence)">示范朗读</button>',
  '<button class="btn sm" @click="recordSentence(idx)" :disabled="!speechSupported || s.recording">{{ s.recording && s.currentSentenceIdx===idx ? \'识别中...\' : \'开始朗读\' }}</button>',
  '</div>',
  '<div v-if="s.speakingResults[idx]" class="result">',
  '<div style="margin-bottom:6px">得分: <span class="score-tag" :class="scoreClass(s.speakingResults[idx].score)">{{ s.speakingResults[idx].score }} 分</span></div>',
  '<div>识别: {{ s.speakingResults[idx].recognized || \'（未识别）\' }}</div>',
  '</div>',
  '</div></div>',
  '<div v-else class="empty">请先选择一篇文章</div></div>',
  '<div class="main" v-else-if="s.page===\'admin\'">',
  '<button class="btn ghost sm" @click="go(\'home\')" style="margin-bottom:16px">返回</button>',
  '<div class="tabs">',
  '<div class="tab" :class="{active: s.adminTab===\'stats\'}" @click="s.adminTab=\'stats\';loadStats()">每日动态</div>',
  '<div class="tab" :class="{active: s.adminTab===\'users\'}" @click="s.adminTab=\'users\';loadUsers()">用户</div>',
  '<div class="tab" :class="{active: s.adminTab===\'articles\'}" @click="s.adminTab=\'articles\'">文章</div>',
  '</div>',
  '<div v-if="s.adminTab===\'stats\'">',
  '<button class="btn sm" @click="exportCsv" style="margin-bottom:12px">导出打字记录 CSV</button>',
  '<div class="card"><h4 style="margin-bottom:12px">近 7 天打字练习</h4>',
  '<div v-for="d in s.dailyStats" :key="d.date" class="bar-row"><span class="date">{{ d.date.slice(5) }}</span>',
  '<div class="bar" :style="{width: (d.typingCount * 30 + 2) + \'px\'}"></div>',
  '<span>{{ d.typingCount }} 次 · WPM {{ d.avgWpm }}</span></div></div>',
  '<div class="card"><h4 style="margin-bottom:12px">近 7 天口语练习</h4>',
  '<div v-for="d in s.dailyStats" :key="d.date" class="bar-row"><span class="date">{{ d.date.slice(5) }}</span>',
  '<div class="bar green" :style="{width: (d.speakingCount * 30 + 2) + \'px\'}"></div>',
  '<span>{{ d.speakingCount }} 次 · 平均 {{ d.avgScore }} 分</span></div></div>',
  '</div>',
  '<div v-if="s.adminTab===\'users\'">',
  '<table class="table"><thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>打字次数</th><th>口语次数</th></tr></thead>',
  '<tbody><tr v-for="u in s.adminUsers" :key="u.id"><td>{{ u.id }}</td><td>{{ u.username }}</td><td>{{ u.role }}</td><td>{{ u.counts.typing }}</td><td>{{ u.counts.speaking }}</td></tr></tbody></table>',
  '</div>',
  '<div v-if="s.adminTab===\'articles\'">',
  '<button class="btn" @click="openDialog()" style="margin-bottom:12px">新增文章</button>',
  '<table class="table"><thead><tr><th>ID</th><th>标题</th><th>分类</th><th>难度</th><th>操作</th></tr></thead>',
  '<tbody><tr v-for="a in s.articles" :key="a.id"><td>{{ a.id }}</td><td>{{ a.title }}</td><td>{{ a.category }}</td><td>{{ a.difficulty }}</td>',
  '<td><button class="btn sm" @click="openDialog(a)">编辑</button> <button class="btn sm red" @click="removeArticle(a)">删除</button></td></tr></tbody></table>',
  '</div></div>',
  '<div v-if="s.showDialog" class="dialog-mask" @click.self="s.showDialog=false">',
  '<div class="dialog">',
  '<h3>{{ s.form.id ? \'编辑文章\' : \'新增文章\' }}</h3>',
  '<input class="input" v-model="s.form.title" placeholder="标题" style="margin-bottom:12px">',
  '<input class="input" v-model="s.form.category" placeholder="分类" style="margin-bottom:12px">',
  '<input class="input" type="number" v-model.number="s.form.difficulty" min="1" max="5" placeholder="难度 1-5" style="margin-bottom:12px">',
  '<textarea class="input" v-model="s.form.content" rows="8" placeholder="英文内容"></textarea>',
  '<div class="dialog-actions"><button class="btn ghost" @click="s.showDialog=false" style="color:#333;border-color:#ccc">取消</button>',
  '<button class="btn" @click="saveArticle">保存</button></div>',
  '</div></div>',
  '</div>'
].join('');

const APP_JS = [
  "const { createApp, reactive, computed, onMounted } = Vue;",
  "const state = reactive({",
  "  token: localStorage.getItem('token') || '',",
  "  profile: null,",
  "  page: 'login',",
  "  articles: [],",
  "  selectedArticle: null,",
  "  selectedArticleId: null,",
  "  typed: '',",
  "  typingStart: null,",
  "  typingDone: false,",
  "  adminTab: 'stats',",
  "  adminUsers: [],",
  "  dailyStats: [],",
  "  showDialog: false,",
  "  form: { id: null, title: '', category: 'general', difficulty: 1, content: '' },",
  "  speakingResults: {},",
  "  recording: false,",
  "  currentSentenceIdx: -1,",
  "  loginUser: '',",
  "  loginPass: '',",
  "  loginTab: 'login',",
  "  loading: false,",
  "  err: ''",
  "});",
  "async function api(path, opts) {",
  "  opts = opts || {};",
  "  const headers = { 'Content-Type': 'application/json' };",
  "  if (state.token) headers.Authorization = 'Bearer ' + state.token;",
  "  const res = await fetch('/api' + path, {",
  "    method: opts.method || 'GET',",
  "    headers: headers,",
  "    body: opts.body ? JSON.stringify(opts.body) : undefined",
  "  });",
  "  if (res.status === 401) {",
  "    state.token = '';",
  "    localStorage.removeItem('token');",
  "    state.profile = null;",
  "    state.page = 'login';",
  "    throw new Error('请重新登录');",
  "  }",
  "  const data = await res.json().catch(function() { return {}; });",
  "  if (!res.ok) throw new Error(data.message || '请求失败');",
  "  return data;",
  "}",
  "async function doLogin() {",
  "  state.err = '';",
  "  if (!state.loginUser || !state.loginPass) { state.err = '请输入用户名和密码'; return; }",
  "  state.loading = true;",
  "  try {",
  "    const path = state.loginTab === 'login' ? '/auth/login' : '/auth/register';",
  "    const data = await api(path, { method: 'POST', body: { username: state.loginUser, password: state.loginPass } });",
  "    state.token = data.token;",
  "    localStorage.setItem('token', data.token);",
  "    state.profile = data.user;",
  "    await loadArticles();",
  "    state.page = 'home';",
  "  } catch (e) { state.err = e.message; }",
  "  state.loading = false;",
  "}",
  "function logout() {",
  "  state.token = '';",
  "  state.profile = null;",
  "  localStorage.removeItem('token');",
  "  state.page = 'login';",
  "}",
  "async function loadArticles() {",
  "  state.articles = await api('/articles');",
  "}",
  "function go(p) {",
  "  state.page = p;",
  "  if (p === 'admin') { loadStats(); loadUsers(); }",
  "}",
  "async function startTyping(id) {",
  "  state.page = 'typing';",
  "  state.selectedArticleId = id;",
  "  await loadArticle();",
  "}",
  "async function startSpeaking(id) {",
  "  state.page = 'speaking';",
  "  state.selectedArticleId = id;",
  "  await loadArticleForSpeaking();",
  "}",
  "async function loadArticle() {",
  "  state.selectedArticle = await api('/articles/' + state.selectedArticleId);",
  "  state.typed = '';",
  "  state.typingStart = null;",
  "  state.typingDone = false;",
  "}",
  "async function loadArticleForSpeaking() {",
  "  state.selectedArticle = await api('/articles/' + state.selectedArticleId);",
  "  state.speakingResults = {};",
  "  state.currentSentenceIdx = -1;",
  "}",
  "function resetTyping() {",
  "  state.typed = '';",
  "  state.typingStart = null;",
  "  state.typingDone = false;",
  "}",
  "const typingStats = computed(function() {",
  "  if (!state.selectedArticle) return { wpm: 0, cpm: 0, accuracy: 100, errors: 0, duration: 0 };",
  "  const content = state.selectedArticle.content;",
  "  const t = state.typed;",
  "  let errors = 0;",
  "  for (let i = 0; i < t.length; i++) { if (t[i] !== content[i]) errors++; }",
  "  const correct = t.length - errors;",
  "  const accuracy = t.length ? Number((correct / t.length * 100).toFixed(1)) : 100;",
  "  const elapsed = state.typingStart ? Math.max(0, (Date.now() - state.typingStart) / 1000) : 0;",
  "  const minutes = elapsed / 60;",
  "  const wpm = minutes > 0 ? Math.round(correct / 5 / minutes) : 0;",
  "  const cpm = minutes > 0 ? Math.round(correct / minutes) : 0;",
  "  return { wpm: wpm, cpm: cpm, accuracy: accuracy, errors: errors, duration: Math.round(elapsed) };",
  "});",
  "function charClass(i) {",
  "  const content = state.selectedArticle.content;",
  "  const t = state.typed;",
  "  if (i >= t.length) return i === t.length ? 'current' : 'pending';",
  "  return t[i] === content[i] ? 'correct' : 'wrong';",
  "}",
  "async function onTyping() {",
  "  if (!state.typingStart && state.typed.length > 0) state.typingStart = Date.now();",
  "  if (state.selectedArticle && state.typed.length >= state.selectedArticle.content.length && !state.typingDone) {",
  "    if (state.typed === state.selectedArticle.content) {",
  "      state.typingDone = true;",
  "      try {",
  "        await api('/typing/records', { method: 'POST', body: {",
  "          articleId: state.selectedArticle.id,",
  "          wpm: typingStats.value.wpm,",
  "          cpm: typingStats.value.cpm,",
  "          accuracy: typingStats.value.accuracy,",
  "          duration: typingStats.value.duration,",
  "          errors: typingStats.value.errors,",
  "          mode: 'full'",
  "        }});",
  "      } catch (e) {}",
  "    }",
  "  }",
  "}",
  "const sentences = computed(function() {",
  "  if (!state.selectedArticle) return [];",
  "  return state.selectedArticle.content.split(/(?<=[.!?])\\s+/).map(function(s) { return s.trim(); }).filter(Boolean);",
  "});",
  "const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;",
  "const speechSupported = !!SpeechRecognition;",
  "let recognizer = null;",
  "function speakSentence(text) {",
  "  if (!window.speechSynthesis) return;",
  "  const u = new SpeechSynthesisUtterance(text);",
  "  u.lang = 'en-US';",
  "  u.rate = 0.9;",
  "  speechSynthesis.cancel();",
  "  speechSynthesis.speak(u);",
  "}",
  "function similarity(a, b) {",
  "  a = a.toLowerCase().replace(/[^a-z0-9\\s]/g, '').trim();",
  "  b = b.toLowerCase().replace(/[^a-z0-9\\s]/g, '').trim();",
  "  if (!a) return 0;",
  "  const m = a.length, n = b.length;",
  "  const dp = [];",
  "  for (let i = 0; i <= m; i++) { dp[i] = []; for (let j = 0; j <= n; j++) dp[i][j] = 0; }",
  "  for (let i = 0; i <= m; i++) dp[i][0] = i;",
  "  for (let j = 0; j <= n; j++) dp[0][j] = j;",
  "  for (let i = 1; i <= m; i++) {",
  "    for (let j = 1; j <= n; j++) {",
  "      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j-1], dp[i-1][j], dp[i][j-1]);",
  "    }",
  "  }",
  "  return Math.max(0, 1 - dp[m][n] / Math.max(m, n));",
  "}",
  "function wordDiff(original, recognized) {",
  "  const orig = original.toLowerCase().replace(/[^a-z0-9\\s]/g, '').split(/\\s+/);",
  "  const rec = recognized.toLowerCase().replace(/[^a-z0-9\\s]/g, '').split(/\\s+/);",
  "  const set = {};",
  "  rec.forEach(function(w) { set[w] = true; });",
  "  return orig.map(function(w) { return { text: w, ok: !!set[w] }; });",
  "}",
  "function scoreClass(s) { return s >= 85 ? 'good' : s >= 60 ? 'mid' : 'bad'; }",
  "function recordSentence(idx) {",
  "  if (!speechSupported) return;",
  "  if (state.recording) { if (recognizer) recognizer.stop(); return; }",
  "  state.currentSentenceIdx = idx;",
  "  recognizer = new SpeechRecognition();",
  "  recognizer.lang = 'en-US';",
  "  recognizer.interimResults = false;",
  "  recognizer.maxAlternatives = 1;",
  "  state.recording = true;",
  "  recognizer.onresult = async function(e) {",
  "    const recognized = e.results[0][0].transcript.trim();",
  "    const original = sentences.value[idx];",
  "    const score = Math.round(similarity(original, recognized) * 100);",
  "    const words = wordDiff(original, recognized);",
  "    const nr = Object.assign({}, state.speakingResults);",
  "    nr[idx] = { recognized: recognized, score: score, words: words };",
  "    state.speakingResults = nr;",
  "    try {",
  "      await api('/speaking/records', { method: 'POST', body: {",
  "        articleId: state.selectedArticle.id,",
  "        sentence: original,",
  "        recognizedText: recognized,",
  "        score: score",
  "      }});",
  "    } catch (e) {}",
  "  };",
  "  recognizer.onerror = function() { state.recording = false; };",
  "  recognizer.onend = function() { state.recording = false; };",
  "  recognizer.start();",
  "}",
  "async function loadStats() { state.dailyStats = await api('/admin/stats/daily'); }",
  "async function loadUsers() { state.adminUsers = await api('/admin/users'); }",
  "function openDialog(a) {",
  "  if (a) {",
  "    state.form = { id: a.id, title: a.title, category: a.category, difficulty: a.difficulty, content: a.content };",
  "  } else {",
  "    state.form = { id: null, title: '', category: 'general', difficulty: 1, content: '' };",
  "  }",
  "  state.showDialog = true;",
  "}",
  "async function saveArticle() {",
  "  if (!state.form.title || !state.form.content) { alert('标题和内容不能为空'); return; }",
  "  if (state.form.id) {",
  "    await api('/admin/articles/' + state.form.id, { method: 'PUT', body: state.form });",
  "  } else {",
  "    await api('/admin/articles', { method: 'POST', body: state.form });",
  "  }",
  "  state.showDialog = false;",
  "  await loadArticles();",
  "}",
  "async function removeArticle(a) {",
  "  if (!confirm('确认删除《' + a.title + '》？')) return;",
  "  await api('/admin/articles/' + a.id, { method: 'DELETE' });",
  "  await loadArticles();",
  "}",
  "function exportCsv() {",
  "  const token = localStorage.getItem('token');",
  "  fetch('/api/admin/export/typing.csv', { headers: { Authorization: 'Bearer ' + token } })",
  "    .then(function(r) { return r.blob(); })",
  "    .then(function(blob) {",
  "      const url = URL.createObjectURL(blob);",
  "      const a = document.createElement('a');",
  "      a.href = url;",
  "      a.download = 'typing_records.csv';",
  "      a.click();",
  "      URL.revokeObjectURL(url);",
  "    });",
  "}",
  "const App = {",
  "  template: document.getElementById('app-template').innerHTML,",
  "  setup: function() {",
  "    onMounted(async function() {",
  "      if (state.token) {",
  "        try {",
  "          state.profile = await api('/auth/me');",
  "          await loadArticles();",
  "          state.page = 'home';",
  "        } catch (e) { logout(); }",
  "      }",
  "    });",
  "    return {",
  "      s: state,",
  "      typingStats: typingStats,",
  "      sentences: sentences,",
  "      speechSupported: speechSupported,",
  "      doLogin: doLogin,",
  "      logout: logout,",
  "      go: go,",
  "      loadArticle: loadArticle,",
  "      loadArticleForSpeaking: loadArticleForSpeaking,",
  "      resetTyping: resetTyping,",
  "      charClass: charClass,",
  "      onTyping: onTyping,",
  "      startTyping: startTyping,",
  "      startSpeaking: startSpeaking,",
  "      speakSentence: speakSentence,",
  "      recordSentence: recordSentence,",
  "      scoreClass: scoreClass,",
  "      loadStats: loadStats,",
  "      loadUsers: loadUsers,",
  "      openDialog: openDialog,",
  "      saveArticle: saveArticle,",
  "      removeArticle: removeArticle,",
  "      exportCsv: exportCsv",
  "    };",
  "  }",
  "};",
  "createApp(App).mount('#app');"
].join('\n');

app.get('/', function(req, res) {
  const html = '<!doctype html><html lang="zh-CN"><head>'
    + '<meta charset="UTF-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>English Typing Practice</title>'
    + '<script src="https://unpkg.com/vue@3/dist/vue.global.prod.js"></script>'
    + '<style>' + CSS + '</style>'
    + '</head><body>'
    + '<div id="app"></div>'
    + '<template id="app-template">' + TEMPLATE + '</template>'
    + '<script src="/app.js"></script>'
    + '</body></html>';
  res.type('html').send(html);
});

app.get('/app.js', function(req, res) {
  res.type('application/javascript').send(APP_JS);
});

app.listen(PORT, '0.0.0.0', function() {
  console.log('Server started on http://0.0.0.0:' + PORT);
});