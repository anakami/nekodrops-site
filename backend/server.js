const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || "https://nekodrops-site.onrender.com",
    credentials: true
}));
app.use(express.json());

// Variáveis de ambiente
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || "https://nekodrops-backend.onrender.com/auth/callback";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://nekodrops-site.onrender.com";
const SERVER_ID = process.env.SERVER_ID;
const MEMBER_ROLE_ID = process.env.MEMBER_ROLE_ID;
const VIP_ROLE_ID = process.env.VIP_ROLE_ID;
const OWNER_ROLE_ID = process.env.OWNER_ROLE_ID;

// Rota de autenticação do Discord
app.get('/auth/discord', (req, res) => {
    const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify%20guilds%20guilds.members.read`;
    res.redirect(discordAuthUrl);
});

// Rota de callback do Discord
app.get('/auth/callback', async (req, res) => {
    console.log('✅ Callback recebido! Query parameters:', req.query);
    const code = req.query.code;
    
    if (!code) {
        console.log('❌ Erro: Code não recebido');
        return res.redirect(`${FRONTEND_URL}/?error=no_code`);
    }
    
    console.log('✅ Code recebido:', code);

    try {
        // Trocar code por access token
        const data = {
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: REDIRECT_URI,
            scope: 'identify guilds guilds.members.read'
        };

        const response = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            body: new URLSearchParams(data),
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });

        const json = await response.json();
        
        if (response.ok) {
            // Redirecionar com o token para o frontend
            res.redirect(`${FRONTEND_URL}/?token=${json.access_token}`);
        } else {
            console.log('❌ Erro ao obter token:', json);
            res.redirect(`${FRONTEND_URL}/?error=${json.error}`);
        }
    } catch (error) {
        console.error('❌ Erro no callback:', error);
        res.redirect(`${FRONTEND_URL}/?error=server_error`);
    }
});

// Rota para obter informações do usuário e cargos
app.get('/api/user-info', async (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token não fornecido' });
    }

    const token = authHeader.substring(7);

    try {
        // Obter informações do usuário
        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: {
                Authorization: `Bearer ${token}`,
            },
        });

        if (!userResponse.ok) {
            return res.status(401).json({ error: 'Token inválido' });
        }

        const user = await userResponse.json();

        // Verificar se o usuário está no servidor
        const memberResponse = await fetch(`https://discord.com/api/users/@me/guilds/${SERVER_ID}/member`, {
            headers: {
                Authorization: `Bearer ${token}`,
            },
        });

        if (!memberResponse.ok) {
            return res.status(403).json({ error: 'Usuário não está no servidor' });
        }

        const member = await memberResponse.json();
        const roles = member.roles || [];

        // Verificar se é membro (tem o cargo de membro ou superior)
        const isMember = roles.includes(MEMBER_ROLE_ID) || roles.includes(VIP_ROLE_ID) || roles.includes(OWNER_ROLE_ID);
        const isVip = roles.includes(VIP_ROLE_ID) || roles.includes(OWNER_ROLE_ID);
        const isOwner = roles.includes(OWNER_ROLE_ID);

        if (!isMember) {
            return res.status(403).json({ error: 'Acesso negado. Você precisa ser membro do servidor.' });
        }

        res.json({
            userId: user.id,
            username: user.username,
            avatar: user.avatar,
            discriminator: user.discriminator,
            roles: roles,
            isVip: isVip,
            isMember: isMember,
            isOwner: isOwner,
            canAccess: isMember
        });

    } catch (error) {
        console.error('❌ Erro ao obter informações do usuário:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        environment: {
            hasClientId: !!CLIENT_ID,
            hasClientSecret: !!CLIENT_SECRET,
            hasServerId: !!SERVER_ID
        }
    });
});

// Rota básica para teste
app.get('/', (req, res) => {
    res.json({ 
        message: 'NEKO DROPS Backend API', 
        status: 'online',
        timestamp: new Date().toISOString(),
        endpoints: {
            auth: '/auth/discord',
            callback: '/auth/callback',
            userInfo: '/api/user-info',
            health: '/health'
        }
    });
});

// Middleware de erro global
app.use((error, req, res, next) => {
    console.error('❌ Erro não tratado:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
});

// Rota para 404
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint não encontrado' });
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`🌐 Frontend URL: ${FRONTEND_URL}`);
    console.log(`🔗 Redirect URI: ${REDIRECT_URI}`);
    console.log(`✅ Health check disponível em: http://localhost:${PORT}/health`);
});
