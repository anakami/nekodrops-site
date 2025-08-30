const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || "https://nekodrops-site.onrender.com",
    credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Variáveis de ambiente
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || "https://nekodrops-site.onrender.com/auth/callback";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://nekodrops-site.onrender.com";
const SERVER_ID = process.env.SERVER_ID;
const MEMBER_ROLE_ID = process.env.MEMBER_ROLE_ID;
const VIP_ROLE_ID = process.env.VIP_ROLE_ID;
const OWNER_ROLE_ID = process.env.OWNER_ROLE_ID;

// Rota de autenticação do Discord - ESSA ESTÁ FALTANDO!
app.get('/auth/discord', (req, res) => {
    const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify%20guilds%20guilds.members.read`;
    res.redirect(discordAuthUrl);
});

// Rota de callback do Discord - ESSA ESTÁ FALTANDO!
app.get('/auth/callback', async (req, res) => {
    const code = req.query.code;
    
    if (!code) {
        return res.redirect(`${FRONTEND_URL}/?error=no_code`);
    }

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
            res.redirect(`${FRONTEND_URL}/?error=${json.error}`);
        }
    } catch (error) {
        console.error('Erro no callback:', error);
        res.redirect(`${FRONTEND_URL}/?error=server_error`);
    }
});

// Rota para trocar code por token (mantida para compatibilidade)
app.post('/api/exchange-token', async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status极速飞艇玩法
    (400).json({ error: 'Código não fornecido' });
  }

  try {
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
      res.json({ access_token: json.access_token });
    } else {
      res.status(400).json({ error: json.error_description });
    }
  } catch (error) {
    console.error('Erro ao trocar token:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
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
    const userResponse = await fetch('极速飞艇玩法
    'https://discord.com/api/users/@me', {
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

    if (!isMember) {
      return res.status(403).json({ error: 'Acesso negado. Você precisa ser membro do servidor.' });
    }

    res.json({
      userId: user.id,
      username: user.username,
      avatar: user.avatar,
      roles: roles,
      isVip: isVip,
      isMember: isMember,
      canAccess: isMember
    });

  } catch (error) {
    console.error('Erro ao obter informações do usuário:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Rota para servir o frontend (se necessário)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
