const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const { Server } = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "https://nekodrops-site.onrender.com",
    methods: ["GET", "POST"]
  }
});

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
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;

// "Banco de dados" em memória
let dropsDatabase = [];
let connectedClients = new Map();

// WebSocket para atualização em tempo real
io.on('connection', (socket) => {
  console.log('🔗 Cliente conectado via WebSocket:', socket.id);
  
  socket.on('authenticate', async (userData) => {
  try {
    let userInfo;
    if (userData.token) {
      userInfo = await getUserInfoFromToken(userData.token);
    } else {
      userInfo = userData;
    }
    connectedClients.set(socket.id, {
      userId: userInfo.userId,
      roles: userInfo.roles || [],
      isVip: userInfo.roles?.includes(VIP_ROLE_ID) || userInfo.roles?.includes(OWNER_ROLE_ID),
      isOwner: userInfo.roles?.includes(OWNER_ROLE_ID)
    });
    console.log(`✅ Cliente ${socket.id} autenticado como ${userInfo.userId}`);
  } catch (e) {
    console.error("❌ Falha ao autenticar WS:", e.message);
  }
});
  
  socket.on('disconnect', () => {
    console.log('🔌 Cliente desconectado:', socket.id);
    connectedClients.delete(socket.id);
  });
});

// Função para emitir drops apenas para usuários autorizados
function emitNewDropToAllowedUsers(dropData) {
  connectedClients.forEach((clientInfo, socketId) => {
    const canSee = dropData.isVip 
      ? clientInfo.isVip || clientInfo.isOwner
      : true;
    
    if (canSee) {
      io.to(socketId).emit('new-drop', dropData);
    }
  });
  console.log('📢 Novo drop emitido para clientes autorizados');
}

// Função auxiliar para obter informações do usuário
async function getUserInfoFromToken(token) {
  try {
    // 1. Obter informações básicas do usuário
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!userResponse.ok) {
      throw new Error('Token inválido');
    }

    const user = await userResponse.json();

    // 2. Obter informações do membro no servidor (URL CORRETA)
    const memberResponse = await fetch(
      `https://discord.com/api/guilds/${SERVER_ID}/members/${user.id}`,
      { 
        headers: { 
          Authorization: `Bot ${DISCORD_BOT_TOKEN}`
        } 
      }
    );

    if (!memberResponse.ok) {
      console.log('❌ Erro ao buscar membro:', memberResponse.status);
      throw new Error('Usuário não está no servidor');
    }

    const member = await memberResponse.json();
    
    return {
      userId: user.id,
      username: user.username,
      avatar: user.avatar,
      roles: member.roles || [],
      isVip: member.roles.includes(VIP_ROLE_ID) || member.roles.includes(OWNER_ROLE_ID),
      isOwner: member.roles.includes(OWNER_ROLE_ID)
    };
    
  } catch (error) {
    console.error('❌ Erro em getUserInfoFromToken:', error.message);
    throw new Error('Falha ao obter informações do usuário');
  }
}

// Rota para receber drops do bot
app.post('/api/drops', async (req, res) => {
  try {
    console.log('📦 Drop recebido:', req.body);
    
    const dropData = {
      ...req.body,
      id: Math.random().toString(36).substr(2, 9),
      receivedAt: new Date().toISOString(),
      isActive: true
    };
    
    // Salvar no banco de dados
    dropsDatabase.push(dropData);
    
    // Manter apenas os 1000 drops mais recentes
    if (dropsDatabase.length > 1000) {
      dropsDatabase = dropsDatabase.slice(-1000);
    }
    
    // Emitir para usuários autorizados
    emitNewDropToAllowedUsers(dropData);
    
    res.json({ 
      success: true, 
      message: 'Drop recebido com sucesso',
      id: dropData.id,
      totalDrops: dropsDatabase.length
    });
    
  } catch (error) {
    console.error('❌ Erro ao processar drop:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para listar drops
app.get('/api/drops', async (req, res) => {
  try {
    const { type, limit = 50, offset = 0 } = req.query;
    const authHeader = req.headers.authorization;
    
    let filteredDrops = dropsDatabase.filter(drop => drop.isActive !== false);
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.json({ success: true, drops: [] });
    }
    
    const token = authHeader.substring(7);
    
    try {
      const userInfo = await getUserInfoFromToken(token);
      const canSeeVip = userInfo.roles.includes(VIP_ROLE_ID) || userInfo.roles.includes(OWNER_ROLE_ID);
      
      filteredDrops = filteredDrops.filter(drop => {
        if (drop.isVip && !canSeeVip) return false;
        return true;
      });
      
    } catch (error) {
      console.log('⚠️ Token inválido, retornando drops públicos');
      filteredDrops = filteredDrops.filter(drop => !drop.isVip);
    }
    
    if (type === 'vip') {
      filteredDrops = filteredDrops.filter(drop => drop.isVip);
    } else if (type === 'normal') {
      filteredDrops = filteredDrops.filter(drop => !drop.isVip);
    }
    
    filteredDrops.sort((a, b) => new Date(b.receivedAt) - new Date(a.receivedAt));
    
    const paginatedDrops = filteredDrops.slice(offset, offset + parseInt(limit));
    
    res.json({
      success: true,
      drops: paginatedDrops,
      total: filteredDrops.length,
      hasMore: (offset + parseInt(limit)) < filteredDrops.length
    });
    
  } catch (error) {
    console.error('❌ Erro ao buscar drops:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para deletar um drop
app.delete('/api/drops/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Token não fornecido' });
    }
    
    const token = authHeader.substring(7);
    
    try {
      const userInfo = await getUserInfoFromToken(token);
      if (!userInfo.isOwner) {
        return res.status(403).json({ error: 'Apenas owners podem deletar drops' });
      }
    } catch (error) {
      return res.status(401).json({ error: 'Token inválido' });
    }
    
    const dropIndex = dropsDatabase.findIndex(drop => drop.id === id);
    
    if (dropIndex === -1) {
      return res.status(404).json({ error: 'Drop não encontrado' });
    }
    
    dropsDatabase[dropIndex].isActive = false;
    dropsDatabase[dropIndex].deletedAt = new Date().toISOString();
    
    io.emit('drop-deleted', id);
    
    res.json({ 
      success: true, 
      message: 'Drop removido com sucesso',
      deletedId: id
    });
    
  } catch (error) {
    console.error('❌ Erro ao deletar drop:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para estatísticas
app.get('/api/stats', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    let activeDrops = dropsDatabase.filter(drop => drop.isActive !== false);
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      try {
        const userInfo = await getUserInfoFromToken(token);
        const canSeeVip = userInfo.isVip || userInfo.isOwner;
        
        if (!canSeeVip) {
          activeDrops = activeDrops.filter(drop => !drop.isVip);
        }
      } catch (error) {
        activeDrops = activeDrops.filter(drop => !drop.isVip);
      }
    } else {
      activeDrops = activeDrops.filter(drop => !drop.isVip);
    }
    
    const vipDrops = activeDrops.filter(drop => drop.isVip);
    const normalDrops = activeDrops.filter(drop => !drop.isVip);
    
    res.json({
      success: true,
      stats: {
        totalDrops: activeDrops.length,
        vipDrops: vipDrops.length,
        normalDrops: normalDrops.length,
        lastUpdate: new Date().toISOString()
      }
    });
    
  } catch (error) {
    console.error('❌ Erro ao buscar estatísticas:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota de autenticação do Discord
app.get('/auth/discord', (req, res) => {
    const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify%20guilds%20guilds.members.read`;
    res.redirect(discordAuthUrl);
});

// Rota de callback do Discord
app.get('/auth/callback', async (req, res) => {
    console.log('✅ Callback recebido! Query parameters:', req.query);
    
    const { code, error, error_description } = req.query;
    
    if (error) {
        console.log('❌ Erro do Discord:', error, error_description);
        return res.redirect(`${FRONTEND_URL}/?error=${error}`);
    }
    
    if (!code) {
        console.log('❌ Erro: Code não recebido');
        return res.redirect(`${FRONTEND_URL}/?error=no_code`);
    }
    
    console.log('✅ Code recebido:', code);

    try {
        const data = new URLSearchParams();
        data.append('client_id', CLIENT_ID);
        data.append('client_secret', CLIENT_SECRET);
        data.append('grant_type', 'authorization_code');
        data.append('code', code);
        data.append('redirect_uri', REDIRECT_URI);
        data.append('scope', 'identify guilds guilds.members.read');

        console.log('📤 Enviando requisição para Discord...');
        
        const response = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            body: data,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });

        const responseText = await response.text();
        console.log('📥 Resposta do Discord:', response.status, responseText);
        
        let json;
        try {
            json = JSON.parse(responseText);
        } catch (e) {
            console.error('❌ Erro ao parsear resposta JSON:', e);
            return res.redirect(`${FRONTEND_URL}/?error=invalid_response`);
        }

        if (response.ok) {
            console.log('✅ Token obtido com sucesso!');
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

// Rota para obter informações do usuário
app.get('/api/user-info', async (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token não fornecido' });
    }

    const token = authHeader.substring(7);

    try {
        const userInfo = await getUserInfoFromToken(token);
        
        res.json({
            success: true,
            userId: userInfo.userId,
            username: userInfo.username,
            avatar: userInfo.avatar,
            roles: userInfo.roles,
            isVip: userInfo.isVip,
            isOwner: userInfo.isOwner,
            canAccess: true
        });

    } catch (error) {
        console.error('❌ Erro ao obter informações do usuário:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Rota para obter cargos do usuário
app.get('/api/user-roles', async (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token não fornecido' });
    }

    const token = authHeader.substring(7);

    try {
        const userInfo = await getUserInfoFromToken(token);
        
        res.json({
            success: true,
            roles: userInfo.roles
        });

    } catch (error) {
        console.error('❌ Erro ao obter cargos do usuário:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        websocketClients: connectedClients.size,
        totalDrops: dropsDatabase.length,
        environment: {
            hasClientId: !!CLIENT_ID,
            hasClientSecret: !!CLIENT_SECRET,
            hasServerId: !!SERVER_ID,
            hasBotToken: !!DISCORD_BOT_TOKEN
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
            userRoles: '/api/user-roles',
            drops: '/api/drops',
            stats: '/api/stats',
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

server.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`🌐 Frontend URL: ${FRONTEND_URL}`);
    console.log(`🔗 Redirect URI: ${REDIRECT_URI}`);
    console.log(`✅ Health check disponível em: http://localhost:${PORT}/health`);
    console.log(`📊 WebSocket pronto para conexões`);
});
