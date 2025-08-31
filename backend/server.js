const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const { Server } = require('socket.io');
const http = require('http');
const path = require('path');

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

// "Banco de dados" em memória (substitua por MongoDB depois)
let dropsDatabase = [];
let connectedClients = new Map(); // Mapa para armazenar informações dos clientes

// WebSocket para atualização em tempo real
io.on('connection', (socket) => {
  console.log('🔗 Cliente conectado via WebSocket:', socket.id);
  
  // Evento para autenticar o cliente com suas permissões
  socket.on('authenticate', (userData) => {
    connectedClients.set(socket.id, {
      userId: userData.userId,
      roles: userData.roles || [],
      isVip: userData.roles?.includes(VIP_ROLE_ID) || userData.roles?.includes(OWNER_ROLE_ID),
      isOwner: userData.roles?.includes(OWNER_ROLE_ID)
    });
    console.log(`✅ Cliente ${socket.id} autenticado como ${userData.userId}`);
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
    
    // Salvar no "banco de dados"
    dropsDatabase.push(dropData);
    
    // Manter apenas os 1000 drops mais recentes
    if (dropsDatabase.length > 1000) {
      dropsDatabase = dropsDatabase.slice(-1000);
    }
    
    // Emitir apenas para usuários autorizados via WebSocket
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

// Rota para listar todos os drops (com filtro por permissões)
app.get('/api/drops', async (req, res) => {
  try {
    const { type, limit = 50, offset = 0 } = req.query;
    const authHeader = req.headers.authorization;
    
    let filteredDrops = dropsDatabase.filter(drop => drop.isActive !== false);
    
    // Se não tem token, retorna vazio
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.json({ success: true, drops: [] });
    }
    
    const token = authHeader.substring(7);
    
    try {
      // Verificar permissões do usuário
      const userInfo = await getUserInfoFromToken(token);
      const canSeeVip = userInfo.roles.includes(VIP_ROLE_ID) || userInfo.roles.includes(OWNER_ROLE_ID);
      
      // Filtrar drops conforme permissões
      filteredDrops = filteredDrops.filter(drop => {
        if (drop.isVip && !canSeeVip) return false;
        return true;
      });
      
    } catch (error) {
      console.log('⚠️ Token inválido ou expirado, retornando drops públicos');
      filteredDrops = filteredDrops.filter(drop => !drop.isVip);
    }
    
    // Filtrar por tipo se especificado
    if (type === 'vip') {
      filteredDrops = filteredDrops.filter(drop => drop.isVip);
    } else if (type === 'normal') {
      filteredDrops = filteredDrops.filter(drop => !drop.isVip);
    }
    
    // Ordenar por data (mais recente primeiro)
    filteredDrops.sort((a, b) => new Date(b.receivedAt) - new Date(a.receivedAt));
    
    // Paginação
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

// Função auxiliar para obter informações do usuário a partir do token
async function getUserInfoFromToken(token) {
  try {
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!userResponse.ok) {
      throw new Error('Token inválido');
    }

    const user = await userResponse.json();

    const memberResponse = await fetch(`https://discord.com/api/users/@me/guilds/${SERVER_ID}/member`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!memberResponse.ok) {
      throw new Error('Usuário não está no servidor');
    }

    const member = await memberResponse.json();
    
    return {
      userId: user.id,
      roles: member.roles || [],
      isVip: member.roles.includes(VIP_ROLE_ID) || member.roles.includes(OWNER_ROLE_ID),
      isOwner: member.roles.includes(OWNER_ROLE_ID)
    };
    
  } catch (error) {
    throw new Error('Falha ao obter informações do usuário: ' + error.message);
  }
}

// Rota para deletar um drop (apenas owner)
app.delete('/api/drops/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Token não fornecido' });
    }
    
    const token = authHeader.substring(7);
    
    // Verificar se é owner
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
    
    // Marcar como inativo ao invés de deletar permanentemente
    dropsDatabase[dropIndex].isActive = false;
    dropsDatabase[dropIndex].deletedAt = new Date().toISOString();
    
    // Emitir atualização para todos os clientes
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

// Rota para estatísticas (com filtro por permissões)
app.get('/api/stats', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    let activeDrops = dropsDatabase.filter(drop => drop.isActive !== false);
    
    // Filtrar por permissões se token fornecido
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      try {
        const userInfo = await getUserInfoFromToken(token);
        const canSeeVip = userInfo.isVip || userInfo.isOwner;
        
        if (!canSeeVip) {
          activeDrops = activeDrops.filter(drop => !drop.isVip);
        }
      } catch (error) {
        // Se token inválido, mostra apenas drops normais
        activeDrops = activeDrops.filter(drop => !drop.isVip);
      }
    } else {
      // Sem token, mostra apenas drops normais
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
    const code = req.query.code;
    
    if (!code) {
        console.log('❌ Erro: Code não recebido');
        return res.redirect(`${FRONTEND_URL}/?error=no_code`);
    }
    
    console.log('✅ Code recebido:', code);

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
        const userInfo = await getUserInfoFromToken(token);
        
        res.json({
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
    console.log(`🔒 Sistema de segurança VIP ativado`);
});
