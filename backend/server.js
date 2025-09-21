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
const BOOSTER_ROLE_ID = process.env.BOOSTER_ROLE_ID;
const MEMBER_ROLE_ID = process.env.MEMBER_ROLE_ID;
const VIP_ROLE_ID = process.env.VIP_ROLE_ID;
const OWNER_ROLE_ID = process.env.OWNER_ROLE_ID;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;

// "Banco de dados" em memória
let dropsDatabase = [];
let connectedClients = new Map();

// Variável para cache de banimentos
let bannedUsersCache = [];
let lastCacheUpdate = 0;
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutos

// Função para buscar banimentos da API do Discord
async function fetchBannedUsers() {
  try {
    console.log('🔍 Buscando lista de banimentos do Discord...');
    const response = await fetch(`https://discord.com/api/guilds/${SERVER_ID}/bans`, {
      headers: {
        'Authorization': `Bot ${DISCORD_BOT_TOKEN}`
      }
    });
    
    if (response.ok) {
      const bans = await response.json();
      const bannedIds = bans.map(ban => ban.user.id);
      console.log(`✅ ${bannedIds.length} usuários banidos encontrados`);
      return bannedIds;
    } else if (response.status === 403) {
      console.error('❌ Permissão negada para ver banimentos. Verifique se o bot tem a permissão BAN_MEMBERS');
      return [];
    } else {
      console.error('❌ Erro ao buscar banimentos:', response.status, response.statusText);
      return [];
    }
  } catch (error) {
    console.error('❌ Erro ao buscar banimentos:', error.message);
    return [];
  }
}

// Middleware para verificar e atualizar cache de banimentos
async function updateBansCache() {
  const now = Date.now();
  if (now - lastCacheUpdate > CACHE_DURATION) {
    console.log('🔄 Atualizando cache de banimentos...');
    bannedUsersCache = await fetchBannedUsers();
    lastCacheUpdate = now;
    console.log(`✅ ${bannedUsersCache.length} usuários banidos em cache`);
  }
}

// Função para verificar se um usuário está banido
async function checkIfUserIsBanned(userId) {
  try {
    await updateBansCache(); // Atualiza cache se necessário
    return bannedUsersCache.includes(userId);
  } catch (error) {
    console.error('❌ Erro ao verificar banimento:', error);
    return false;
  }
}

// Função para verificar se usuário está no servidor
async function checkGuildMembership(userId) {
  try {
    const response = await fetch(`https://discord.com/api/guilds/${SERVER_ID}/members/${userId}`, {
      headers: {
        'Authorization': `Bot ${DISCORD_BOT_TOKEN}`
      }
    });
    
    return response.status === 200;
  } catch (error) {
    console.error('❌ Erro ao verificar membership:', error);
    return false;
  }
}

// Inicializar cache de banimentos ao iniciar o servidor
async function initializeBansCache() {
  try {
    console.log('🔄 Inicializando cache de banimentos...');
    bannedUsersCache = await fetchBannedUsers();
    lastCacheUpdate = Date.now();
    console.log(`✅ Cache de banimentos inicializado com ${bannedUsersCache.length} usuários`);
  } catch (error) {
    console.error('❌ Erro ao inicializar cache de banimentos:', error);
  }
}

// WebSocket para atualização em tempo real
io.on('connection', (socket) => {
  console.log('🔗 Cliente conectado via WebSocket:', socket.id);
  
  socket.on('authenticate', async (userData) => {
    try {
      console.log('🔐 Tentativa de autenticação WebSocket:', userData);
      
      let userInfo;
      
      if (userData.token) {
        // Se tem token, usa para buscar informações
        userInfo = await getUserInfoFromToken(userData.token);
      } else if (userData.userId && userData.roles) {
        // Se já tem informações do usuário, usa diretamente
        userInfo = userData;
      } else {
        throw new Error('Dados de autenticação inválidos');
      }

      // Verificar se usuário está banido
      const isBanned = await checkIfUserIsBanned(userInfo.userId);
      if (isBanned) {
        console.log(`🚫 Usuário ${userInfo.username} (${userInfo.userId}) está banido - desconectando`);
        socket.emit('user_banned', { userId: userInfo.userId });
        socket.disconnect();
        return;
      }

      connectedClients.set(socket.id, {
        userId: userInfo.userId,
        username: userInfo.username,
        roles: userInfo.roles || [],
        isVip: userInfo.roles?.includes(VIP_ROLE_ID) || userInfo.roles?.includes(OWNER_ROLE_ID),
        isOwner: userInfo.roles?.includes(OWNER_ROLE_ID)
      });

      console.log(`✅ Cliente ${socket.id} autenticado como ${userInfo.username}`);
      socket.emit('authenticated', { success: true });
      
    } catch (error) {
      console.error('❌ Falha na autenticação WebSocket:', error.message);
      socket.emit('auth_error', { error: error.message });
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
    console.log('🔍 Verificando token com Discord API...');
    
    // 1. Obter informações básicas do usuário
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!userResponse.ok) {
      console.log('❌ Token inválido - Status:', userResponse.status);
      throw new Error('Token inválido');
    }

    const user = await userResponse.json();
    console.log('✅ Usuário encontrado:', user.username);

    // 2. Obter informações do membro no servidor
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
    
    console.log('✅ Cargos do usuário:', member.roles);
    
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

// Rota para verificar se um usuário está banido
app.get('/api/check-ban/:userId', async (req, res) => {
  try {
    await updateBansCache(); // Atualiza cache se necessário
    
    const { userId } = req.params;
    const isBanned = bannedUsersCache.includes(userId);
    
    res.json({ banned: isBanned });
  } catch (error) {
    console.error('❌ Erro ao verificar banimento:', error);
    res.status(500).json({ error: 'Erro ao verificar banimento' });
  }
});

// Rota para verificar status no servidor
app.get('/api/check-membership/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    // Verifica se o usuário ainda está no servidor
    const isMember = await checkGuildMembership(userId);
    res.json({ isMember });
  } catch (error) {
    console.error('❌ Erro ao verificar membership:', error);
    res.status(500).json({ error: 'Erro ao verificar membership' });
  }
});

// Rota para forçar atualização do cache (opcional)
app.post('/api/refresh-bans', async (req, res) => {
  try {
    bannedUsersCache = await fetchBannedUsers();
    lastCacheUpdate = Date.now();
    res.json({ success: true, count: bannedUsersCache.length });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao atualizar banimentos' });
  }
});

app.get('/api/user-methods-permissions', async (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  const token = authHeader.substring(7);

  try {
    const userInfo = await getUserInfoFromToken(token);
    
    const hasBooster = userInfo.roles.includes(BOOSTER_ROLE_ID);
    const hasVip = userInfo.roles.includes(VIP_ROLE_ID) || userInfo.roles.includes(OWNER_ROLE_ID);
    const hasMember = userInfo.roles.includes(MEMBER_ROLE_ID);
    
    res.json({
      success: true,
      permissions: {
        canSeeMethods: hasMember, // Mínimo precisa ser membro
        canSeeFreeMethods: hasMember,
        canSeeVipMethods: hasVip,
        canSeeBoosterMethods: hasBooster,
        hasBooster: hasBooster,
        hasVip: hasVip,
        hasMember: hasMember
      }
    });

  } catch (error) {
    console.error('❌ Erro ao verificar permissões de métodos:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.get('/api/security/validate', async (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ valid: false, reason: 'no_token' });
  }

  const token = authHeader.substring(7);
  
  try {
    const userInfo = await getUserInfoFromToken(token);
    
    // Verificar se usuário está banido
    const isBanned = await checkIfUserIsBanned(userInfo.userId);
    if (isBanned) {
      return res.status(403).json({ 
        valid: false, 
        reason: 'banned',
        message: 'Usuário banido do servidor' 
      });
    }
    
    res.json({
      valid: true,
      userId: userInfo.userId,
      roles: userInfo.roles,
      isVip: userInfo.isVip,
      isOwner: userInfo.isOwner,
      timestamp: Date.now()
    });
    
  } catch (error) {
    res.status(401).json({ 
      valid: false, 
      reason: 'invalid_token',
      message: error.message 
    });
  }
});

// Middleware de segurança adicional
app.use('/api/drops', async (req, res, next) => {
  if (req.method === 'GET') {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      
      try {
        // Verificar rapidamente se o token ainda é válido
        const userInfo = await getUserInfoFromToken(token);
        
        // Verificar se usuário está banido
        const isBanned = await checkIfUserIsBanned(userInfo.userId);
        if (isBanned) {
          return res.status(403).json({ error: 'Usuário banido' });
        }
        
        req.userInfo = userInfo;
      } catch (error) {
        // Token inválido, mas permitir acesso a drops públicos
        console.log('⚠️ Token inválido em requisição de drops');
      }
    }
  }
  next();
});

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
    const { type } = req.query;
    const authHeader = req.headers.authorization;
    
    let filteredDrops = dropsDatabase.filter(drop => drop.isActive !== false);
    
    // Se não tem token, retorna apenas drops públicos
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      filteredDrops = filteredDrops.filter(drop => !drop.isVip);
    } else {
      const token = authHeader.substring(7);
      
      try {
        const userInfo = await getUserInfoFromToken(token);
        
        // Verificar se usuário está banido
        const isBanned = await checkIfUserIsBanned(userInfo.userId);
        if (isBanned) {
          return res.status(403).json({ error: 'Usuário banido' });
        }
        
        const canSeeVip = userInfo.roles.includes(VIP_ROLE_ID) || userInfo.roles.includes(OWNER_ROLE_ID);
        
        // Filtrar drops conforme permissões
        filteredDrops = filteredDrops.filter(drop => {
          if (drop.isVip && !canSeeVip) return false;
          return true;
        });
        
      } catch (error) {
        console.log('⚠️ Token inválido, retornando drops públicos');
        filteredDrops = filteredDrops.filter(drop => !drop.isVip);
      }
    }
    
    // Filtrar por tipo se especificado
    if (type === 'vip') {
      filteredDrops = filteredDrops.filter(drop => drop.isVip);
    } else if (type === 'normal') {
      filteredDrops = filteredDrops.filter(drop => !drop.isVip);
    }
    
    // Ordenar por data (mais recente primeiro)
    filteredDrops.sort((a, b) => new Date(b.receivedAt) - new Date(a.receivedAt));
    
    res.json({
      success: true,
      drops: filteredDrops,
      total: filteredDrops.length,
      hasMore: false
    });
    
  } catch (error) {
    console.error('❌ Erro ao buscar drops:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.get('/api/ip-info', async (req, res) => {
  const { ip } = req.query;
  
  if (!ip) {
    return res.status(400).json({ error: 'IP não fornecido' });
  }
  
  try {
    const response = await fetch(`https://ipinfo.io/${ip}/json`);
    const data = await response.json();
    
    res.json({
      success: true,
      countryInfo: {
        code: data.country.toLowerCase(),
        name: data.country_name || data.country,
        flag: `https://flagcdn.com/w40/${data.country.toLowerCase()}.png`,
        country: data.country_name || data.country,
        city: data.city,
        region: data.region
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: 'Erro ao buscar informações do IP' 
    });
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
        
        // Verificar se usuário está banido
        const isBanned = await checkIfUserIsBanned(userInfo.userId);
        if (isBanned) {
            return res.status(403).json({ 
                error: 'Usuário banido do servidor',
                banned: true 
            });
        }
        
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
        
        // Verificar se usuário está banido
        const isBanned = await checkIfUserIsBanned(userInfo.userId);
        if (isBanned) {
            return res.status(403).json({ 
                error: 'Usuário banido do servidor',
                banned: true 
            });
        }
        
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
        bannedUsers: bannedUsersCache.length,
        lastCacheUpdate: new Date(lastCacheUpdate).toISOString(),
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
            health: '/health',
            checkBan: '/api/check-ban/:userId',
            checkMembership: '/api/check-membership/:userId'
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

// Inicializar servidor
server.listen(PORT, async () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`🌐 Frontend URL: ${FRONTEND_URL}`);
    console.log(`🔗 Redirect URI: ${REDIRECT_URI}`);
    console.log(`✅ Health check disponível em: http://localhost:${PORT}/health`);
    console.log(`📊 WebSocket pronto para conexões`);
    
    // Inicializar cache de banimentos
    await initializeBansCache();
});
