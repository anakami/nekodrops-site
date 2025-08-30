# NEKO DROPS - Site de Contas Roblox

Este projeto consiste em um site para distribuição de contas Roblox para membros de um servidor Discord.

## Estrutura

- `/backend`: API Node.js/Express para autenticação com Discord
- `/frontend`: Interface web estática

## Configuração

1. Clone o repositório
2. Configure as variáveis de ambiente no arquivo `render.yaml`
3. Conecte o repositório ao Render.com
4. Configure as variáveis de ambiente no painel do Render

## Variáveis de Ambiente

### Backend
- `CLIENT_ID`: ID da aplicação Discord
- `CLIENT_SECRET`: Secret da aplicação Discord
- `REDIRECT_URI`: URL de redirecionamento (seu frontend no Render)
- `SERVER_ID`: ID do servidor Discord
- `MEMBER_ROLE_ID`, `VIP_ROLE_ID`, `OWNER_ROLE_ID`: IDs dos cargos do Discord

## Deploy no Render

O deploy é automático através do arquivo `render.yaml`. Render criará dois serviços:
1. Backend Node.js
2. Frontend estático

## Desenvolvimento Local

Para desenvolvimento local:

1. Instale as dependências do backend: `cd backend && npm install`
2. Configure um arquivo `.env` com as variáveis de ambiente
3. Execute o backend: `npm run dev`
4. Sirva o frontend com um servidor local (ex: Live Server)
