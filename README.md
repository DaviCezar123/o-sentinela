# O Sentinela

Aplicação web educativa para uma feira de ciências. O projeto não dá garantias mágicas: explica sinais de risco em URLs, compara algumas afirmações com uma base educativa local e ajuda a entender senhas fortes.

## O que foi melhorado em relação ao protótipo

- Interface responsiva para tablet e celular, com páginas/rotas próprias para cada modo.
- Front-end em **React + TypeScript** e API em **Python + FastAPI**: tecnologias separadas e comunicando por HTTP.
- Resultados explicáveis: a justificativa fica recolhida e cada regra usada é apresentada ao visitante.
- Senhas não são armazenadas e o modo forte usa o gerador criptograficamente seguro do Python.
- A análise de informação é conservadora: quando não reconhece algo, responde **“Não verificada”**, em vez de inventar uma resposta.
- Testes automáticos para as regras essenciais do back-end.

## Estrutura

```text
o-sentinela/
├── frontend/        # React + TypeScript: interface vista no navegador
├── backend/         # Python + FastAPI: regras e endpoints da API
└── README.md        # este guia
```

## 1. Instalar as ferramentas (uma única vez)

1. Instale o [Visual Studio Code](https://code.visualstudio.com/).
2. Instale o [Node.js LTS](https://nodejs.org/). Ele executa o front-end.
3. Instale o [Python 3.12 ou superior](https://www.python.org/downloads/). Na instalação, marque **Add Python to PATH**.
4. No VS Code, instale as extensões **Python** (Microsoft) e **ESLint** (Microsoft).

Abra a pasta `o-sentinela` no VS Code. No Windows, use **Arquivo > Abrir Pasta** e selecione esta pasta. Depois abra dois terminais pelo menu **Terminal > Novo Terminal**.

## 2. Executar no seu computador

### Terminal 1 — API em Python

```powershell
cd backend
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv312\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:ALLOWED_ORIGINS = "*"
python -m uvicorn app.main:app --reload --port 8000
```

Se o PowerShell bloquear a ativação, execute apenas nesta janela:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Ao final, abra `http://localhost:8000/docs`. Essa é a documentação automática da API. Deixe esse terminal ligado.

### Terminal 2 — interface em React

```powershell
cd frontend
npm run dev
```

Abra o endereço mostrado pelo Vite, normalmente `http://localhost:5173`. A interface fará chamadas para `http://localhost:8000`; isso é a interligação entre front-end e back-end.

Se o PowerShell mostrar uma mensagem sobre “execução de scripts desabilitada” ao usar `npm`, troque `npm` por `npm.cmd` nos comandos acima. Não é necessário alterar configurações globais do computador.

## 3. Testar e gerar a versão de produção

Com o ambiente virtual ativo dentro de `backend`:

```powershell
pytest
```

Dentro de `frontend`:

```powershell
npm run build
```

O comando cria `frontend/dist`, a versão otimizada que será publicada. Não envie as pastas `.venv`, `node_modules` ou `dist` ao GitHub.

## 4. Publicar para a feira (GitHub + Render)

O projeto usa dois serviços gratuitos dentro do Render: um **Web Service** para a API em Python e um **Static Site** para a interface React. O código fica no GitHub, e cada atualização enviada à branch principal cria um novo deploy automático.

### Primeiro: API no Render

1. No [Render](https://render.com/), escolha **New > Web Service** e conecte o repositório do GitHub.
2. Use estas configurações:

```text
Root Directory: backend
Runtime: Python
Build Command: pip install -r requirements.txt
Start Command: python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT
Health Check Path: /health
Instance Type: Free
```

3. Em **Environment**, adicione:

```text
RATE_LIMIT_PER_MINUTE=60
PWNED_PASSWORDS_ENABLED=false
```

4. Conclua o deploy e copie a URL da API, por exemplo `https://o-sentinela-api.onrender.com`.

### Depois: interface no Render

1. Escolha **New > Static Site** e conecte o mesmo repositório.
2. Use estas configurações:

```text
Root Directory: frontend
Build Command: npm ci && npm run build
Publish Directory: dist
```

3. Em **Environment**, crie a variável abaixo usando a URL da API que você copiou:

```text
VITE_API_URL=https://o-sentinela-api.onrender.com
```

4. Conclua o deploy e copie a URL pública do site, por exemplo `https://o-sentinela.onrender.com`.

### Por último: liberar a comunicação entre os dois

Volte ao serviço da API, abra **Environment** e adicione:

```text
ALLOWED_ORIGINS=https://o-sentinela.onrender.com
```

Salve usando **Save, rebuild and deploy**. Sem essa variável, o navegador bloqueia a comunicação por segurança (CORS). A API não usa `*` em produção.

### Monitorar e atualizar

- **Logs:** abra o serviço da API no Render e use a aba **Logs** para ver erros ou acessos.
- **Health Check:** abra `https://sua-api.onrender.com/health`; a resposta deve conter `"status":"ok"`.
- **Deploys:** a aba **Events** mostra se cada publicação funcionou ou falhou.
- **Atualizar o site:** altere os arquivos no VS Code, teste localmente e envie as alterações ao GitHub. O Render detecta o novo commit e publica automaticamente.
- **Dia da feira:** abra a API e o site no tablet cerca de dois minutos antes. O serviço gratuito pode adormecer após um período sem uso e o primeiro acesso pode levar mais tempo.

## 5. Antes de mostrar ao público

- Troque “Equipe O Sentinela” na rota **Criadores** pelos nomes, turma, escola e professor(a) orientador(a).
- Teste pelo celular no Wi‑Fi do local e tenha um plano B: deixe o projeto aberto em uma aba e leve um hotspot, se possível.
- Use o QR Code já presente no site: em produção ele aponta automaticamente para a URL pública atual. Imprima esse endereço na cartolina.
- Explique que o resultado é educativo e baseado em sinais; não peça senhas reais nem dados pessoais aos visitantes.

## Onde personalizar

- `frontend/src/App.tsx`: textos, criadores e páginas.
- `frontend/src/styles.css`: cores e aparência.
- `backend/app/analysis.py`: domínios reconhecidos, fatos da base educativa e regras de análise.

## Limites importantes

O modo Site não visita a página e não substitui antivírus, serviços de reputação ou análise humana. O modo Informação não pesquisa a internet em tempo real: ele usa uma base pequena, com fontes linkadas. Para saúde, eleições, finanças ou notícias recentes, consulte fontes primárias e especializadas.
