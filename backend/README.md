# O Sentinela — back-end de evidências

O servidor combina regras locais explicáveis com fontes online opcionais. Ele
não promete certeza absoluta: quando não há evidência suficiente, a resposta
continua como **não verificada** em vez de inventar um veredito.

## Camadas de análise

- **Sites:** validação da URL, HTTPS, domínio imitador, punycode, IP local,
  portas incomuns e termos típicos de golpe. Com `WEBRISK_API_KEY`, consulta a
  Google Web Risk para ameaças conhecidas de malware e engenharia social.
- **Informações:** base educativa local, detecção de linguagem sensacionalista
  e proteção contra frases que apenas citam uma alegação para desmenti-la. Com
  `FACTCHECK_API_KEY`, procura checagens publicadas pela Google Fact Check
  Tools API e mostra as fontes encontradas.
- **Senhas:** tamanho, variedade, sequências de teclado, blocos repetidos e
  padrões comuns. Com `PWNED_PASSWORDS_ENABLED=true`, consulta a base Pwned
  Passwords usando k-anonimato: apenas cinco caracteres de um hash SHA-1 são
  enviados, nunca a senha inteira.

## Configuração opcional

Copie `.env.example` para `.env` e preencha somente os recursos que for usar:

```env
ALLOWED_ORIGINS=http://localhost:5173
RATE_LIMIT_PER_MINUTE=60
WEBRISK_API_KEY=sua_chave_restrita_ao_servidor
FACTCHECK_API_KEY=sua_chave_restrita_ao_servidor
PWNED_PASSWORDS_ENABLED=false
```

Mantenha `.env` fora do Git e nunca coloque essas chaves no front-end. Para
ambiente de feira, o modo local funciona sem nenhuma chave; as integrações
online apenas tornam os resultados mais ricos quando o computador tiver
internet.

## Rodar e testar

```powershell
cd backend
.\.venv312\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
python -m uvicorn app.main:app --reload --port 8000
```

Verifique em `http://localhost:8000/health` e veja quais integrações estão
ativas em `http://localhost:8000/api/intelligence/status`.

## Princípios de segurança

- URLs enviadas por visitantes **não são abertas diretamente** pelo servidor,
  evitando que a ferramenta vire um meio de acessar redes privadas.
- Nenhuma senha é salva ou devolvida pela rota de análise.
- Ausência de uma ameaça na lista não significa que o site é seguro; ausência
  de uma checagem publicada não significa que a informação é verdadeira.
