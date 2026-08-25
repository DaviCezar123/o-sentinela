import { FormEvent, useEffect, useState } from 'react'
import QRCode from 'react-qr-code'

type Level = 'safe' | 'warning' | 'danger' | 'neutral'
type Mode = 'inicio' | 'site' | 'informacao' | 'senha' | 'gerador' | 'calculadora'
type AnalyzerMode = 'site' | 'informacao' | 'senha'

type Result = {
  score: number
  score_display?: string | null
  metric_label?: string
  status: string
  level: Level
  summary: string
  reasons: string[]
  disclaimer: string
  sources: { label: string; url: string }[]
}

type CalculatorResult = {
  expression: string
  normalized_expression: string
  result: number
  display: string
  fraction: string | null
}

const API_URL = (import.meta.env.VITE_API_URL ?? 'http://localhost:8000').replace(/\/$/, '')
const PUBLIC_APP_URL = import.meta.env.VITE_PUBLIC_APP_URL ?? window.location.origin
const LOGO = '/logo-sentinela.png'

const moduleContent = {
  site: { tag: 'MÓDULO 01 // VERIFICAÇÃO DE SITE', title: 'Analise antes de acessar.', text: 'Inspecione sinais técnicos de uma URL antes de clicar, comprar ou compartilhar dados.', label: 'Endereço do site', placeholder: 'https://exemplo.com', key: 'url', endpoint: '/api/site/analyze', samples: ['https://www.nasa.gov', 'http://192.168.1.15/pix-gratis'] },
  informacao: { tag: 'MÓDULO 02 // VERIFICAÇÃO DE INFORMAÇÃO', title: 'Pare. Pense. Verifique.', text: 'Compare uma afirmação com a base educativa do Sentinela e veja os motivos do resultado.', label: 'Afirmação para verificar', placeholder: 'Ex.: A Terra é plana', key: 'text', endpoint: '/api/information/analyze', samples: ['A Terra é plana', 'Vacinas causam autismo', 'O Sol é uma estrela'] },
  senha: { tag: 'MÓDULO 03 // ANÁLISE DE SENHA', title: 'Sua senha resiste?', text: 'A análise é imediata e sua senha não é armazenada pelo projeto.', label: 'Digite uma senha', placeholder: 'Sua senha fica privada', key: 'password', endpoint: '/api/password/analyze', samples: ['Senha123', 'F3ir@2026'] },
} as const

function getMode(): Mode {
  const route = window.location.hash.replace('#/', '').split('/')[0]
  return ['site', 'informacao', 'senha', 'gerador', 'calculadora'].includes(route) ? route as Mode : 'inicio'
}

function App() {
  const [mode, setMode] = useState<Mode>(getMode)
  const [transitionTarget, setTransitionTarget] = useState<Exclude<Mode, 'inicio'> | null>(null)
  useEffect(() => { const update = () => setMode(getMode()); window.addEventListener('hashchange', update); return () => window.removeEventListener('hashchange', update) }, [])
  useEffect(() => { if (mode === 'inicio') window.scrollTo({ top: 0, left: 0, behavior: 'auto' }) }, [mode])
  function navigate(next: Mode) {
    if (next === mode || transitionTarget) return
    if (next === 'inicio') {
      const returnToSectorOne = () => window.scrollTo({ top: 0, left: 0, behavior: 'auto' })
      window.location.hash = '#/'
      setMode('inicio')
      returnToSectorOne()
      window.requestAnimationFrame(returnToSectorOne)
      return
    }
    setTransitionTarget(next)
    window.setTimeout(() => { window.location.hash = `#/${next}`; setMode(next) }, 390)
    window.setTimeout(() => setTransitionTarget(null), 1150)
  }
  return <main><TelemetryBar />{mode === 'inicio' ? <Home onNavigate={navigate} /> : mode === 'gerador' ? <Generator onNavigate={navigate} /> : mode === 'calculadora' ? <Calculator onNavigate={navigate} /> : <Analyzer mode={mode} onNavigate={navigate} />}<ModuleTransition target={transitionTarget} /><footer><span>© O SENTINELA · Versão 1.2</span><span>Vigilância Ativa · 2026</span></footer></main>
}

function TelemetryBar() {
  return <header className="telemetry-bar"><span className="online-dot" /><b>SISTEMA ATIVO</b><i /> <span>Versão 1.2</span><i /> <span>VERIFICAÇÃO EM TEMPO REAL</span><span className="telemetry-right">CRIPTOGRAFADO <em>1101110000100101</em></span></header>
}

function ModuleTransition({ target }: { target: Exclude<Mode, 'inicio'> | null }) {
  if (!target) return null
  const labels: Record<Exclude<Mode, 'inicio'>, string> = { site: 'VERIFICAÇÃO DE SITE', informacao: 'ANÁLISE DE INFORMAÇÃO', senha: 'ANÁLISE DE SENHA', gerador: 'GERADOR DE SENHA', calculadora: 'CALCULADORA SEGURA' }
  return <div className="module-transition" aria-live="polite"><div className="transition-grid" /><div className="transition-beam" /><div className="transition-core"><span>PROTOCOLO DE ABERTURA</span><strong>{labels[target]}</strong><small>Sincronizando sensores e núcleo de análise...</small></div></div>
}

function BinaryField({ className = '' }: { className?: string }) {
  const values = Array.from({ length: 180 }, (_, index) => (index * 7 + index % 5) % 3 ? '0' : '1')
  return <div className={`binary-field ${className}`} aria-hidden="true">{values.map((value, index) => <span key={index}>{value}</span>)}</div>
}

function SideBinary() {
  const streams = Array.from({ length: 7 }, () => Array.from({ length: 340 }, () => Math.random() > .5 ? '1' : '0').join(''))
  return <><div className="side-binary-flow side-binary-left" aria-hidden="true">{streams.map((stream, index) => <span className={`binary-line line-${index + 1}`} key={`left-${index}`}>{stream}{stream}</span>)}</div><div className="side-binary-flow side-binary-right" aria-hidden="true">{streams.map((stream, index) => <span className={`binary-line line-${index + 1}`} key={`right-${index}`}>{stream.split('').reverse().join('')}{stream}</span>)}</div></>
}

function Home({ onNavigate }: { onNavigate: (mode: Mode) => void }) {
  return <>
    <section className="hero-protocol"><BinaryField className="hero-binary" /><SideBinary /><div className="hero-orbit orbit-one" /><div className="hero-orbit orbit-two" /><div className="hero-orbit orbit-three" /><div className="hero-logo-wrap"><span className="hero-beacon" /><span className="eye-reactor"><i /><i /><i /></span><img src={LOGO} alt="Logo O Sentinela" /></div><div className="hero-copy-base44"><p className="radar-state"><span /> Radar de Desinformação · Online</p><h1>O <em>SENTINELA</em></h1><strong>Bem-vindo(a)!</strong><p>Uma plataforma de verificação digital de alta integridade — analisando sites, informações e senhas com precisão técnica contra a desinformação.</p><div className="hero-tags"><span>Varredura 360°</span><span>Criptografia Ponta-a-Ponta</span><span>Análise em Tempo Real</span><span>Detecção de Fontes</span><span>Núcleo Protegido</span></div><a className="scroll-protocol" href="#modos">↓ Role para iniciar o protocolo</a></div></section>
    <section className="mode-protocol" id="modos"><BinaryField className="section-binary" /><SideBinary /><div className="sector-label"><span>SECTOR-02 · NEXUS</span><span>3 MODOS · ONLINE</span></div><CornerEmblem /><p className="mini-label">Modo de Operação</p><h2>Escolha o Seu Modo de Verificação</h2><p className="section-lead">Selecione o modo de uso desejado - cada um tem sua funcionalidade e propósito próprio.</p><p className="selection-status"><i /> Sinais ativos · aguardando seleção</p><div className="base-mode-grid"><ProtocolCard number="01" title="Site" text="Verificação da segurança de seu site, em busca de autenticidade e segurança." checks="URL · SSL · REPUTAÇÃO · DOMÍNIO · CERTIFICADO" to="#/site" onNavigate={onNavigate} /><ProtocolCard number="02" title="Informações" text="Checagem em tempo real de frases ou texto que tentam compartilhar desinformação." checks="FATO · CONTEXTO · ORIGEM · CRUZAMENTO · FONTE" to="#/informacao" onNavigate={onNavigate} /><ProtocolCard number="03" title="Senhas" text="Criador e análise de senhas para você se manter seguro protegendo suas contas da melhor forma." checks="FORÇA · COMPLEXIDADE · VAZAMENTO · EXPOSIÇÃO · GERAÇÃO" to="#/senha" onNavigate={onNavigate} /></div><div className="mode-readouts"><span><b>NÚCLEO</b> ATIVO</span><span><b>UPLINK</b> ESTÁVEL</span><span><b>VARREDURA</b> 360°</span><span><b>LOG</b> LIMPO</span></div></section>
    <section className="objective-protocol" id="objetivo"><BinaryField className="section-binary lower-binary" /><SideBinary /><div className="sector-label"><span>SECTOR-03 · MONOLITH</span><span>MISSÃO · CARREGADA</span></div><CornerEmblem /><div className="objective-layout"><div className="objective-copy"><div className="objective-heading"><p className="mini-label">Missão</p><h2>OBJETIVO</h2><h3>Proteger o mundo contra a desinformação que a cada dia se torna mais forte.</h3></div><p className="objective-description">O Sentinela existe como uma camada de defesa entre a verdade e a desinformação. Através de análise minuciosa de sites, informações e senhas, nós fornecemos clareza onde há desinformação — transformando dados brutos em certeza verificável. Cada verificação é um ato de segurança; cada confirmação, um compromisso com a verdade.</p></div></div></section>
    <section className="creators-protocol" id="criadores"><BinaryField className="section-binary lower-binary" /><SideBinary /><div className="sector-label"><span>SECTOR-04 · MANIFEST</span><span>EQUIPE · 3 UNIDADES</span></div><CornerEmblem /><p className="mini-label">System Manifest</p><h2>CRIADORES</h2><div className="creator-intro"><span>Registro de autoria · acesso total concedido</span><b>Versão 1.2 · Menção Honrosa</b></div><div className="creator-grid-base44"><Creator code="SYS-ARCH // 001" letter="D" name="DAVI" role="Programador · Desenvolvedor Principal" text="Responsável por TODO o desenvolvimento do site — do código à estrutura completa." /><Creator code="DATA-CORE // 002" letter="J" name="JOÃO" role="Modelador · Ideias · Apresentador" text="Modelagem conceitual, idealização e apresentação do projeto na feira de ciências." /><Creator code="FRONT-OPS // 003" letter="P" name="PIETRO" role="Capitão · Ideias · Apresentador" text="Liderança da equipe, idealização e apresentação do projeto na feira de ciências." /></div><QrCallout /></section>
  </>
}

function ProtocolCard({ number, title, text, checks, to, onNavigate }: { number: string; title: string; text: string; checks: string; to: string; onNavigate: (mode: Mode) => void }) { const mode = to.replace('#/', '') as AnalyzerMode; return <a className="protocol-card" href={to} onClick={(event) => { event.preventDefault(); onNavigate(mode) }}><ModeGlyph mode={mode} /><span className="card-number">{number}</span><span className="card-frame" /><h3>{title}</h3><p>{text}</p><div className="card-checks"><b>O que verifica:</b><span>{checks}</span></div><div className="card-state"><i /><span className="idle-state">EM ESPERA</span><span className="ready-state">PRONTO PARA USO</span></div><span className="open-module">INICIAR MÓDULO →</span></a> }

function ModeGlyph({ mode }: { mode: AnalyzerMode }) { return <span className={`card-mode-art card-art-${mode}`} aria-hidden="true">{mode === 'site' && <svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="45" /><path d="M15 60h90M20 43c25 12 55 12 80 0M20 77c25-12 55-12 80 0M60 15c-15 13-24 28-24 45s9 32 24 45M60 15c15 13 24 28 24 45s-9 32-24 45" /></svg>}{mode === 'informacao' && <svg viewBox="0 0 120 120"><path d="M28 17h42l18 18v62H28zM70 17v19h18M39 51h33M39 63h25M39 75h19" /><circle cx="75" cy="78" r="18" /><path d="m88 91 15 15m-35-27 5 5 9-11" /></svg>}{mode === 'senha' && <svg viewBox="0 0 120 120"><rect x="27" y="52" width="49" height="40" rx="5" /><path d="M38 52V39a14 14 0 0 1 28 0v13M52 70v10m27 2 23-23m-13 0h13v13" /></svg>}</span> }

function CornerEmblem() { return <div className="corner-emblem" aria-hidden="true"><img src={LOGO} alt="" /></div> }

function Creator({ code, letter, name, role, text }: { code: string; letter: string; name: string; role: string; text: string }) { return <article className="creator-protocol-card"><div className="creator-top"><span>{code}</span><b>ACESSO TOTAL</b></div><div className="creator-letter">{letter}</div><h3>{name}</h3><strong>{role}</strong><p>{text}</p></article> }

function QrCallout() { return <aside className="qr-callout"><div className="qr-frame"><QRCode value={PUBLIC_APP_URL} size={112} bgColor="#07131e" fgColor="#88f3cf" level="M" /></div><div><small>ACESSO MÓVEL // ONLINE</small><h3>Teste o Sentinela</h3><p>Aponte a câmera do celular para acessar a plataforma.</p></div><span className="qr-signal">⌁</span></aside> }

function BackHome({ onNavigate, target = 'inicio', label = '← VOLTAR AO NÚCLEO' }: { onNavigate?: (mode: Mode) => void; target?: Mode; label?: string }) { return <a className="back-home" href={target === 'inicio' ? '#/' : `#/${target}`} onClick={(event) => { if (!onNavigate) return; event.preventDefault(); onNavigate(target) }}>{label}</a> }

type BackdropMode = AnalyzerMode | 'calculadora'

function ModuleBackdrop({ mode }: { mode: BackdropMode }) { return <div className={`module-backdrop backdrop-${mode}`} aria-hidden="true">{mode === 'site' && <svg viewBox="0 0 480 480"><circle cx="240" cy="240" r="151" /><path d="M89 240h302M105 180c85 39 185 39 270 0M105 300c85-39 185-39 270 0M240 89c-48 43-76 94-76 151s28 108 76 151M240 89c48 43 76 94 76 151s-28 108-76 151" /></svg>}{mode === 'informacao' && <svg viewBox="0 0 480 480"><path d="M126 86h164l65 65v236H126z" /><path d="M290 86v68h65M173 199h126M173 240h103M173 281h79" /><circle cx="310" cy="316" r="61" /><path d="m355 361 47 47M286 318l16 16 29-36" /></svg>}{mode === 'senha' && <svg viewBox="0 0 480 480"><rect x="113" y="205" width="205" height="160" rx="18" /><path d="M159 205v-49a57 57 0 0 1 114 0v49" /><circle cx="216" cy="281" r="16" /><path d="M216 297v33M295 327l76-76m-42 0h42v42M85 148h49m-25-25v50M354 168h44m-22-22v44" /></svg>}{mode === 'calculadora' && <svg className="calculator-pi-backdrop" viewBox="0 0 480 480"><circle cx="240" cy="240" r="151" /><circle cx="240" cy="240" r="118" /><text x="240" y="240" textAnchor="middle" dominantBaseline="middle">π</text></svg>}{mode !== 'calculadora' && <><span className="backdrop-node node-a" /><span className="backdrop-node node-b" /><span className="backdrop-node node-c" /></>}</div> }

function Analyzer({ mode, onNavigate }: { mode: AnalyzerMode; onNavigate: (mode: Mode) => void }) {
  const config = moduleContent[mode]
  const [value, setValue] = useState('')
  const [result, setResult] = useState<Result | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [showReasons, setShowReasons] = useState(false)
  const [passwordVisible, setPasswordVisible] = useState(false)

  function clearForm() {
    setValue('')
    setResult(null)
    setError('')
    setShowReasons(false)
    setPasswordVisible(false)
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!value.trim()) return
    setLoading(true)
    setError('')
    setResult(null)
    setShowReasons(false)
    try {
      const [response] = await Promise.all([
        fetch(`${API_URL}${config.endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ [config.key]: value }) }),
        new Promise((resolve) => window.setTimeout(resolve, 1150)),
      ])
      if (!response.ok) throw new Error()
      setResult(await response.json() as Result)
    } catch {
      setError('Não foi possível falar com o Sentinela. Verifique se o back-end está ligado e tente novamente.')
    } finally {
      setLoading(false)
    }
  }

  return <section className={`module-page module-${mode}`}><BinaryField className="module-binary" /><ModuleBackdrop mode={mode} /><BackHome onNavigate={onNavigate} /><div className="module-heading"><p>{config.tag}</p><h1>{config.title}</h1><span>{config.text}</span></div><div className="module-console"><form onSubmit={submit}><label htmlFor="entry">{config.label}</label>{mode === 'informacao' ? <textarea id="entry" value={value} onChange={(event) => setValue(event.target.value)} placeholder={config.placeholder} /> : mode === 'senha' ? <div className="password-entry"><input id="entry" type={passwordVisible ? 'text' : 'password'} value={value} onChange={(event) => setValue(event.target.value)} placeholder={config.placeholder} autoComplete="off" /><button className="password-visibility" type="button" onClick={() => setPasswordVisible((visible) => !visible)} aria-pressed={passwordVisible}>{passwordVisible ? '◉ OCULTAR SENHA' : '◌ MOSTRAR SENHA'}</button></div> : <input id="entry" type="url" value={value} onChange={(event) => setValue(event.target.value)} placeholder={config.placeholder} autoComplete="off" />}<div className="sample-row"><small>EXEMPLOS PARA TESTAR</small><div>{config.samples.map((sample) => <button className="sample-chip" type="button" onClick={() => setValue(sample)} key={sample}>{sample}</button>)}</div></div><div className="form-actions"><button type="submit" disabled={loading}>{loading ? 'ANALISANDO...' : 'INICIAR VARREDURA'} →</button><button className="clear-button" type="button" disabled={loading} onClick={clearForm}>LIMPAR</button></div>{mode === 'senha' && <a className="generator-link" href="#/gerador" onClick={(event) => { event.preventDefault(); onNavigate('gerador') }}>CRIAR SENHA PERSONALIZADA →</a>}</form>{loading ? <ProcessingPanel mode={mode} /> : <ResultPanel result={result} error={error} showReasons={showReasons} onToggle={() => setShowReasons(!showReasons)} />}</div><button className="calculator-launch" type="button" onClick={() => onNavigate('calculadora')}><span aria-hidden="true">π</span><b>CALCULADORA</b><small>operações e frações →</small></button></section>
}

function ProcessingPanel({ mode }: { mode: AnalyzerMode }) {
  const [progress, setProgress] = useState(8); const [packet, setPacket] = useState(418)
  const labels: Record<AnalyzerMode, string> = { site: 'Mapeando integridade da URL', informacao: 'Cruzando sinais e contexto', senha: 'Testando resistência da credencial' }
  useEffect(() => { const progressTimer = window.setInterval(() => setProgress((current) => Math.min(94, current + Math.max(1, Math.round((95 - current) / 10)))), 150); const packetTimer = window.setInterval(() => setPacket((current) => current + Math.floor(Math.random() * 19) + 7), 280); return () => { window.clearInterval(progressTimer); window.clearInterval(packetTimer) } }, [])
  return <aside className="analysis-result processing-panel"><div className="processing-top"><small>VARREDURA EM ANDAMENTO</small><b>{progress}<em>%</em></b></div><div className="processing-radar"><i /><i /><i /><span>⌾</span></div><h2>{labels[mode]}</h2><p>Pacotes analisados: <strong>{packet.toString().padStart(4, '0')}</strong> · Sensores ativos: 07</p><div className="processing-line"><i style={{ width: `${progress}%` }} /></div><small className="processing-status">⌁ NÚCLEO OPERANDO · DADOS NÃO ARMAZENADOS</small></aside>
}

function ResultPanel({ result, error, showReasons, onToggle }: { result: Result | null; error: string; showReasons: boolean; onToggle: () => void }) { if (error) return <aside className="analysis-result result-error"><small>CONEXÃO</small><h2>Não foi possível analisar</h2><p>{error}</p></aside>; if (!result) return <aside className="analysis-result result-empty"><span>◈</span><small>RESULTADO</small><h2>Aguardando uma análise</h2><p>O resultado e a explicação aparecerão aqui.</p></aside>; const hasScoreDisplay = Boolean(result.score_display); return <aside className={`analysis-result result-${result.level}`}><div className={`result-score${hasScoreDisplay ? ' result-score-text' : ''}`}><small>{result.metric_label ?? 'RESULTADO'}</small><b>{hasScoreDisplay ? result.score_display : <>{result.score}<em>/100</em></>}</b></div>{!hasScoreDisplay && <div className="score-line"><i style={{ width: `${result.score}%` }} /></div>}<h2>{result.status}</h2><p>{result.summary}</p><button className="justification-button" onClick={onToggle}><span><small>ANÁLISE EXPLICADA</small>{showReasons ? 'Ocultar justificativa' : 'Mostrar justificativa'}</span><b>{showReasons ? '−' : '+'}</b></button>{showReasons && <div className="reason-list"><ul>{result.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>{result.sources.map((source) => <a key={source.url} href={source.url} target="_blank" rel="noreferrer">↗ {source.label}</a>)}</div>}<small className="disclaimer">{result.disclaimer}</small></aside> }

type CalculatorKey = { label: string; value: string; tone?: 'operator' | 'fraction' | 'utility' | 'equals'; title?: string }

const calculatorKeys: CalculatorKey[] = [
  { label: '7', value: '7' }, { label: '8', value: '8' }, { label: '9', value: '9' }, { label: '÷', value: '÷', tone: 'operator' }, { label: '(', value: '(', tone: 'operator' }, { label: ')', value: ')', tone: 'operator' },
  { label: '4', value: '4' }, { label: '5', value: '5' }, { label: '6', value: '6' }, { label: '×', value: '×', tone: 'operator' }, { label: '^', value: '^', tone: 'operator' }, { label: '√', value: '√(', tone: 'operator', title: 'raiz quadrada' },
  { label: '1', value: '1' }, { label: '2', value: '2' }, { label: '3', value: '3' }, { label: '−', value: '−', tone: 'operator' }, { label: ',', value: ',', tone: 'operator', title: 'vírgula decimal' }, { label: '⌫', value: 'backspace', tone: 'utility', title: 'apagar último símbolo' },
  { label: '0', value: '0' }, { label: '00', value: '00' }, { label: 'a/b', value: '/', tone: 'fraction', title: 'fração' }, { label: '+', value: '+', tone: 'operator' }, { label: 'C', value: 'clear', tone: 'utility', title: 'limpar' }, { label: '=', value: 'calculate', tone: 'equals', title: 'calcular' },
]

function Calculator({ onNavigate }: { onNavigate: (mode: Mode) => void }) {
  const [expression, setExpression] = useState('')
  const [result, setResult] = useState<CalculatorResult | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  function append(value: string) {
    setExpression((current) => current.length >= 120 ? current : `${current}${value}`)
    setError('')
  }

  function useKey(value: string) {
    if (value === 'backspace') { setExpression((current) => current.slice(0, -1)); setError(''); return }
    if (value === 'clear') { setExpression(''); setResult(null); setError(''); return }
    if (value === 'calculate') { void calculate(); return }
    append(value)
  }

  async function calculate(event?: FormEvent) {
    event?.preventDefault()
    if (!expression.trim() || loading) return
    setLoading(true)
    setError('')
    try {
      const response = await fetch(`${API_URL}/api/calculator/evaluate`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ expression }) })
      const data = await response.json() as CalculatorResult | { detail?: string }
      if (!response.ok) throw new Error('detail' in data ? data.detail : 'Não foi possível concluir o cálculo.')
      setResult(data as CalculatorResult)
    } catch (requestError) {
      setResult(null)
      setError(requestError instanceof Error ? requestError.message : 'Não foi possível falar com o Sentinela. Verifique se o back-end está ligado.')
    } finally {
      setLoading(false)
    }
  }

  return <section className="module-page calculator-page"><BinaryField className="module-binary" /><ModuleBackdrop mode="calculadora" /><BackHome onNavigate={onNavigate} target="informacao" label="← VOLTAR ÀS INFORMAÇÕES" /><div className="module-heading"><p>MÓDULO 02A // CÁLCULO SEGURO</p><h1>Calculadora do Sentinela</h1><span>Resolva expressões com parênteses, frações, potências e raízes. O cálculo é feito pelo núcleo do Sentinela, sem executar código no navegador.</span></div><div className="calculator-layout"><form className="calculator-console" onSubmit={calculate}><label htmlFor="calculator-entry">Expressão matemática</label><div className="calculator-display-wrap"><input id="calculator-entry" value={expression} onChange={(event) => { setExpression(event.target.value); setError('') }} placeholder="Ex.: (1 ÷ 2) + √(9)" inputMode="text" autoComplete="off" aria-describedby="calculator-help" /><span aria-hidden="true">⌁</span></div><p id="calculator-help">Use <b>a/b</b> para frações, <b>^</b> para potência e <b>√(</b> para raiz.</p><div className="calculator-keypad" aria-label="Teclado da calculadora">{calculatorKeys.map((key) => <button className={key.tone ? `calculator-key ${key.tone}` : 'calculator-key'} type="button" title={key.title} aria-label={key.title ?? key.label} onClick={() => useKey(key.value)} key={key.label}>{key.label}</button>)}</div><button className="calculator-submit" type="submit" disabled={loading}>{loading ? 'CALCULANDO...' : 'CALCULAR'} <span>→</span></button></form><aside className={`calculator-result ${error ? 'calculator-error' : ''}`} aria-live="polite">{error ? <><small>AJUSTE NECESSÁRIO</small><h2>Não foi possível calcular</h2><p>{error}</p><span className="calculator-error-mark">×</span></> : result ? <><small>RESULTADO CONFIRMADO</small><output>{result.display}</output>{result.fraction && <p className="fraction-readout">Fração exata <b>{result.fraction}</b></p>}<p className="calculation-trace">{result.expression} <span>→</span> {result.display}</p><small className="calculator-note">Cálculo local restrito · expressão não armazenada</small></> : <><span className="calculator-empty-mark">⌬</span><small>VISOR PRONTO</small><h2>Aguardando expressão</h2><p>Monte o cálculo no teclado ou digite diretamente no visor.</p><div className="calculator-examples"><button type="button" onClick={() => setExpression('1/2 + 1/4')}>1/2 + 1/4</button><button type="button" onClick={() => setExpression('√(81) + 2^3')}>√(81) + 2^3</button></div></>}</aside></div></section>
}

function Generator({ onNavigate }: { onNavigate: (mode: Mode) => void }) {
  const [strength, setStrength] = useState<'fraca' | 'media' | 'forte'>('forte'); const [theme, setTheme] = useState(''); const [length, setLength] = useState(16); const [password, setPassword] = useState(''); const [error, setError] = useState('')
  async function generate(event: FormEvent) { event.preventDefault(); setError(''); try { const response = await fetch(`${API_URL}/api/password/generate`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ strength, theme, length }) }); if (!response.ok) throw new Error(); const data = await response.json() as { password: string }; setPassword(data.password) } catch { setError('Não foi possível gerar a senha. Confirme se o back-end está em execução.') } }
  return <section className="module-page generator-page"><BinaryField className="module-binary" /><BackHome /><div className="module-heading"><p>MÓDULO 03 // GERADOR</p><h1>Forje uma senha segura.</h1><span>Escolha um nível para gerar uma senha demonstrativa e personalizada.</span></div><div className="module-console generator-console"><form onSubmit={generate}><label>Nível de segurança</label><div className="strength-choice">{(['fraca', 'media', 'forte'] as const).map((item) => <button type="button" className={strength === item ? `chosen ${item}` : ''} onClick={() => setStrength(item)} key={item}>{item}</button>)}</div>{strength === 'forte' ? <><label htmlFor="length">Tamanho: {length} caracteres</label><input id="length" type="range" min="16" max="32" value={length} onChange={(event) => setLength(Number(event.target.value))} /></> : <><label htmlFor="theme">Tema genérico opcional</label><input id="theme" value={theme} onChange={(event) => setTheme(event.target.value)} placeholder="Ex.: Cometa" /></>}<button>GERAR SENHA →</button></form><aside className="analysis-result generated-result"><small>SENHA GERADA</small>{password ? <code>{password}</code> : <><span>⌘</span><h2>Pronta para criar</h2><p>Escolha um nível e inicie o processo.</p></>}{error && <p className="error-copy">{error}</p>}</aside></div></section>
}

export default App
