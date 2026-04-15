/**
 * Popup da extensao — abre ao clicar no icone na barra do navegador
 * Mostra resultado da analise de URL via API DomURLs-BERT,
 * cards de emails analisados, status da API,
 * e controles para cache e configuracao.
 */

import { useEffect, useState } from "react"
import type { AnalysisResult, AnalysisSource, EmailUrlResultData } from "./background"

import "./popup.css"

// ============================================================
// Tipos
// ============================================================

interface TabResult extends AnalysisResult {
  url: string
}

interface EmailResult extends AnalysisResult {
  url: string
  timestamp: number
}

interface HealthInfo {
  online: boolean
  device?: string
  version?: string
}

// ============================================================
// Helpers — mensagens para o background
// ============================================================

function sendMsg<T>(msg: Record<string, unknown>): Promise<T> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (response: T) => resolve(response))
  })
}

async function fetchResult(tabId: number): Promise<TabResult | null> {
  const resp = await sendMsg<{ result: TabResult | null }>({
    type: "GET_RESULT",
    tabId,
  })
  return resp?.result ?? null
}

async function fetchEmailHistory(tabId: number): Promise<EmailResult[]> {
  const resp = await sendMsg<{ emails: EmailResult[] }>({
    type: "GET_EMAIL_HISTORY",
    tabId,
  })
  return resp?.emails ?? []
}

async function fetchApiStatus(): Promise<HealthInfo> {
  const resp = await sendMsg<{ health: Record<string, unknown> }>({
    type: "GET_API_STATUS",
  })
  const h = resp?.health
  if (!h || "offline" in h) return { online: false }
  return {
    online: true,
    device: String(h.device ?? ""),
    version: String(h.version ?? ""),
  }
}

async function clearCacheMsg(): Promise<boolean> {
  const resp = await sendMsg<{ success: boolean }>({ type: "CLEAR_CACHE" })
  return resp?.success ?? false
}

async function setApiUrlMsg(apiUrl: string): Promise<boolean> {
  const resp = await sendMsg<{ success: boolean }>({
    type: "SET_API_URL",
    apiUrl,
  })
  return resp?.success ?? false
}

// ============================================================
// Componentes auxiliares
// ============================================================

function ConfidenceBar({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence)
  const color = pct >= 80 ? "#e53e3e" : pct >= 60 ? "#dd6b20" : "#38a169"
  return (
    <div className="confidence-bar-wrap">
      <div
        className="confidence-bar-fill"
        style={{ width: pct + "%", backgroundColor: color }}
      />
      <span className="confidence-bar-label">{pct}%</span>
    </div>
  )
}

function sourceLabel(source: AnalysisSource): string {
  const labels: Record<AnalysisSource, string> = {
    blacklist: "Blacklist",
    whitelist: "Whitelist",
    cache: "Cache",
    api: "API",
    offline: "Offline",
  }
  return labels[source] ?? source
}

function modelSourceLabel(modelSource?: string): string {
  if (!modelSource || modelSource === "bert") return "BERT"
  if (modelSource === "cascade") return "BERT + CatBoost"
  return modelSource
}

function formatInferenceMs(ms?: number): string {
  if (ms === undefined || ms === null) return "-"
  if (ms < 1000) return `${Math.round(ms)}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

function formatTimestamp(ts: number): string {
  const d = new Date(ts)
  return d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })
}

function ApiStatusDot({ online }: { online: boolean }) {
  return (
    <span
      className={"api-dot " + (online ? "api-dot-online" : "api-dot-offline")}
      title={online ? "API online" : "API offline"}
    />
  )
}

function EmailUrlItem({ urlResult }: { urlResult: EmailUrlResultData }) {
  const cls = urlResult.isPhishing ? "email-url-phishing" : "email-url-legit"
  const truncUrl =
    urlResult.url.length > 45
      ? urlResult.url.slice(0, 45) + "..."
      : urlResult.url
  return (
    <div className={"email-url-item " + cls} title={urlResult.url}>
      <span className="email-url-text">{truncUrl}</span>
      <span className="email-url-conf">{Math.round(urlResult.confidence)}%</span>
    </div>
  )
}

// ============================================================
// Email Card Component
// ============================================================

function EmailCard({ email, expanded, onToggle }: {
  email: EmailResult
  expanded: boolean
  onToggle: () => void
}) {
  const sender = email.url.startsWith("email:") ? email.url.slice(6) : email.url
  const isPhishing = email.label === "PHISHING"
  const isSuspicious = email.label === "SUSPICIOUS"
  const isOffline = email.offline === true

  const cardClass = isOffline
    ? "email-card email-card-offline"
    : isPhishing
      ? "email-card email-card-phishing"
      : isSuspicious
        ? "email-card email-card-suspicious"
        : "email-card email-card-legit"

  const labelText = isOffline
    ? "OFFLINE"
    : isPhishing
      ? "PHISHING"
      : isSuspicious
        ? "SUSPEITO"
        : "SEGURO"

  const labelClass = isOffline
    ? "email-card-badge badge-offline"
    : isPhishing
      ? "email-card-badge badge-phishing"
      : isSuspicious
        ? "email-card-badge badge-suspicious"
        : "email-card-badge badge-legit"

  return (
    <div className={cardClass} onClick={onToggle}>
      <div className="email-card-header">
        <div className="email-card-info">
          <span className="email-card-sender" title={sender}>
            {sender.length > 35 ? sender.slice(0, 35) + "..." : sender}
          </span>
          <span className="email-card-time">{formatTimestamp(email.timestamp)}</span>
        </div>
        <span className={labelClass}>{labelText}</span>
      </div>

      {!isOffline && (
        <div className="email-card-bar">
          <ConfidenceBar confidence={email.confidence} />
        </div>
      )}

      {expanded && !isOffline && (
        <div className="email-card-details">
          {email.analysis && (
            <p className="email-card-analysis">{email.analysis}</p>
          )}

          {email.languageDetected && (
            <div className="email-card-meta">
              <span className="email-lang-badge">Idioma: {email.languageDetected}</span>
              {email.translated && (
                <span className="email-lang-badge email-lang-translated">Traduzido</span>
              )}
            </div>
          )}

          {email.urlResults && email.urlResults.length > 0 && (
            <div className="email-card-urls">
              <div className="email-card-urls-title">URLs encontradas:</div>
              {email.urlResults.map((ur, i) => (
                <EmailUrlItem key={i} urlResult={ur} />
              ))}
            </div>
          )}

          <div className="email-card-footer">
            <span>Tempo: {formatInferenceMs(email.inferenceMs)}</span>
            <span>Fonte: {sourceLabel(email.source)}</span>
          </div>
        </div>
      )}
    </div>
  )
}

// ============================================================
// URL Result Card (for non-email pages)
// ============================================================

function UrlResultCard({ result }: { result: TabResult }) {
  const isPhishing = result.isPhishing
  const isOffline = result.offline === true

  if (isOffline) {
    return (
      <div className="result-card result-offline">
        <div className="result-label">API Offline</div>
        <div className="result-url" title={result.url}>
          {result.url.length > 55 ? result.url.slice(0, 55) + "..." : result.url}
        </div>
      </div>
    )
  }

  return (
    <div className={"result-card " + (isPhishing ? "result-phishing" : "result-legit")}>
      <div className="result-label">
        {isPhishing ? "PHISHING" : "SEGURO"}
      </div>
      <div className="result-url" title={result.url}>
        {result.url.length > 55 ? result.url.slice(0, 55) + "..." : result.url}
      </div>

      <div className="section" style={{ margin: "8px 0 0" }}>
        <ConfidenceBar confidence={result.confidence} />
      </div>

      {result.analysis && (
        <p className="analysis-text" style={{ marginTop: 8 }}>{result.analysis}</p>
      )}

      <div className="metrics-row" style={{ margin: "8px 0 0" }}>
        <div className="metric">
          <span className="metric-label">Resultado</span>
          <span className="metric-value">{result.label}</span>
        </div>
        <div className="metric">
          <span className="metric-label">Fonte</span>
          <span className="metric-value">{sourceLabel(result.source)}</span>
        </div>
        <div className="metric">
          <span className="metric-label">Motor</span>
          <span className="metric-value">{modelSourceLabel(result.modelSource)}</span>
        </div>
        {result.inferenceMs !== undefined && (
          <div className="metric">
            <span className="metric-label">Tempo</span>
            <span className="metric-value">{formatInferenceMs(result.inferenceMs)}</span>
          </div>
        )}
      </div>
    </div>
  )
}

// ============================================================
// Popup principal
// ============================================================

export default function Popup() {
  const [result, setResult] = useState<TabResult | null>(null)
  const [emails, setEmails] = useState<EmailResult[]>([])
  const [health, setHealth] = useState<HealthInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [showSettings, setShowSettings] = useState(false)
  const [apiUrl, setApiUrl] = useState("http://localhost:8000")
  const [apiUrlSaved, setApiUrlSaved] = useState(false)
  const [cacheCleared, setCacheCleared] = useState(false)
  const [expandedEmail, setExpandedEmail] = useState<number | null>(null)
  const [isWebmail, setIsWebmail] = useState(false)

  useEffect(() => {
    init()
  }, [])

  async function init() {
    try {
      setLoading(true)
      setError("")

      const stored = await chrome.storage.sync.get("apiUrl")
      if (stored.apiUrl) setApiUrl(stored.apiUrl)

      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      if (!tab?.id) {
        setLoading(false)
        return
      }

      // Check if on webmail
      const url = tab.url ?? ""
      const webmail = url.includes("mail.google.com") ||
        url.includes("outlook.live.com") ||
        url.includes("outlook.office365.com") ||
        url.includes("outlook.office.com")
      setIsWebmail(webmail)

      // Fetch all data in parallel
      const [tabResult, emailHistory, apiHealth] = await Promise.all([
        fetchResult(tab.id),
        fetchEmailHistory(tab.id),
        fetchApiStatus(),
      ])

      // For webmail: don't show the URL result if it's an email result
      if (tabResult && !tabResult.url.startsWith("email:")) {
        setResult(tabResult)
      }
      setEmails(emailHistory)
      setHealth(apiHealth)

      // Auto-expand the first email if on webmail
      if (webmail && emailHistory.length > 0) {
        setExpandedEmail(0)
      }

      setLoading(false)
    } catch (err) {
      setError(String(err))
      setLoading(false)
    }
  }

  async function handleClearCache() {
    const ok = await clearCacheMsg()
    if (ok) {
      setCacheCleared(true)
      setTimeout(() => setCacheCleared(false), 2000)
    }
  }

  async function handleSaveApiUrl() {
    const ok = await setApiUrlMsg(apiUrl)
    if (ok) {
      setApiUrlSaved(true)
      setTimeout(() => setApiUrlSaved(false), 2000)
      const apiHealth = await fetchApiStatus()
      setHealth(apiHealth)
    }
  }

  // ---- Render: loading ----
  if (loading) {
    return (
      <div className="popup">
        <Header health={health} />
        <div className="center-content">
          <div className="spinner" />
          <p className="status-text">Carregando...</p>
        </div>
      </div>
    )
  }

  // ---- Render: error ----
  if (error) {
    return (
      <div className="popup">
        <Header health={health} />
        <div className="center-content">
          <p className="status-text">Erro: {error}</p>
          <button className="btn-retry" onClick={init}>Tentar novamente</button>
        </div>
      </div>
    )
  }

  const hasEmails = emails.length > 0
  const hasUrlResult = result !== null && !result.url.startsWith("email:")
  const hasNothing = !hasEmails && !hasUrlResult

  return (
    <div className="popup">
      <Header health={health} />

      {/* URL analysis (non-webmail pages) */}
      {hasUrlResult && !isWebmail && (
        <div style={{ padding: "0 16px" }}>
          <UrlResultCard result={result!} />
        </div>
      )}

      {/* Email analysis section */}
      {isWebmail && (
        <div className="email-section">
          <div className="email-section-header">
            <span className="email-section-title">Emails analisados</span>
            {hasEmails && (
              <span className="email-section-count">{emails.length}</span>
            )}
          </div>

          {hasEmails ? (
            <div className="email-cards-list">
              {emails.map((email, i) => (
                <EmailCard
                  key={email.url + email.timestamp}
                  email={email}
                  expanded={expandedEmail === i}
                  onToggle={() => setExpandedEmail(expandedEmail === i ? null : i)}
                />
              ))}
            </div>
          ) : (
            <div className="email-empty">
              <p className="status-text">Nenhum email analisado ainda.</p>
              <p className="status-text-sub">Abra um email para analisar.</p>
            </div>
          )}
        </div>
      )}

      {/* Empty state for non-webmail */}
      {hasNothing && !isWebmail && (
        <div className="center-content">
          <p className="status-text">Nenhuma analise para esta aba.</p>
          <p className="status-text-sub">Navegue para uma pagina para analisar.</p>
        </div>
      )}

      {/* Settings */}
      <SettingsPanel
        show={showSettings}
        onToggle={() => setShowSettings((s) => !s)}
        apiUrl={apiUrl}
        onApiUrlChange={setApiUrl}
        onSaveApiUrl={handleSaveApiUrl}
        apiUrlSaved={apiUrlSaved}
        onClearCache={handleClearCache}
        cacheCleared={cacheCleared}
      />
    </div>
  )
}

// ============================================================
// Settings Panel
// ============================================================

function SettingsPanel({
  show,
  onToggle,
  apiUrl,
  onApiUrlChange,
  onSaveApiUrl,
  apiUrlSaved,
  onClearCache,
  cacheCleared,
}: {
  show: boolean
  onToggle: () => void
  apiUrl: string
  onApiUrlChange: (v: string) => void
  onSaveApiUrl: () => void
  apiUrlSaved: boolean
  onClearCache: () => void
  cacheCleared: boolean
}) {
  return (
    <div className="settings-area">
      <div className="btn-row">
        <button className="btn-secondary" onClick={onToggle}>
          {show ? "Ocultar configuracoes" : "Configuracoes"}
        </button>
      </div>
      {show && (
        <div className="section">
          <div className="section-title">URL da API</div>
          <div className="api-url-row">
            <input
              className="api-url-input"
              type="text"
              value={apiUrl}
              onChange={(e) => onApiUrlChange(e.target.value)}
              placeholder="http://localhost:8000"
            />
            <button className="btn-save" onClick={onSaveApiUrl}>
              {apiUrlSaved ? "Salvo!" : "Salvar"}
            </button>
          </div>

          <div className="section-title" style={{ marginTop: 10 }}>Cache</div>
          <button className="btn-clear" onClick={onClearCache}>
            {cacheCleared ? "Cache limpo!" : "Limpar cache"}
          </button>
        </div>
      )}
    </div>
  )
}

// ============================================================
// Header
// ============================================================

function Header({ health }: { health: HealthInfo | null }) {
  const iconUrl = chrome.runtime.getURL("assets/Icone.png")
  return (
    <div className="header">
      <img src={iconUrl} alt="icone" className="header-icon" />
      <div className="header-info">
        <div className="header-title">Detector de Phishing</div>
        <div className="header-subtitle">DomURLs-BERT via API</div>
      </div>
      {health !== null && (
        <div className="header-status">
          <ApiStatusDot online={health.online} />
          <span className="header-status-text">
            {health.online ? "API online" : "API offline"}
          </span>
        </div>
      )}
    </div>
  )
}
