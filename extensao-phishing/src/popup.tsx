/**
 * Popup da extensão — abre ao clicar no ícone na barra do navegador
 * Mostra resultado da análise via API DomURLs-BERT, status da API,
 * e controles para cache e configuração de URL da API.
 */

import { useEffect, useState } from "react"
import type { AnalysisResult, AnalysisSource } from "./background"

import "./popup.css"

// ============================================================
// Tipos
// ============================================================

interface TabResult extends AnalysisResult {
  url: string
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

function ApiStatusDot({ online }: { online: boolean }) {
  return (
    <span
      className={"api-dot " + (online ? "api-dot-online" : "api-dot-offline")}
      title={online ? "API online" : "API offline"}
    />
  )
}

// ============================================================
// Popup principal
// ============================================================

export default function Popup() {
  const [result, setResult] = useState<TabResult | null>(null)
  const [health, setHealth] = useState<HealthInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [showSettings, setShowSettings] = useState(false)
  const [apiUrl, setApiUrl] = useState("http://localhost:8000")
  const [apiUrlSaved, setApiUrlSaved] = useState(false)
  const [cacheCleared, setCacheCleared] = useState(false)

  useEffect(() => {
    init()
  }, [])

  async function init() {
    try {
      setLoading(true)
      setError("")

      // Load saved API URL
      const stored = await chrome.storage.sync.get("apiUrl")
      if (stored.apiUrl) setApiUrl(stored.apiUrl)

      // Get current tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      if (!tab?.id) {
        setLoading(false)
        return
      }

      // Fetch result and API status in parallel
      const [tabResult, apiHealth] = await Promise.all([
        fetchResult(tab.id),
        fetchApiStatus(),
      ])

      setResult(tabResult)
      setHealth(apiHealth)
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
      // Re-check API status with new URL
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
          <p className="status-text">Carregando resultado...</p>
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
          <p className="error-icon">⚠️</p>
          <p className="status-text">Erro</p>
          <p className="error-text">{error}</p>
          <button className="btn-retry" onClick={init}>Tentar novamente</button>
        </div>
      </div>
    )
  }

  // ---- Render: no result yet ----
  if (!result) {
    return (
      <div className="popup">
        <Header health={health} />
        <div className="center-content">
          <p className="status-text">Nenhuma análise para esta aba.</p>
          <p className="status-text-sub">Navegue para uma página para analisar.</p>
        </div>
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

  // ---- Render: result ----
  const isPhishing = result.isPhishing
  const isOffline = result.offline === true

  return (
    <div className="popup">
      <Header health={health} />

      {/* Card de resultado */}
      {isOffline ? (
        <div className="result-card result-offline">
          <div className="result-label">API Offline</div>
          <div className="result-url" title={result.url}>
            {result.url.length > 55 ? result.url.slice(0, 55) + "…" : result.url}
          </div>
        </div>
      ) : (
        <div className={"result-card " + (isPhishing ? "result-phishing" : "result-legit")}>
          <div className="result-label">
            {isPhishing ? "⚠ PHISHING" : "✓ LEGÍTIMO"}
          </div>
          <div className="result-url" title={result.url}>
            {result.url.length > 55 ? result.url.slice(0, 55) + "…" : result.url}
          </div>
        </div>
      )}

      {/* Confiança */}
      {!isOffline && (
        <div className="section">
          <div className="section-title">Confiança</div>
          <ConfidenceBar confidence={result.confidence} />
        </div>
      )}

      {/* Análise */}
      {!isOffline && result.analysis && (
        <div className="section">
          <div className="section-title">Análise</div>
          <p className="analysis-text">{result.analysis}</p>
        </div>
      )}

      {/* Métricas */}
      <div className="metrics-row">
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
          <span className="metric-value">DomURLs-BERT</span>
        </div>
      </div>

      {/* Settings panel */}
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
          {show ? "Ocultar configurações" : "⚙ Configurações"}
        </button>
      </div>
      {show && (
        <div className="section">
          {/* API URL */}
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
              {apiUrlSaved ? "✓ Salvo" : "Salvar"}
            </button>
          </div>

          {/* Clear cache */}
          <div className="section-title" style={{ marginTop: 10 }}>Cache</div>
          <button className="btn-clear" onClick={onClearCache}>
            {cacheCleared ? "✓ Cache limpo" : "Limpar cache"}
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
      <img src={iconUrl} alt="ícone" className="header-icon" />
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
