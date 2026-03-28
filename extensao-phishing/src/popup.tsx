/**
 * Popup da extensão — abre ao clicar no ícone na barra do navegador
 * Analisa a URL da aba atual usando o modelo GBM local via ONNX
 */

import { useEffect, useState } from "react"
import { loadModel, predictUrl, type PredictionResult } from "./utils/inference"
import { loadBlacklist, isBlacklisted, isWhitelisted } from "./utils/blacklist"
import { logger, type DecisionLog } from "./utils/logger"
import { FEATURE_ORDER } from "./utils/features"

import "./popup.css"

// ============================================================
// Tipos de estado
// ============================================================

type Status = "loading-model" | "analyzing" | "done" | "error"

// ============================================================
// Componentes auxiliares
// ============================================================

function ConfidenceBar({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence * 100)
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

function HistoryItem({ entry }: { entry: DecisionLog }) {
  const isPhishing = entry.isPhishing
  return (
    <div className={"history-item " + (isPhishing ? "history-phishing" : "history-legit")}>
      <span className="history-badge">{entry.label}</span>
      <span className="history-conf">{entry.confidencePct}</span>
      <span className="history-url" title={entry.url}>
        {entry.url.length > 45 ? entry.url.slice(0, 45) + "…" : entry.url}
      </span>
    </div>
  )
}

// ============================================================
// Popup principal
// ============================================================

export default function Popup() {
  const [status, setStatus]   = useState<Status>("loading-model")
  const [result, setResult]   = useState<PredictionResult | null>(null)
  const [currentUrl, setCurrentUrl] = useState<string>("")
  const [history, setHistory] = useState<DecisionLog[]>([])
  const [error, setError]     = useState<string>("")
  const [showHistory, setShowHistory] = useState(false)

  // Carrega o modelo e analisa a URL atual ao abrir o popup
  useEffect(() => {
    init()
  }, [])

  async function init() {
    try {
      setStatus("loading-model")

      // Pega a URL da aba ativa
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      const url = tab?.url ?? ""
      setCurrentUrl(url)

      // Carrega blacklist e modelo em paralelo
      await Promise.all([loadBlacklist(), loadModel()])

      setStatus("analyzing")

      // Checa whitelist → domínios conhecidos nunca passam pelo modelo
      let res: PredictionResult
      if (isWhitelisted(url)) {
        res = {
          url, isPhishing: false, confidence: 1.0, confidencePct: "100.00%",
          label: "LEGITIMO",
          analysis: "Domínio presente na whitelist de sites legítimos conhecidos. Análise do modelo ignorada.",
          inferenceMs: 0,
        }
      } else {
        // Checa blacklist antes de rodar inferência
        const blacklisted = isBlacklisted(url)
        if (blacklisted === true) {
          res = {
            url, isPhishing: true, confidence: 1.0, confidencePct: "100.00%",
            label: "PHISHING",
            analysis: "Domínio encontrado na blacklist de phishing/malware conhecidos.",
            inferenceMs: 0,
          }
        } else {
          res = await predictUrl(url)
        }
      }
      setResult(res as PredictionResult)
      setStatus("done")

      // Carrega histórico
      const hist = await logger.getDecisions()
      setHistory(hist.slice(-5).reverse())
    } catch (err) {
      setError(String(err))
      setStatus("error")
    }
  }

  async function reanalyze() {
    setResult(null)
    await init()
  }

  // ---- Render: carregando modelo ----
  if (status === "loading-model") {
    return (
      <div className="popup">
        <Header />
        <div className="center-content">
          <div className="spinner" />
          <p className="status-text">Carregando modelo...</p>
        </div>
      </div>
    )
  }

  // ---- Render: analisando ----
  if (status === "analyzing") {
    return (
      <div className="popup">
        <Header />
        <div className="center-content">
          <div className="spinner" />
          <p className="status-text">Analisando URL...</p>
          <p className="url-text" title={currentUrl}>
            {currentUrl.length > 50 ? currentUrl.slice(0, 50) + "…" : currentUrl}
          </p>
        </div>
      </div>
    )
  }

  // ---- Render: erro ----
  if (status === "error") {
    return (
      <div className="popup">
        <Header />
        <div className="center-content">
          <p className="error-icon">⚠️</p>
          <p className="status-text">Erro ao analisar</p>
          <p className="error-text">{error}</p>
          <button className="btn-retry" onClick={reanalyze}>Tentar novamente</button>
        </div>
      </div>
    )
  }

  // ---- Render: resultado ----
  const isPhishing = result!.isPhishing
  return (
    <div className="popup">
      <Header />

      {/* Resultado principal */}
      <div className={"result-card " + (isPhishing ? "result-phishing" : "result-legit")}>
        <div className="result-label">{isPhishing ? "⚠ PHISHING" : "✓ LEGÍTIMO"}</div>
        <div className="result-url" title={currentUrl}>
          {currentUrl.length > 55 ? currentUrl.slice(0, 55) + "…" : currentUrl}
        </div>
      </div>

      {/* Confiança */}
      <div className="section">
        <div className="section-title">Confiança do modelo</div>
        <ConfidenceBar confidence={result!.confidence} />
      </div>

      {/* Análise (texto igual ao campo analysis da phishing-api) */}
      <div className="section">
        <div className="section-title">Análise</div>
        <p className="analysis-text">{result!.analysis}</p>
      </div>

      {/* Métricas */}
      <div className="metrics-row">
        <div className="metric">
          <span className="metric-label">Inferência</span>
          <span className="metric-value">{result!.inferenceMs}ms</span>
        </div>
        <div className="metric">
          <span className="metric-label">Features</span>
          <span className="metric-value">{FEATURE_ORDER.length}</span>
        </div>
        <div className="metric">
          <span className="metric-label">Modelo</span>
          <span className="metric-value">GBM local</span>
        </div>
      </div>

      {/* Botões */}
      <div className="btn-row">
        <button className="btn-secondary" onClick={reanalyze}>↺ Reanalisar</button>
        <button
          className="btn-secondary"
          onClick={() => setShowHistory(h => !h)}>
          {showHistory ? "Ocultar histórico" : "Ver histórico"}
        </button>
      </div>

      {/* Histórico de decisões */}
      {showHistory && (
        <div className="section">
          <div className="section-title">Últimas análises</div>
          {history.length === 0 ? (
            <p className="empty-history">Nenhuma análise anterior.</p>
          ) : (
            history.map((entry, i) => <HistoryItem key={i} entry={entry} />)
          )}
          <button
            className="btn-clear"
            onClick={async () => {
              await logger.clearLogs()
              setHistory([])
            }}>
            Limpar histórico
          </button>
        </div>
      )}
    </div>
  )
}

function Header() {
  const iconUrl = chrome.runtime.getURL("assets/Icone.png")
  return (
    <div className="header">
      <img src={iconUrl} alt="ícone" className="header-icon" />
      <div>
        <div className="header-title">Detector de Phishing</div>
        <div className="header-subtitle">Modelo GBM local • sem envio de dados</div>
      </div>
    </div>
  )
}
