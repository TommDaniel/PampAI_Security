/**
 * Logger estruturado para a extensão
 * Espelha o padrão usado na phishing-api (app.py):
 *   logger.info(f"Resposta: modelo - Phishing/Legítimo (confiança)")
 *
 * Persiste logs no chrome.storage.local para consulta posterior
 * (equivalente a um arquivo de log — extensões não têm sistema de arquivos)
 */

export type LogLevel = "INFO" | "WARN" | "ERROR"

export interface LogEntry {
  timestamp: string
  level: LogLevel
  message: string
  data?: Record<string, unknown>
}

export interface DecisionLog {
  timestamp: string
  url: string
  isPhishing: boolean
  confidence: number          // probabilidade de phishing (0-1)
  confidencePct: string       // ex: "87.43%"
  label: "PHISHING" | "LEGITIMO"
  analysis: string            // texto explicando a decisão (igual ao campo analysis da API)
  featuresUsed: number        // quantas features foram extraídas
  inferenceMs: number         // tempo de inferência em ms
}

const MAX_LOGS = 500  // limite para não estourar o storage

class Logger {
  private prefix = "[Phishing Detector]"

  private format(level: LogLevel, message: string): string {
    const ts = new Date().toISOString()
    return `${ts} [${level}] ${this.prefix} ${message}`
  }

  info(message: string, data?: Record<string, unknown>) {
    console.log(this.format("INFO", message), data ?? "")
    this.persist({ timestamp: new Date().toISOString(), level: "INFO", message, data })
  }

  warn(message: string, data?: Record<string, unknown>) {
    console.warn(this.format("WARN", message), data ?? "")
    this.persist({ timestamp: new Date().toISOString(), level: "WARN", message, data })
  }

  error(message: string, data?: Record<string, unknown>) {
    console.error(this.format("ERROR", message), data ?? "")
    this.persist({ timestamp: new Date().toISOString(), level: "ERROR", message, data })
  }

  /** Loga a decisão do modelo — equivalente ao logger.info da API após /predict */
  logDecision(entry: DecisionLog) {
    const msg =
      `Resposta: GBM - ${entry.label} (${entry.confidencePct}) | ` +
      `URL: ${entry.url} | Inferência: ${entry.inferenceMs}ms`

    this.info(msg)
    this.persistDecision(entry)
  }

  private async persist(entry: LogEntry) {
    try {
      const { logs = [] } = await chrome.storage.local.get("logs")
      logs.push(entry)
      if (logs.length > MAX_LOGS) logs.splice(0, logs.length - MAX_LOGS)
      await chrome.storage.local.set({ logs })
    } catch {
      // storage pode não estar disponível em alguns contextos (ex: content script isolado)
    }
  }

  private async persistDecision(entry: DecisionLog) {
    try {
      const { decisions = [] } = await chrome.storage.local.get("decisions")
      decisions.push(entry)
      if (decisions.length > MAX_LOGS) decisions.splice(0, decisions.length - MAX_LOGS)
      await chrome.storage.local.set({ decisions })
    } catch {}
  }

  /** Recupera os logs de decisão salvos (para exibir no popup ou exportar) */
  async getDecisions(): Promise<DecisionLog[]> {
    const { decisions = [] } = await chrome.storage.local.get("decisions")
    return decisions
  }

  /** Recupera os logs gerais */
  async getLogs(): Promise<LogEntry[]> {
    const { logs = [] } = await chrome.storage.local.get("logs")
    return logs
  }

  /** Limpa todos os logs */
  async clearLogs() {
    await chrome.storage.local.remove(["logs", "decisions"])
    this.info("Logs limpos pelo usuário")
  }
}

export const logger = new Logger()
