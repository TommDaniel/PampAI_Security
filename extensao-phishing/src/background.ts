/**
 * Service Worker (Background) — MV3
 *
 * Responsabilidades:
 *   - Carrega a blacklist ao instalar/iniciar a extensão
 *   - Checa blacklist (O(1)) para o content script — resposta instantânea
 *   - Inferência ONNX é feita no popup (contexto de página real, sem restrições de service worker)
 *
 * Fluxo content script:
 *   detector.ts → ANALYZE_URL → background → blacklist hit? → responde
 *
 * Fluxo popup:
 *   popup.tsx → roda inferência ONNX diretamente no contexto do popup
 */

import type { PredictionResult } from "./utils/inference"
import { loadBlacklist, isBlacklisted } from "./utils/blacklist"
import { logger } from "./utils/logger"

const HIGH_CONFIDENCE_THRESHOLD = 0.85

// ============================================================
// Inicialização — blacklist
// ============================================================

loadBlacklist()
  .then(() => logger.info("Service worker iniciado — blacklist pronta"))
  .catch((err) => logger.error("Falha ao carregar blacklist", { error: String(err) }))

chrome.runtime.onInstalled.addListener(() => {
  loadBlacklist()
    .then(() => logger.info("Extensão instalada/atualizada — blacklist recarregada"))
    .catch((err) => logger.error("Erro no onInstalled", { error: String(err) }))
})

// ============================================================
// Listener de mensagens
// ============================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // ---- ANALYZE_URL: content script pede análise ----
  if (message.type === "ANALYZE_URL") {
    const url: string = message.url

    logger.info("Background recebeu requisição", { url, tabId: sender.tab?.id })

    const blacklisted = isBlacklisted(url)

    if (blacklisted === true) {
      logger.info("Blacklist hit", { url })

      const result: PredictionResult = {
        url,
        isPhishing:    true,
        confidence:    1.0,
        confidencePct: "100.00%",
        label:         "PHISHING",
        analysis:      "Domínio encontrado na blacklist de phishing/malware conhecidos.",
        inferenceMs:   0,
      }

      sendResponse({ success: true, result })
      emitNotification(result)
      return true
    }

    // Não está na blacklist — content script não mostra banner (inferência é feita no popup)
    sendResponse({ success: true, result: null })
    return true
  }

  // ---- GET_LAST_RESULT: popup pede o último resultado cacheado ----
  if (message.type === "GET_LAST_RESULT") {
    chrome.storage.session
      .get("lastResult")
      .then((data) => sendResponse({ result: data.lastResult ?? null }))
      .catch(() => sendResponse({ result: null }))
    return true
  }
})

// ============================================================
// Helpers
// ============================================================

function emitNotification(result: PredictionResult) {
  chrome.notifications.create({
    type:     "basic",
    iconUrl:  "assets/Icone.png",
    title:    "Phishing detectado",
    message:  result.analysis,
    priority: 2,
  })
}
