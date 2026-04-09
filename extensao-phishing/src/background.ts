/**
 * Service Worker (Background) — MV3
 *
 * Orchestrates the anti-phishing analysis pipeline:
 *   whitelist (instant) -> blacklist (instant) -> cache (instant) -> API call
 *
 * Results are stored per tab in chrome.storage.session.
 * Cache is stored in chrome.storage.local (survives SW restarts).
 */

import type { ClientFeatures } from "./utils/clientFeatures"
import type { ApiResponse } from "./utils/api"
import { loadBlacklist, isBlacklisted, isWhitelisted } from "./utils/blacklist"
import { getCached, setCached, clearCache } from "./utils/cache"
import { analyzeUrl, analyzeEmail, checkHealth } from "./utils/api"
import type { EmailAnalysisResponse } from "./utils/api"
import { logger } from "./utils/logger"
import type { DecisionLog } from "./utils/logger"
import { initIdentity, onIdentityChanged } from "./utils/identity"

export type AnalysisSource = "blacklist" | "whitelist" | "cache" | "api" | "offline"

export interface EmailUrlResultData {
  url: string
  isPhishing: boolean
  confidence: number
  label: string
}

export interface AnalysisResult {
  isPhishing: boolean
  confidence: number
  label: string
  analysis: string
  source: AnalysisSource
  inferenceMs?: number
  modelSource?: string
  offline?: boolean
  // Email-specific fields (present when url starts with "email:")
  emailScore?: number
  urlResults?: EmailUrlResultData[]
  languageDetected?: string
  translated?: boolean
}

// ============================================================
// Initialization — blacklist
// ============================================================

loadBlacklist()
  .then(() => logger.info("Service worker started — blacklist ready"))
  .catch((err) => logger.error("Failed to load blacklist", { error: String(err) }))

// Load enterprise identity from managed storage and cache locally.
initIdentity()
  .then((id) =>
    logger.info("Identity loaded", {
      orgId: id.orgId ?? "(none)",
      userEmail: id.userEmail ?? "(none)",
      hasApiEndpoint: id.apiEndpoint !== null
    })
  )
  .catch((err) => logger.error("Failed to load identity", { error: String(err) }))

// Re-sync identity whenever IT admin updates the managed policy at runtime.
onIdentityChanged((id) => {
  logger.info("Managed policy updated — identity refreshed", {
    orgId: id.orgId ?? "(none)",
    userEmail: id.userEmail ?? "(none)"
  })
})

chrome.runtime.onInstalled.addListener(() => {
  loadBlacklist()
    .then(() => logger.info("Extension installed/updated — blacklist reloaded"))
    .catch((err) => logger.error("Error on onInstalled", { error: String(err) }))
  initIdentity().catch((err) =>
    logger.error("Error loading identity on install", { error: String(err) })
  )
})

// ============================================================
// Analysis pipeline
// ============================================================

async function analyzePipeline(
  url: string,
  features: ClientFeatures
): Promise<AnalysisResult> {
  // 1. Whitelist check (instant)
  if (isWhitelisted(url)) {
    logger.info("Whitelist hit", { url })
    return {
      isPhishing: false,
      confidence: 100,
      label: "LEGITIMATE",
      analysis: "Known legitimate domain (whitelist).",
      source: "whitelist"
    }
  }

  // 2. Blacklist check (instant)
  const blacklisted = isBlacklisted(url)
  if (blacklisted === true) {
    logger.info("Blacklist hit", { url })
    return {
      isPhishing: true,
      confidence: 100,
      label: "PHISHING",
      analysis: "Domain found in known phishing/malware blacklist.",
      source: "blacklist"
    }
  }

  // 3. Cache check (instant)
  const cached = await getCached(url)
  if (cached) {
    logger.info("Cache hit", { url })
    return {
      isPhishing: cached.isPhishing,
      confidence: cached.confidence,
      label: cached.label,
      analysis: cached.analysis,
      source: "cache"
    }
  }

  // 4. API call
  const apiResult = await analyzeUrl(url, features)

  if ("offline" in apiResult) {
    logger.warn("API offline — fail-open", { url })
    return {
      isPhishing: false,
      confidence: 0,
      label: "UNKNOWN",
      analysis: "API unavailable. Fail-open: not blocking.",
      source: "offline",
      offline: true
    }
  }

  const response = apiResult as ApiResponse

  // Store in cache
  await setCached(url, {
    isPhishing: response.is_phishing,
    confidence: response.confidence,
    label: response.label,
    analysis: response.analysis,
    timestamp: Date.now()
  })

  logger.info("API result", {
    url,
    label: response.label,
    confidence: response.confidence,
    inference_ms: response.inference_ms,
    model_source: response.source
  })

  return {
    isPhishing: response.is_phishing,
    confidence: response.confidence,
    label: response.label,
    analysis: response.analysis,
    source: "api",
    inferenceMs: response.inference_ms,
    modelSource: response.source ?? "bert"
  }
}

// ============================================================
// Store result per tab
// ============================================================

async function storeTabResult(
  tabId: number,
  result: AnalysisResult & { url: string }
): Promise<void> {
  try {
    const { tabResults = {} } = await chrome.storage.session.get("tabResults")
    tabResults[tabId] = result
    await chrome.storage.session.set({ tabResults })
  } catch {
    // session storage may not be available
  }
}

async function getTabResult(
  tabId: number
): Promise<(AnalysisResult & { url: string }) | null> {
  try {
    const { tabResults = {} } = await chrome.storage.session.get("tabResults")
    return tabResults[tabId] ?? null
  } catch {
    return null
  }
}

// ============================================================
// Store email analysis history per tab
// ============================================================

const MAX_EMAIL_HISTORY = 20

async function storeEmailResult(
  tabId: number,
  result: AnalysisResult & { url: string; timestamp: number }
): Promise<void> {
  try {
    const { emailHistory = {} } = await chrome.storage.session.get("emailHistory")
    const history: Array<AnalysisResult & { url: string; timestamp: number }> = emailHistory[tabId] ?? []

    // Deduplicate by sender (url = "email:sender")
    const existing = history.findIndex((h) => h.url === result.url)
    if (existing !== -1) {
      history[existing] = result // update existing
    } else {
      history.unshift(result) // newest first
    }

    // Limit history
    emailHistory[tabId] = history.slice(0, MAX_EMAIL_HISTORY)
    await chrome.storage.session.set({ emailHistory })
  } catch {
    // session storage may not be available
  }
}

async function getEmailHistory(
  tabId: number
): Promise<Array<AnalysisResult & { url: string; timestamp: number }>> {
  try {
    const { emailHistory = {} } = await chrome.storage.session.get("emailHistory")
    return emailHistory[tabId] ?? []
  } catch {
    return []
  }
}

// ============================================================
// Badge — visual indicator on extension icon
// ============================================================

function updateBadge(tabId: number, result: AnalysisResult): void {
  if (result.offline) {
    chrome.action.setBadgeText({ text: "", tabId })
    return
  }

  if (result.isPhishing) {
    chrome.action.setBadgeText({ text: "!", tabId })
    chrome.action.setBadgeBackgroundColor({ color: "#c53030", tabId })
  } else if (result.confidence < 70) {
    chrome.action.setBadgeText({ text: "?", tabId })
    chrome.action.setBadgeBackgroundColor({ color: "#d69e2e", tabId })
  } else {
    chrome.action.setBadgeText({ text: "\u2713", tabId })
    chrome.action.setBadgeBackgroundColor({ color: "#38a169", tabId })
  }
}

// ============================================================
// Message listener
// ============================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // ---- ANALYZE_URL: content script requests analysis ----
  if (message.type === "ANALYZE_URL") {
    const url: string = message.url
    const features: ClientFeatures = message.features
    const tabId = sender.tab?.id

    logger.info("Analysis requested", { url, tabId })

    analyzePipeline(url, features)
      .then(async (result) => {
        if (tabId !== undefined) {
          await storeTabResult(tabId, { ...result, url })
          updateBadge(tabId, result)
        }

        if (result.isPhishing) {
          emitNotification(result)
        }

        logger.logDecision({
          timestamp: new Date().toISOString(),
          url,
          isPhishing: result.isPhishing,
          confidence: result.confidence,
          confidencePct: `${result.confidence.toFixed(1)}%`,
          label: result.isPhishing ? "PHISHING" : "LEGITIMO",
          analysis: result.analysis,
          source: result.source,
          inferenceMs: result.inferenceMs ?? 0
        } satisfies DecisionLog)

        sendResponse({ success: true, result })
      })
      .catch((err) => {
        logger.error("Analysis failed", { url, error: String(err) })
        sendResponse({
          success: true,
          result: {
            isPhishing: false,
            confidence: 0,
            label: "UNKNOWN",
            analysis: "Analysis failed. Fail-open: not blocking.",
            source: "offline" as AnalysisSource,
            offline: true
          }
        })
      })

    return true // async response
  }

  // ---- ANALYZE_EMAIL: webmail content script requests email analysis ----
  if (message.type === "ANALYZE_EMAIL") {
    const email = message.email as {
      subject: string
      body: string
      sender: string
      urls_in_body: string[]
    }
    const tabId = sender.tab?.id

    logger.info("Email analysis requested", { sender: email.sender, tabId })

    analyzeEmail(email)
      .then(async (apiResult) => {
        if ("offline" in apiResult) {
          const offlineResult: AnalysisResult & { url: string; timestamp: number } = {
            isPhishing: false,
            confidence: 0,
            label: "UNKNOWN",
            analysis: "API unavailable. Fail-open: not blocking.",
            source: "offline",
            offline: true,
            url: "email:" + email.sender,
            timestamp: Date.now()
          }
          if (tabId !== undefined) {
            await storeTabResult(tabId, offlineResult)
            await storeEmailResult(tabId, offlineResult)
            updateBadge(tabId, offlineResult)
          }

          logger.logDecision({
            timestamp: new Date().toISOString(),
            url: "email:" + email.sender,
            isPhishing: false,
            confidence: 0,
            confidencePct: "0.0%",
            label: "LEGITIMO",
            analysis: offlineResult.analysis,
            source: "offline",
            inferenceMs: 0
          } satisfies DecisionLog)

          sendResponse({ success: true, result: offlineResult })
          return
        }

        const response = apiResult as EmailAnalysisResponse
        const result: AnalysisResult & { url: string; timestamp: number } = {
          isPhishing: response.is_phishing,
          confidence: response.confidence,
          label: response.label,
          analysis: response.analysis,
          source: "api",
          inferenceMs: response.inference_ms,
          url: "email:" + email.sender,
          emailScore: response.email_score,
          urlResults: response.url_results.map((ur) => ({
            url: ur.url,
            isPhishing: ur.is_phishing,
            confidence: ur.confidence,
            label: ur.label
          })),
          languageDetected: response.language_detected,
          translated: response.translated,
          timestamp: Date.now()
        }

        if (tabId !== undefined) {
          await storeTabResult(tabId, result)
          await storeEmailResult(tabId, result)
          updateBadge(tabId, result)
        }

        if (result.isPhishing) {
          emitNotification(result)
        }

        logger.logDecision({
          timestamp: new Date().toISOString(),
          url: "email:" + email.sender,
          isPhishing: result.isPhishing,
          confidence: result.confidence,
          confidencePct: `${result.confidence.toFixed(1)}%`,
          label: result.isPhishing ? "PHISHING" : "LEGITIMO",
          analysis: result.analysis,
          source: result.source,
          inferenceMs: result.inferenceMs ?? 0
        } satisfies DecisionLog)

        sendResponse({ success: true, result })
      })
      .catch((err) => {
        logger.error("Email analysis failed", { error: String(err) })
        sendResponse({
          success: true,
          result: {
            isPhishing: false,
            confidence: 0,
            label: "UNKNOWN",
            analysis: "Email analysis failed. Fail-open: not blocking.",
            source: "offline" as AnalysisSource,
            offline: true
          }
        })
      })

    return true // async response
  }

  // ---- GET_RESULT: popup requests the result for current tab ----
  if (message.type === "GET_RESULT") {
    const tabId: number | undefined = message.tabId
    if (tabId === undefined) {
      sendResponse({ result: null })
      return true
    }

    getTabResult(tabId)
      .then((result) => sendResponse({ result }))
      .catch(() => sendResponse({ result: null }))

    return true
  }

  // ---- GET_API_STATUS: popup checks API health ----
  if (message.type === "GET_API_STATUS") {
    checkHealth()
      .then((health) => sendResponse({ health }))
      .catch(() => sendResponse({ health: { offline: true } }))

    return true
  }

  // ---- GET_EMAIL_HISTORY: popup requests email analysis history ----
  if (message.type === "GET_EMAIL_HISTORY") {
    const tabId: number | undefined = message.tabId
    if (tabId === undefined) {
      sendResponse({ emails: [] })
      return true
    }

    getEmailHistory(tabId)
      .then((emails) => sendResponse({ emails }))
      .catch(() => sendResponse({ emails: [] }))

    return true
  }

  // ---- CLEAR_CACHE: popup requests cache clear ----
  if (message.type === "CLEAR_CACHE") {
    clearCache()
      .then(() => {
        logger.info("Cache cleared by user")
        sendResponse({ success: true })
      })
      .catch(() => sendResponse({ success: false }))

    return true
  }

  // ---- SET_API_URL: popup updates API URL ----
  if (message.type === "SET_API_URL") {
    const apiUrl: string = message.apiUrl
    chrome.storage.sync
      .set({ apiUrl })
      .then(() => {
        logger.info("API URL updated", { apiUrl })
        sendResponse({ success: true })
      })
      .catch(() => sendResponse({ success: false }))

    return true
  }
})

// ============================================================
// Helpers
// ============================================================

function emitNotification(result: AnalysisResult) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: chrome.runtime.getURL("assets/Icone.png"),
    title: "Phishing detectado",
    message: result.analysis,
    priority: 2
  })
}
