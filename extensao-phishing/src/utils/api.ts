/**
 * HTTP client module for communicating with the DomURLs-BERT FastAPI backend.
 */

import type { ClientFeatures } from "./clientFeatures"
import { getIdentity } from "./identity"

const DEFAULT_API_URL = "http://localhost:8000"
const TIMEOUT_MS = 5000

export interface ApiResponse {
  url: string
  is_phishing: boolean
  confidence: number
  label: string
  analysis: string
  inference_ms: number
  source: string
}

export interface ApiOfflineResponse {
  offline: true
}

export interface EmailUrlResult {
  url: string
  is_phishing: boolean
  confidence: number
  label: string
}

export interface EmailAnalysisResponse {
  is_phishing: boolean
  confidence: number
  label: string
  analysis: string
  inference_ms: number
  email_score: number
  url_results: EmailUrlResult[]
  language_detected: string
  translated: boolean
}

export interface HealthResponse {
  status: string
  model_loaded: boolean
  device: string
  version: string
}

export interface HealthOfflineResponse {
  offline: true
}

async function getApiUrl(): Promise<string> {
  try {
    // Prefer managed policy endpoint (set by IT admin) over user-configured value.
    const identity = await getIdentity()
    if (identity.apiEndpoint) return identity.apiEndpoint

    const data = await chrome.storage.sync.get("apiUrl")
    return data.apiUrl || DEFAULT_API_URL
  } catch {
    return DEFAULT_API_URL
  }
}

/**
 * Build auth/identity headers from the cached identity.
 * X-API-Key is sent when an API key is configured (enterprise only).
 * X-User-Email is sent when a user email is configured (for event attribution).
 */
async function getAuthHeaders(): Promise<Record<string, string>> {
  try {
    const identity = await getIdentity()
    const headers: Record<string, string> = {}
    if (identity.apiKey) headers["X-API-Key"] = identity.apiKey
    if (identity.userEmail) headers["X-User-Email"] = identity.userEmail
    return headers
  } catch {
    return {}
  }
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit
): Promise<Response> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    })
    return response
  } finally {
    clearTimeout(timer)
  }
}

export async function analyzeUrl(
  url: string,
  features: ClientFeatures
): Promise<ApiResponse | ApiOfflineResponse> {
  try {
    const [apiUrl, authHeaders] = await Promise.all([getApiUrl(), getAuthHeaders()])
    const response = await fetchWithTimeout(`${apiUrl}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify({ url, client_features: features })
    })
    if (!response.ok) {
      return { offline: true }
    }
    return (await response.json()) as ApiResponse
  } catch {
    return { offline: true }
  }
}

export async function analyzeEmail(email: {
  subject: string
  body: string
  sender: string
  urls_in_body: string[]
}): Promise<EmailAnalysisResponse | ApiOfflineResponse> {
  try {
    const [apiUrl, authHeaders] = await Promise.all([getApiUrl(), getAuthHeaders()])
    const response = await fetchWithTimeout(`${apiUrl}/analyze-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify(email)
    })
    if (!response.ok) {
      return { offline: true }
    }
    return (await response.json()) as EmailAnalysisResponse
  } catch {
    return { offline: true }
  }
}

export async function checkHealth(): Promise<
  HealthResponse | HealthOfflineResponse
> {
  try {
    const [apiUrl, authHeaders] = await Promise.all([getApiUrl(), getAuthHeaders()])
    const response = await fetchWithTimeout(`${apiUrl}/health`, {
      method: "GET",
      headers: authHeaders
    })
    if (!response.ok) {
      return { offline: true }
    }
    return (await response.json()) as HealthResponse
  } catch {
    return { offline: true }
  }
}
