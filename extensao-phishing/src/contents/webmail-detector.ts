/**
 * Content Script — Webmail Email Phishing Detector
 *
 * Detects when the user OPENS an email in Gmail or Outlook,
 * extracts subject, body, sender, and URLs from the DOM,
 * and sends the data to the background script for phishing analysis.
 *
 * Detection strategy:
 *   Gmail:   URL hash changes to #inbox/<threadId> when an email is opened.
 *            We watch hashchange + poll for email body DOM to appear.
 *   Outlook: MutationObserver on reading pane with debounce.
 *
 * Hash-based deduplication prevents re-analyzing the same email.
 */

import type { PlasmoCSConfig } from "plasmo"

export const config: PlasmoCSConfig = {
  matches: [
    "*://mail.google.com/*",
    "*://outlook.live.com/*",
    "*://outlook.office365.com/*",
    "*://outlook.office.com/*"
  ],
  run_at: "document_idle"
}

// ============================================================
// State
// ============================================================

let lastEmailHash = ""
let debounceTimer: ReturnType<typeof setTimeout> | null = null
let pollTimer: ReturnType<typeof setTimeout> | null = null
const DEBOUNCE_MS = 800
const POLL_INTERVAL_MS = 300
const POLL_MAX_ATTEMPTS = 20 // 6 seconds max

// ============================================================
// Gmail: detect email open via URL hash
// ============================================================

function isGmail(): boolean {
  return window.location.hostname === "mail.google.com"
}

/**
 * Gmail URLs follow this pattern when an email is open:
 *   #inbox/FMfcgzQXKVPBgjDqjVhKNjZpmmxfJfLq
 *   #sent/FMfcgz...
 *   #label/Work/FMfcgz...
 *   #search/query/FMfcgz...
 *
 * Inbox/list views look like: #inbox, #sent, #label/Work (no thread ID)
 */
function isGmailEmailOpen(): boolean {
  const hash = window.location.hash
  if (!hash) return false
  // Thread IDs are long alphanumeric strings after the last /
  const parts = hash.split("/")
  const lastPart = parts[parts.length - 1]
  // Thread IDs are typically 20+ chars, purely alphanumeric
  return lastPart.length >= 15 && /^[A-Za-z0-9]+$/.test(lastPart)
}

/**
 * Poll for email DOM to appear after Gmail URL changes.
 * Gmail is a SPA — DOM may not be ready when hashchange fires.
 */
function pollForGmailEmail(attempts = 0): void {
  if (pollTimer) clearTimeout(pollTimer)

  if (attempts >= POLL_MAX_ATTEMPTS) return

  const emailData = extractGmailEmail()
  if (emailData && (emailData.subject || emailData.body)) {
    analyzeIfNew(emailData)
  } else {
    pollTimer = setTimeout(() => pollForGmailEmail(attempts + 1), POLL_INTERVAL_MS)
  }
}

// ============================================================
// DOM extraction — Gmail
// ============================================================

function extractGmailEmail(): {
  subject: string
  body: string
  sender: string
  urls: string[]
} | null {
  const subject =
    document.querySelector("h2.hP")?.textContent?.trim() ??
    document.querySelector("[data-thread-perm-id] h2")?.textContent?.trim() ??
    document.querySelector('[role="main"] h2')?.textContent?.trim() ??
    ""

  const bodyEl =
    document.querySelector("div.a3s.aiL") ??
    document.querySelector("[data-message-id] div.a3s") ??
    document.querySelector('[role="main"] [data-message-id]')

  if (!bodyEl && !subject) return null

  const body = bodyEl?.textContent?.trim() ?? ""

  const sender =
    document.querySelector("span.gD[email]")?.getAttribute("email") ??
    document.querySelector("[data-message-id] [email]")?.getAttribute("email") ??
    document.querySelector('[role="main"] [email]')?.getAttribute("email") ??
    ""

  const urls = extractUrls(bodyEl)

  return { subject, body, sender, urls }
}

// ============================================================
// DOM extraction — Outlook
// ============================================================

function extractOutlookEmail(): {
  subject: string
  body: string
  sender: string
  urls: string[]
} | null {
  const subject =
    document.querySelector('[role="main"] [role="heading"]')?.textContent?.trim() ??
    document.querySelector('[role="document"] [role="heading"]')?.textContent?.trim() ??
    ""

  const bodyEl =
    document.querySelector('div[role="document"]') ??
    document.querySelector('[role="main"] [role="document"]') ??
    document.querySelector('[role="main"] div[class*="Body"]')

  if (!bodyEl && !subject) return null

  const body = bodyEl?.textContent?.trim() ?? ""

  const sender =
    document.querySelector('[role="main"] [role="button"][aria-label*="@"]')
      ?.getAttribute("aria-label")?.match(/[\w.-]+@[\w.-]+/)?.[0] ??
    document.querySelector('[role="main"] span[email]')?.getAttribute("email") ??
    ""

  const urls = extractUrls(bodyEl)

  return { subject, body, sender, urls }
}

// ============================================================
// URL extraction helper
// ============================================================

function extractUrls(container: Element | null): string[] {
  if (!container) return []
  const anchors = container.querySelectorAll("a[href]")
  const urls: string[] = []
  for (const a of anchors) {
    const href = a.getAttribute("href")
    if (href && href.startsWith("http")) {
      urls.push(href)
    }
  }
  return [...new Set(urls)].slice(0, 10)
}

// ============================================================
// Hash for deduplication
// ============================================================

function hashEmail(subject: string, body: string, sender: string): string {
  const content = `${sender}|${subject}|${body.slice(0, 200)}`
  let hash = 0
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i)
    hash = ((hash << 5) - hash + char) | 0
  }
  return hash.toString(36)
}

// ============================================================
// Core: analyze only if new email
// ============================================================

function analyzeIfNew(emailData: {
  subject: string
  body: string
  sender: string
  urls: string[]
}): void {
  if (!emailData.subject && !emailData.body) return

  const hash = hashEmail(emailData.subject, emailData.body, emailData.sender)
  if (hash === lastEmailHash) return
  lastEmailHash = hash

  try {
    chrome.runtime.sendMessage({
      type: "ANALYZE_EMAIL",
      email: {
        subject: emailData.subject,
        body: emailData.body,
        sender: emailData.sender,
        urls_in_body: emailData.urls
      }
    })
  } catch {
    // Service worker may not be ready
  }
}

// ============================================================
// Outlook: MutationObserver with debounce
// ============================================================

function debouncedOutlookDetect(): void {
  if (debounceTimer) clearTimeout(debounceTimer)
  debounceTimer = setTimeout(() => {
    const emailData = extractOutlookEmail()
    if (emailData) analyzeIfNew(emailData)
  }, DEBOUNCE_MS)
}

// ============================================================
// Start
// ============================================================

if (isGmail()) {
  // Gmail: watch URL hash changes (user opens an email)
  window.addEventListener("hashchange", () => {
    if (isGmailEmailOpen()) {
      pollForGmailEmail()
    }
  })

  // Initial check (page loaded with email already open)
  if (isGmailEmailOpen()) {
    pollForGmailEmail()
  }
} else {
  // Outlook: MutationObserver (SPA, no hash-based navigation)
  const observer = new MutationObserver(() => {
    debouncedOutlookDetect()
  })

  observer.observe(document.body, {
    childList: true,
    subtree: true
  })

  // Initial check
  debouncedOutlookDetect()
}
