/**
 * Content Script — Webmail Email Phishing Detector
 *
 * Detects when the user opens an email in Gmail or Outlook webmail,
 * extracts subject, body, sender, and URLs from the DOM,
 * and sends the data to the background script for phishing analysis.
 *
 * Uses MutationObserver for SPA navigation detection with debounce
 * and hash-based deduplication to avoid re-analyzing the same email.
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
const DEBOUNCE_MS = 500

// ============================================================
// DOM extraction — Gmail
// ============================================================

function extractGmailEmail(): {
  subject: string
  body: string
  sender: string
  urls: string[]
} | null {
  // Subject: specific selectors first, then fallback
  const subject =
    document.querySelector("h2.hP")?.textContent?.trim() ??
    document.querySelector("[data-thread-perm-id] h2")?.textContent?.trim() ??
    document.querySelector('[role="main"] h2')?.textContent?.trim() ??
    ""

  // Body: specific Gmail class, then fallback
  const bodyEl =
    document.querySelector("div.a3s.aiL") ??
    document.querySelector("[data-message-id] div.a3s") ??
    document.querySelector('[role="main"] [data-message-id]')

  if (!bodyEl && !subject) return null

  const body = bodyEl?.textContent?.trim() ?? ""

  // Sender: specific Gmail attribute, then fallback
  const sender =
    document.querySelector("span.gD[email]")?.getAttribute("email") ??
    document.querySelector("[data-message-id] [email]")?.getAttribute("email") ??
    document.querySelector('[role="main"] [email]')?.getAttribute("email") ??
    ""

  // Extract URLs from body element
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
  // Subject
  const subject =
    document.querySelector('[role="main"] [role="heading"]')?.textContent?.trim() ??
    document.querySelector('[role="document"] [role="heading"]')?.textContent?.trim() ??
    ""

  // Body
  const bodyEl =
    document.querySelector('div[role="document"]') ??
    document.querySelector('[role="main"] [role="document"]') ??
    document.querySelector('[role="main"] div[class*="Body"]')

  if (!bodyEl && !subject) return null

  const body = bodyEl?.textContent?.trim() ?? ""

  // Sender
  const sender =
    document.querySelector('[role="main"] [role="button"][aria-label*="@"]')?.getAttribute("aria-label")?.match(/[\w.-]+@[\w.-]+/)?.[0] ??
    document.querySelector('[role="main"] span[email]')?.getAttribute("email") ??
    ""

  // Extract URLs from body element
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
  // Deduplicate and limit to 10
  return [...new Set(urls)].slice(0, 10)
}

// ============================================================
// Hash for deduplication
// ============================================================

function hashEmail(subject: string, body: string, sender: string): string {
  // Simple hash using first 200 chars of body to avoid long string comparison
  const content = `${sender}|${subject}|${body.slice(0, 200)}`
  let hash = 0
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i)
    hash = ((hash << 5) - hash + char) | 0
  }
  return hash.toString(36)
}

// ============================================================
// Main detection logic
// ============================================================

function isGmail(): boolean {
  return window.location.hostname === "mail.google.com"
}

function detectAndAnalyze(): void {
  const emailData = isGmail() ? extractGmailEmail() : extractOutlookEmail()

  if (!emailData) return
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
    // Service worker may not be ready — fail silently
  }
}

function debouncedDetect(): void {
  if (debounceTimer) clearTimeout(debounceTimer)
  debounceTimer = setTimeout(detectAndAnalyze, DEBOUNCE_MS)
}

// ============================================================
// MutationObserver for SPA navigation
// ============================================================

const observer = new MutationObserver(() => {
  debouncedDetect()
})

observer.observe(document.body, {
  childList: true,
  subtree: true
})

// Initial check
debouncedDetect()
