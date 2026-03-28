/**
 * Content Script — injeta em todas as páginas automaticamente
 *
 * Responsabilidades:
 *   - Captura a URL da página ao carregar
 *   - Extrai 11 client_features via clientFeatures.ts
 *   - Envia { url, features } para o background (service worker) analisar
 *   - Se phishing: injeta banner de aviso no topo da página (vermelho)
 *   - Se confiança baixa: injeta banner de atenção (laranja)
 *   - Se offline: não injeta nada (fail-open)
 *
 * Fluxo:
 *   página carrega → extractClientFeatures(url) → sendMessage(ANALYZE_URL, { url, features })
 *                 → background → resultado
 *                 ← se phishing: showBanner(result)
 */

import { extractClientFeatures } from "../utils/clientFeatures"
import type { AnalysisResult } from "../background"

const BANNER_ID = "phishing-detector-banner"

// ============================================================
// Inicia análise ao carregar a página
// ============================================================

;(async () => {
  const url = window.location.href

  // Ignora páginas internas do browser
  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:") ||
    url.startsWith("edge://")
  ) return

  try {
    const features = extractClientFeatures(url)

    const response = await chrome.runtime.sendMessage({
      type: "ANALYZE_URL",
      url,
      features
    })

    if (!response?.success) return

    const result: AnalysisResult = response.result

    // Offline — fail-open, no banner
    if (result.offline) return

    if (result.isPhishing) {
      showBanner(result, "danger")
    } else if (result.confidence < 70) {
      // Confiança abaixo de 70% — aviso laranja
      showBanner(result, "warning")
    }
    // Legítimo com alta confiança: não injeta nada (não atrapalha o usuário)

  } catch {
    // Service worker pode ainda estar carregando — sem erro visível
  }
})()

// ============================================================
// Banner de aviso
// ============================================================

type BannerType = "danger" | "warning"

function showBanner(result: AnalysisResult, type: BannerType) {
  // Remove banner anterior se existir
  document.getElementById(BANNER_ID)?.remove()

  const isDanger = type === "danger"

  const banner = document.createElement("div")
  banner.id = BANNER_ID
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 2147483647;
    padding: 10px 16px;
    display: flex;
    align-items: center;
    gap: 12px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-size: 13px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.25);
    background: ${isDanger ? "#c53030" : "#d69e2e"};
    color: #fff;
  `

  // Ícone
  const icon = document.createElement("span")
  icon.textContent = isDanger ? "\u26A0" : "\u2139"
  icon.style.cssText = "font-size:18px; flex-shrink:0;"

  // Texto principal
  const textWrap = document.createElement("div")
  textWrap.style.cssText = "flex:1; min-width:0;"

  const title = document.createElement("strong")
  title.textContent = isDanger
    ? "Possível phishing detectado"
    : "Confiança baixa — verifique o site"

  const subtitle = document.createElement("div")
  subtitle.style.cssText = "font-size:11px; opacity:0.9; margin-top:2px;"
  subtitle.textContent = result.analysis

  textWrap.appendChild(title)
  textWrap.appendChild(subtitle)

  // Confiança
  const conf = document.createElement("span")
  conf.style.cssText = `
    flex-shrink:0;
    background: rgba(0,0,0,0.2);
    padding: 3px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
  `
  conf.textContent = `${result.confidence.toFixed(1)}%`

  // Botão fechar
  const closeBtn = document.createElement("button")
  closeBtn.textContent = "\u2715"
  closeBtn.style.cssText = `
    flex-shrink:0;
    background: rgba(0,0,0,0.2);
    border: none;
    color: #fff;
    cursor: pointer;
    font-size: 13px;
    width: 24px;
    height: 24px;
    border-radius: 4px;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0;
  `
  closeBtn.addEventListener("click", () => banner.remove())

  banner.appendChild(icon)
  banner.appendChild(textWrap)
  banner.appendChild(conf)
  banner.appendChild(closeBtn)

  // Empurra o conteúdo da página para não sobrepor
  document.body.style.marginTop =
    (parseInt(document.body.style.marginTop || "0") + 48) + "px"

  banner.addEventListener("remove-banner", () => {
    document.body.style.marginTop =
      Math.max(0, parseInt(document.body.style.marginTop || "0") - 48) + "px"
  })

  closeBtn.addEventListener("click", () => {
    document.body.style.marginTop =
      Math.max(0, parseInt(document.body.style.marginTop || "0") - 48) + "px"
  })

  document.body.prepend(banner)
}
