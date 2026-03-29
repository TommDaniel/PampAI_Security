/**
 * Content Script — injeta em todas as páginas automaticamente
 *
 * Responsabilidades:
 *   - Captura a URL da página ao carregar
 *   - Extrai 11 client_features via clientFeatures.ts
 *   - Envia { url, features } para o background (service worker) analisar
 *   - O resultado é exibido via badge no ícone da extensão (background.ts)
 *     e no popup ao clicar no ícone (popup.tsx)
 */

import { extractClientFeatures } from "../utils/clientFeatures"

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
    await chrome.runtime.sendMessage({
      type: "ANALYZE_URL",
      url,
      features
    })
  } catch {
    // Service worker pode ainda estar carregando — sem erro visível
  }
})()
