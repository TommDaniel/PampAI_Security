/**
 * Blacklist local — lookup O(1) por domínio
 *
 * Carrega blacklist.json (gerado por blacklist/coletar_blacklist.py)
 * e verifica se um domínio está na lista antes de rodar a inferência ONNX.
 *
 * Vantagens:
 *   - Instantâneo (sem inferência) para domínios conhecidos
 *   - Cobre casos de drive-by / redirect antes do modelo analisar
 *   - Fallback independente do modelo ONNX
 */

let blacklistSet: Set<string> | null = null

/**
 * Domínios legítimos bem conhecidos que nunca devem ser bloqueados.
 * Falsos positivos comuns nas fontes públicas de blacklist.
 */
const WHITELIST = new Set([
  // Google
  "google.com", "www.google.com", "google.com.br", "accounts.google.com",
  "mail.google.com", "drive.google.com", "docs.google.com", "maps.google.com",
  // YouTube
  "youtube.com", "www.youtube.com", "m.youtube.com",
  // Meta
  "facebook.com", "www.facebook.com", "m.facebook.com",
  "instagram.com", "www.instagram.com",
  "whatsapp.com", "www.whatsapp.com", "web.whatsapp.com",
  // Microsoft
  "microsoft.com", "www.microsoft.com", "live.com", "outlook.com",
  "office.com", "www.office.com", "login.microsoftonline.com",
  "azure.com", "www.azure.com",
  // Apple
  "apple.com", "www.apple.com", "icloud.com", "appleid.apple.com",
  // Amazon / AWS
  "amazon.com", "www.amazon.com", "amazon.com.br", "aws.amazon.com",
  "aws.amazon.com",
  // Social
  "twitter.com", "www.twitter.com", "x.com", "www.x.com",
  "linkedin.com", "www.linkedin.com",
  "reddit.com", "www.reddit.com",
  "tiktok.com", "www.tiktok.com",
  // Entretenimento / jogos
  "netflix.com", "www.netflix.com",
  "spotify.com", "www.spotify.com",
  "twitch.tv", "www.twitch.tv",
  "steampowered.com", "www.steampowered.com", "store.steampowered.com",
  "steamcommunity.com", "www.steamcommunity.com",
  "epicgames.com", "www.epicgames.com", "store.epicgames.com",
  "origin.com", "www.origin.com", "ea.com", "www.ea.com",
  "blizzard.com", "www.blizzard.com", "battle.net", "www.battle.net",
  "riotgames.com", "www.riotgames.com",
  "nintendo.com", "www.nintendo.com",
  "playstation.com", "www.playstation.com",
  "xbox.com", "www.xbox.com",
  // AI
  "chatgpt.com", "www.chatgpt.com",
  "openai.com", "www.openai.com", "platform.openai.com",
  "claude.ai", "www.claude.ai",
  "gemini.google.com", "bard.google.com",
  "copilot.microsoft.com",
  // Tech
  "github.com", "www.github.com", "gist.github.com",
  "stackoverflow.com", "www.stackoverflow.com",
  "discord.com", "www.discord.com",
  "slack.com", "www.slack.com",
  "zoom.us", "www.zoom.us",
  "cloudflare.com", "www.cloudflare.com",
  "wikipedia.org", "www.wikipedia.org",
  // BR
  "mercadolivre.com.br", "www.mercadolivre.com.br",
  "globo.com", "www.globo.com", "g1.globo.com", "ge.globo.com",
  "uol.com.br", "www.uol.com.br",
  "gov.br", "www.gov.br", "receita.fazenda.gov.br",
  "nubank.com.br", "www.nubank.com.br",
  "ifood.com.br", "www.ifood.com.br",
  "olx.com.br", "www.olx.com.br",
  "submarino.com.br", "www.submarino.com.br",
  "americanas.com.br", "www.americanas.com.br",
  "magazineluiza.com.br", "www.magazineluiza.com.br",
  // Outros
  "yahoo.com", "www.yahoo.com",
  "bing.com", "www.bing.com",
  "paypal.com", "www.paypal.com",
  "ebay.com", "www.ebay.com",
  "aliexpress.com", "www.aliexpress.com",
  "shopee.com.br", "www.shopee.com.br",
])

/** Carrega o JSON e popula o Set uma única vez */
export async function loadBlacklist(): Promise<void> {
  if (blacklistSet) return

  try {
    const url = chrome.runtime.getURL("assets/blacklist.json")
    const res = await fetch(url)
    const domains: string[] = await res.json()
    blacklistSet = new Set(domains)
    console.log(`[Blacklist] ${blacklistSet.size.toLocaleString()} domínios carregados`)
  } catch (err) {
    // Arquivo ainda não existe (antes de rodar coletar_blacklist.py)
    blacklistSet = new Set()
    console.warn("[Blacklist] blacklist.json não encontrado — lookup desabilitado", err)
  }
}

/**
 * Verifica se uma URL pertence à whitelist de domínios legítimos conhecidos.
 * Se sim, o modelo não deve ser consultado.
 */
export function isWhitelisted(url: string): boolean {
  try {
    const u = url.startsWith("http") ? url : "http://" + url
    const hostname = new URL(u).hostname.toLowerCase()
    const withoutWww = hostname.replace(/^www\./, "")
    return WHITELIST.has(hostname) || WHITELIST.has(withoutWww)
  } catch {
    return false
  }
}

/**
 * Verifica se uma URL está na blacklist.
 * Checa tanto o hostname exato quanto o domínio sem "www.".
 *
 * Retorna null se a blacklist não foi carregada ainda.
 */
export function isBlacklisted(url: string): boolean | null {
  if (!blacklistSet) return null

  try {
    const u = url.startsWith("http") ? url : "http://" + url
    const hostname = new URL(u).hostname.toLowerCase()
    const withoutWww = hostname.replace(/^www\./, "")

    // Whitelist tem prioridade — domínios legítimos conhecidos nunca são bloqueados
    if (WHITELIST.has(hostname) || WHITELIST.has(withoutWww)) return false

    return blacklistSet.has(hostname) || blacklistSet.has(withoutWww)
  } catch {
    return false
  }
}
