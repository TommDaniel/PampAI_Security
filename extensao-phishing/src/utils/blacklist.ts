/**
 * Blacklist e Whitelist locais — lookup O(1) por domínio
 *
 * Carrega dois JSONs gerados por scripts Python:
 *   - whitelist.json  (whitelist/coletar_whitelist.py) — domínios legítimos
 *   - blacklist.json  (blacklist/coletar_blacklist.py)  — domínios maliciosos
 *
 * Prioridade: whitelist > blacklist > modelo
 */

let blacklistSet: Set<string> | null = null
let whitelistSet: Set<string> | null = null

/** Carrega os dois JSONs e popula os Sets uma única vez */
export async function loadBlacklist(): Promise<void> {
  await Promise.all([loadWhitelistJson(), loadBlacklistJson()])
}

async function loadWhitelistJson(): Promise<void> {
  if (whitelistSet) return
  try {
    const url = chrome.runtime.getURL("assets/whitelist.json")
    const res = await fetch(url)
    const domains: string[] = await res.json()
    whitelistSet = new Set(domains)
    console.log(`[Whitelist] ${whitelistSet.size.toLocaleString()} domínios carregados`)
  } catch {
    // whitelist.json ainda não foi gerado — usa fallback vazio
    whitelistSet = new Set()
    console.warn("[Whitelist] whitelist.json não encontrado — apenas blacklist ativa")
  }
}

async function loadBlacklistJson(): Promise<void> {
  if (blacklistSet) return
  try {
    const url = chrome.runtime.getURL("assets/blacklist.json")
    const res = await fetch(url)
    const domains: string[] = await res.json()
    blacklistSet = new Set(domains)
    console.log(`[Blacklist] ${blacklistSet.size.toLocaleString()} domínios carregados`)
  } catch {
    blacklistSet = new Set()
    console.warn("[Blacklist] blacklist.json não encontrado — lookup desabilitado")
  }
}

/** Extrai hostname e variante sem www de uma URL */
function extractHostnames(url: string): { hostname: string; withoutWww: string } | null {
  try {
    const u = url.startsWith("http") ? url : "http://" + url
    const hostname = new URL(u).hostname.toLowerCase()
    const withoutWww = hostname.replace(/^www\./, "")
    return { hostname, withoutWww }
  } catch {
    return null
  }
}

/**
 * Verifica se uma URL pertence à whitelist de domínios legítimos conhecidos.
 * Se sim, o modelo não deve ser consultado.
 */
export function isWhitelisted(url: string): boolean {
  const h = extractHostnames(url)
  if (!h) return false
  if (!whitelistSet || whitelistSet.size === 0) return false
  return whitelistSet.has(h.hostname) || whitelistSet.has(h.withoutWww)
}

/**
 * Verifica se uma URL está na blacklist.
 * Checa tanto o hostname exato quanto o domínio sem "www.".
 *
 * Retorna null se a blacklist não foi carregada ainda.
 */
export function isBlacklisted(url: string): boolean | null {
  if (!blacklistSet) return null

  const h = extractHostnames(url)
  if (!h) return false

  // Whitelist tem prioridade — domínios legítimos conhecidos nunca são bloqueados
  if (isWhitelisted(url)) return false

  return blacklistSet.has(h.hostname) || blacklistSet.has(h.withoutWww)
}
