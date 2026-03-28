/**
 * Extração de features de URLs
 * Port direto da função extract_features() do treino:
 *   modelo-gbm-brasileiro/treino_gbm_brasileiro.ipynb
 *
 * As 46 features e sua ORDEM são idênticas a list(X.columns) no treino Python.
 * A ordem importa: o vetor Float32Array deve bater com X.columns do treino
 * para o modelo ONNX produzir predições corretas.
 *
 * Equivalências de bibliotecas:
 *   Python urlparse      → URL API nativa do browser
 *   Python tldextract    → tldts (npm)
 *   Python re            → RegExp nativo
 *   Python numpy         → Math nativo
 */

import { parse as tldParse } from "tldts"

// ============================================================
// Tipos
// ============================================================

export interface UrlFeatures {
  // Estrutura básica
  url_length: number
  hostname_length: number
  path_length: number
  query_length: number
  path_depth: number
  num_params: number
  // Caracteres
  num_dots: number
  num_hyphens: number
  num_underscores: number
  num_slashes: number
  num_ats: number
  num_equals: number
  num_digits: number
  num_special: number
  // Diferenciação local
  num_hyphens_domain: number
  num_hyphens_path: number
  num_dots_hostname: number
  // Selos de confiança
  is_gov_br: number
  is_com_br: number
  is_edu_br: number
  is_org_br: number
  // Domínio
  subdomain_length: number
  domain_length: number
  tld_length: number
  num_subdomains: number
  // Proporções e entropia
  digit_ratio: number
  special_ratio: number
  entropy: number
  entropy_domain: number
  // Padrões suspeitos
  has_ip: number
  has_at_sign: number
  has_double_slash_redirect: number
  has_hex_encoding: number
  has_https: number
  has_www: number
  has_prefix_suffix: number
  has_shortener: number
  has_port: number
  has_suspicious_ext: number
  // Novas features (literatura)
  has_punycode: number
  suspicious_tld: number
  tld_in_path: number
  has_digits_in_domain: number
  // Palavras-chave (marca vs ação)
  brand_is_domain: number
  brand_in_subdomain: number
  action_kw_hostname: number
  action_kw_path: number
  action_kw_query: number
  // Tokens
  num_tokens: number
  avg_token_length: number
  max_token_length: number
}

// Ordem exata das 51 features — deve ser idêntica a list(X.columns) no treino Python
export const FEATURE_ORDER: (keyof UrlFeatures)[] = [
  "url_length", "hostname_length", "path_length", "query_length",
  "path_depth", "num_params",
  "num_dots", "num_hyphens", "num_underscores", "num_slashes",
  "num_ats", "num_equals", "num_digits", "num_special",
  "num_hyphens_domain", "num_hyphens_path", "num_dots_hostname",
  "is_gov_br", "is_com_br", "is_edu_br", "is_org_br",
  "subdomain_length", "domain_length", "tld_length", "num_subdomains",
  "digit_ratio", "special_ratio", "entropy", "entropy_domain",
  "has_ip", "has_at_sign", "has_double_slash_redirect", "has_hex_encoding",
  "has_https", "has_www", "has_prefix_suffix", "has_shortener",
  "has_port", "has_suspicious_ext",
  "has_punycode", "suspicious_tld", "tld_in_path", "has_digits_in_domain",
  "brand_is_domain", "brand_in_subdomain",
  "action_kw_hostname", "action_kw_path", "action_kw_query",
  "num_tokens", "avg_token_length", "max_token_length"
]

// ============================================================
// Helpers
// ============================================================

/** Conta ocorrências de um caractere numa string (equivalente ao str.count() do Python) */
function countChar(str: string, char: string): number {
  let n = 0
  for (const c of str) if (c === char) n++
  return n
}

/** Entropia de Shannon — equivalente ao cálculo com numpy no Python */
function shannonEntropy(str: string): number {
  if (str.length === 0) return 0
  const freq = new Map<string, number>()
  for (const c of str) freq.set(c, (freq.get(c) ?? 0) + 1)
  let entropy = 0
  for (const count of freq.values()) {
    const p = count / str.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

/** Média de um array numérico — equivalente ao np.mean() */
function mean(arr: number[]): number {
  if (arr.length === 0) return 0
  return arr.reduce((a, b) => a + b, 0) / arr.length
}

// ============================================================
// Keywords — idênticas ao Python
// ============================================================

const ACTION_KEYWORDS = [
  "login", "signin", "verify", "account", "update", "secure", "confirm", "password", "suspend",
  "conta", "acesso", "seguro", "atualizar", "liberar", "bloqueio", "recadastro", "atencao",
  "beneficio", "auxilio", "urgente"
]

const BRAND_KEYWORDS = [
  // Brasil
  "caixa", "bradesco", "itau", "nubank", "santander", "bb", "inter", "picpay",
  // Global
  "google", "microsoft", "apple", "amazon", "openai", "github",
  "netflix", "facebook", "whatsapp", "instagram", "twitter", "linkedin",
  "paypal", "mercadolivre", "magazineluiza", "americanas",
]

const SHORTENERS = [
  "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly",
  "t.co", "tinyurl.com", "tr.im", "is.gd", "cli.re"
]

const SUSPICIOUS_EXTS = [
  ".exe", ".zip", ".rar", ".js", ".php",
  ".cgi", ".asp", ".aspx", ".scr", ".bat", ".cmd"
]

// ============================================================
// Extração de features — port de extract_features() do Python
// ============================================================

export function extractFeatures(rawUrl: string): UrlFeatures {
  const raw = rawUrl

  // Garante que a URL tem esquema para o parser funcionar
  const urlStr =
    raw.startsWith("http://") || raw.startsWith("https://")
      ? raw
      : "http://" + raw

  let parsed: URL
  try {
    parsed = new URL(urlStr)
  } catch {
    parsed = new URL("http://invalid")
  }

  let ext: ReturnType<typeof tldParse>
  try {
    ext = tldParse(urlStr)
  } catch {
    ext = tldParse("http://invalid")
  }

  const hostname  = (parsed.hostname ?? "").toLowerCase()
  const path      = (parsed.pathname ?? "").toLowerCase()
  const query     = parsed.search.replace(/^\?/, "").toLowerCase()
  const domain    = (ext.domainWithoutSuffix ?? ext.domain ?? "").toLowerCase()
  const subdomain = (ext.subdomain ?? "").toLowerCase()
  const suffix    = (ext.publicSuffix ?? "").toLowerCase()

  // --- ESTRUTURA BÁSICA ---
  const url_length      = raw.length
  const hostname_length = hostname.length
  const path_length     = path.length
  const query_length    = query.length
  const path_depth      = path ? countChar(path, "/") - 1 : 0
  const num_params      = query ? countChar(query, "=") : 0

  // --- CARACTERES ---
  const num_dots        = countChar(raw, ".")
  const num_hyphens     = countChar(raw, "-")
  const num_underscores = countChar(raw, "_")
  const num_slashes     = countChar(raw, "/")
  const num_ats         = countChar(raw, "@")
  const num_equals      = countChar(raw, "=")

  let num_digits = 0
  for (const c of raw) if (c >= "0" && c <= "9") num_digits++

  let num_special = 0
  for (const c of raw) {
    if (!/[a-zA-Z0-9.\-_/]/.test(c)) num_special++
  }

  // --- DIFERENCIAÇÃO LOCAL ---
  const num_hyphens_domain = countChar(hostname, "-")
  const num_hyphens_path   = countChar(path, "-")
  const num_dots_hostname  = countChar(hostname, ".")

  // --- SELOS DE CONFIANÇA ---
  const is_gov_br = suffix === "gov.br" ? 1 : 0
  const is_com_br = suffix === "com.br" ? 1 : 0
  const is_edu_br = suffix === "edu.br" ? 1 : 0
  const is_org_br = suffix === "org.br" ? 1 : 0

  // --- DOMÍNIO ---
  const subdomain_length = subdomain.length
  const domain_length    = domain.length
  const tld_length       = suffix.length
  const num_subdomains   = subdomain ? countChar(subdomain, ".") + 1 : 0

  // --- PROPORÇÕES E ENTROPIA ---
  const digit_ratio   = num_digits  / Math.max(raw.length, 1)
  const special_ratio = num_special / Math.max(raw.length, 1)
  const entropy       = shannonEntropy(raw)

  // Entropia separada do domínio (forte discriminador — Tamal et al. 2024)
  const domStr = domain + (suffix ? "." + suffix : "")
  const entropy_domain = shannonEntropy(domStr)

  // --- PADRÕES SUSPEITOS ---
  const has_ip = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) ? 1 : 0
  const has_at_sign = raw.includes("@") ? 1 : 0
  const has_double_slash_redirect = raw.slice(8).includes("//") ? 1 : 0
  const has_hex_encoding = raw.includes("%") ? 1 : 0
  const has_https = raw.startsWith("https") ? 1 : 0
  const has_www = hostname.includes("www.") ? 1 : 0
  const has_prefix_suffix = hostname.includes("-") ? 1 : 0
  const has_shortener = (SHORTENERS.includes(hostname) || SHORTENERS.some(s => hostname.endsWith("." + s))) ? 1 : 0

  const portStr = parsed.port
  const portNum = portStr ? parseInt(portStr, 10) : null
  const has_port = portNum !== null && portNum !== 80 && portNum !== 443 ? 1 : 0

  const has_suspicious_ext = SUSPICIOUS_EXTS.some(e => path.endsWith(e)) ? 1 : 0

  // --- NOVAS FEATURES (literatura: Tamal 2024, Trieuh2) ---
  // Punycode — ataques homógrafos
  const has_punycode = hostname.includes("xn--") ? 1 : 0

  // TLDs gratuitos/suspeitos muito usados em phishing
  const SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club", "info", "work", "link"]
  const suspicious_tld = SUSPICIOUS_TLDS.some(t => suffix.endsWith(t)) ? 1 : 0

  // TLD aparece no path (ex: evil.com/google.com/login)
  const COMMON_TLDS = [".com", ".org", ".net", ".gov", ".edu", ".com.br", ".org.br"]
  const tld_in_path = COMMON_TLDS.some(t => path.includes(t)) ? 1 : 0

  // Dígitos no domínio registrado (legítimos raramente têm)
  const has_digits_in_domain = /\d/.test(domain) ? 1 : 0

  // --- PALAVRAS-CHAVE (Separação Marca vs Ação) ---
  const is_brand = BRAND_KEYWORDS.includes(domain) ? 1 : 0

  // Marca no domínio registrado = LEGÍTIMO
  const brand_is_domain = is_brand

  // Marca no subdomínio ou hostname mas NÃO é o domínio = SUSPEITO
  const brand_in_subdomain =
    BRAND_KEYWORDS.some(kw => subdomain.includes(kw)) ||
    (BRAND_KEYWORDS.some(kw => hostname.includes(kw)) && !is_brand)
      ? 1 : 0

  // Action keywords NEUTRALIZADAS quando domínio é marca legítima
  const action_h = ACTION_KEYWORDS.filter(kw => hostname.includes(kw)).length
  const action_p = ACTION_KEYWORDS.filter(kw => path.includes(kw)).length
  const action_q = ACTION_KEYWORDS.filter(kw => query.includes(kw)).length

  const action_kw_hostname = action_h * (1 - is_brand)
  const action_kw_path     = action_p * (1 - is_brand)
  const action_kw_query    = action_q * (1 - is_brand)

  // --- TOKENS ---
  const tokens = raw.split(/[.\-_/=?&]/)
  const num_tokens       = tokens.length
  const tokenLengths     = tokens.filter(t => t.length > 0).map(t => t.length)
  const avg_token_length = mean(tokenLengths)
  const max_token_length = tokenLengths.length > 0 ? Math.max(...tokenLengths) : 0

  return {
    url_length, hostname_length, path_length, query_length,
    path_depth, num_params,
    num_dots, num_hyphens, num_underscores, num_slashes,
    num_ats, num_equals, num_digits, num_special,
    num_hyphens_domain, num_hyphens_path, num_dots_hostname,
    is_gov_br, is_com_br, is_edu_br, is_org_br,
    subdomain_length, domain_length, tld_length, num_subdomains,
    digit_ratio, special_ratio, entropy, entropy_domain,
    has_ip, has_at_sign, has_double_slash_redirect, has_hex_encoding,
    has_https, has_www, has_prefix_suffix, has_shortener,
    has_port, has_suspicious_ext,
    has_punycode, suspicious_tld, tld_in_path, has_digits_in_domain,
    brand_is_domain, brand_in_subdomain,
    action_kw_hostname, action_kw_path, action_kw_query,
    num_tokens, avg_token_length, max_token_length
  }
}

/**
 * Converte o objeto de features para Float32Array na ordem correta
 * para entrada no modelo ONNX (equivalente ao X.iloc[[i]] do pandas)
 */
export function featuresToFloat32Array(features: UrlFeatures): Float32Array {
  return new Float32Array(FEATURE_ORDER.map(key => features[key]))
}
