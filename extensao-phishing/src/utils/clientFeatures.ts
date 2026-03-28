/**
 * Client-side feature extraction for the DomURLs-BERT API.
 * Extracts 11 features from a URL that are sent to the API
 * alongside the URL itself for phishing detection.
 */

export interface ClientFeatures {
  length: number
  dom_length: number
  dot: number
  hyphen: number
  slash: number
  at: number
  params: number
  shortened: number
  tls: number
  vowels_domain: number
  email: number
}

const SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "cli.re",
  "go2l.ink",
  "x.co",
  "shorte.st",
  "tr.im",
  "rb.gy",
  "cutt.ly",
  "shorturl.at",
  "tiny.cc"
]

const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/

function countChar(str: string, char: string): number {
  let n = 0
  for (const c of str) if (c === char) n++
  return n
}

function countVowels(str: string): number {
  let n = 0
  for (const c of str) {
    if ("aeiouAEIOU".includes(c)) n++
  }
  return n
}

export function extractClientFeatures(url: string): ClientFeatures {
  const urlStr =
    url.startsWith("http://") || url.startsWith("https://")
      ? url
      : "http://" + url

  let parsed: URL
  try {
    parsed = new URL(urlStr)
  } catch {
    parsed = new URL("http://invalid")
  }

  const hostname = parsed.hostname.toLowerCase()

  // Extract domain (without subdomains and TLD) for vowel counting
  // Simple approach: take the second-to-last part before the TLD
  const parts = hostname.split(".")
  const domain = parts.length >= 2 ? parts[parts.length - 2] : hostname

  const length = url.length
  const dom_length = domain.length
  const dot = countChar(url, ".")
  const hyphen = countChar(url, "-")
  const slash = countChar(url, "/")
  const at = countChar(url, "@")
  const params = parsed.search ? countChar(parsed.search, "=") : 0
  const shortened = SHORTENERS.some(
    (s) => hostname === s || hostname.endsWith("." + s)
  )
    ? 1
    : 0
  const tls = url.startsWith("https") ? 1 : 0
  const vowels_domain = countVowels(domain)
  const email = EMAIL_REGEX.test(url) ? 1 : 0

  return {
    length,
    dom_length,
    dot,
    hyphen,
    slash,
    at,
    params,
    shortened,
    tls,
    vowels_domain,
    email
  }
}
