/**
 * URL analysis cache module.
 * Caches phishing detection results in chrome.storage.local
 * to avoid repeated API calls for frequently visited URLs.
 */

export interface CacheEntry {
  isPhishing: boolean
  confidence: number
  label: string
  analysis: string
  timestamp: number
}

interface CacheStore {
  [normalizedUrl: string]: CacheEntry
}

const CACHE_KEY = "urlCache"
const MAX_ENTRIES = 5000
const TTL_LEGITIMATE_MS = 24 * 60 * 60 * 1000 // 24 hours
const TTL_PHISHING_MS = 7 * 24 * 60 * 60 * 1000 // 7 days

/**
 * Normalize a URL for use as a cache key.
 * Lowercases hostname and removes trailing slash.
 */
function normalizeUrl(url: string): string {
  try {
    const parsed = new URL(
      url.startsWith("http://") || url.startsWith("https://")
        ? url
        : "http://" + url
    )
    // Lowercase hostname, keep path, remove trailing slash
    let normalized = `${parsed.protocol}//${parsed.hostname.toLowerCase()}${parsed.pathname}${parsed.search}${parsed.hash}`
    if (normalized.endsWith("/")) {
      normalized = normalized.slice(0, -1)
    }
    return normalized
  } catch {
    return url.toLowerCase().replace(/\/+$/, "")
  }
}

async function loadCache(): Promise<CacheStore> {
  try {
    const data = await chrome.storage.local.get(CACHE_KEY)
    return (data[CACHE_KEY] as CacheStore) || {}
  } catch {
    return {}
  }
}

async function saveCache(cache: CacheStore): Promise<void> {
  await chrome.storage.local.set({ [CACHE_KEY]: cache })
}

/**
 * Evict oldest 20% of entries when cache exceeds MAX_ENTRIES.
 */
function evictOldest(cache: CacheStore): CacheStore {
  const entries = Object.entries(cache)
  if (entries.length <= MAX_ENTRIES) return cache

  const toRemove = Math.ceil(entries.length * 0.2)
  entries.sort((a, b) => a[1].timestamp - b[1].timestamp)

  const keysToRemove = new Set(entries.slice(0, toRemove).map(([key]) => key))
  const newCache: CacheStore = {}
  for (const [key, value] of entries) {
    if (!keysToRemove.has(key)) {
      newCache[key] = value
    }
  }
  return newCache
}

/**
 * Get a cached analysis result for a URL.
 * Returns undefined if not cached or if the entry has expired.
 */
export async function getCached(
  url: string
): Promise<CacheEntry | undefined> {
  const cache = await loadCache()
  const key = normalizeUrl(url)
  const entry = cache[key]

  if (!entry) return undefined

  const now = Date.now()
  const ttl = entry.isPhishing ? TTL_PHISHING_MS : TTL_LEGITIMATE_MS

  if (now - entry.timestamp > ttl) {
    // Entry expired — remove it
    delete cache[key]
    await saveCache(cache)
    return undefined
  }

  return entry
}

/**
 * Store an analysis result in the cache.
 */
export async function setCached(
  url: string,
  entry: CacheEntry
): Promise<void> {
  let cache = await loadCache()
  const key = normalizeUrl(url)

  cache[key] = entry
  cache = evictOldest(cache)

  await saveCache(cache)
}

/**
 * Clear the entire URL cache.
 */
export async function clearCache(): Promise<void> {
  await chrome.storage.local.remove(CACHE_KEY)
}
