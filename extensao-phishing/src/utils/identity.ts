/**
 * Identity module — reads enterprise configuration from chrome.storage.managed
 * (set by IT admin via GPO/Intune/MDM) and caches it in chrome.storage.local.
 *
 * Managed fields (read-only, set by admin policy):
 *   org_id       — organization identifier (e.g. "acme-corp")
 *   user_email   — user's email address (e.g. "alice@acme.com")
 *   api_endpoint — API base URL override (e.g. "https://phishing-api.acme.com")
 *
 * Fallback order: managed → local cache → defaults
 */

const LOCAL_IDENTITY_KEY = "identity"

export interface Identity {
  orgId: string | null
  userEmail: string | null
  apiEndpoint: string | null
}

const DEFAULT_IDENTITY: Identity = {
  orgId: null,
  userEmail: null,
  apiEndpoint: null
}

// ── Read from managed storage ────────────────────────────────

async function readManaged(): Promise<Partial<Identity>> {
  try {
    const data = await chrome.storage.managed.get([
      "org_id",
      "user_email",
      "api_endpoint"
    ])
    return {
      orgId: (data.org_id as string) || null,
      userEmail: (data.user_email as string) || null,
      apiEndpoint: (data.api_endpoint as string) || null
    }
  } catch {
    // managed storage unavailable (e.g. not enterprise-managed) — not an error
    return {}
  }
}

// ── Cache in local storage ───────────────────────────────────

async function saveLocal(identity: Identity): Promise<void> {
  await chrome.storage.local.set({ [LOCAL_IDENTITY_KEY]: identity })
}

async function readLocal(): Promise<Identity | null> {
  try {
    const data = await chrome.storage.local.get(LOCAL_IDENTITY_KEY)
    return (data[LOCAL_IDENTITY_KEY] as Identity) || null
  } catch {
    return null
  }
}

// ── Public API ───────────────────────────────────────────────

/**
 * Load identity from managed storage, persist to local, and return it.
 * Called at service worker startup and on policy change.
 */
export async function initIdentity(): Promise<Identity> {
  const managed = await readManaged()
  const local = await readLocal()

  const identity: Identity = {
    orgId: managed.orgId ?? local?.orgId ?? DEFAULT_IDENTITY.orgId,
    userEmail:
      managed.userEmail ?? local?.userEmail ?? DEFAULT_IDENTITY.userEmail,
    apiEndpoint:
      managed.apiEndpoint ?? local?.apiEndpoint ?? DEFAULT_IDENTITY.apiEndpoint
  }

  await saveLocal(identity)
  return identity
}

/**
 * Read the locally-cached identity (fast, synchronous-ish).
 * Falls back to defaults if nothing is cached yet.
 */
export async function getIdentity(): Promise<Identity> {
  const local = await readLocal()
  return local ?? DEFAULT_IDENTITY
}

/**
 * Register a callback that fires whenever the managed policy changes at runtime.
 * Automatically refreshes the local cache on change.
 */
export function onIdentityChanged(
  callback: (identity: Identity) => void
): void {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "managed") return
    const relevant = ["org_id", "user_email", "api_endpoint"]
    const changed = relevant.some((key) => key in changes)
    if (!changed) return

    initIdentity().then(callback).catch(() => {
      // swallow — policy change errors are non-fatal
    })
  })
}
