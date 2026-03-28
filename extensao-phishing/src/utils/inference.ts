/**
 * Inferência local usando ONNX Runtime Web
 *
 * ORT é carregado via script tag (não via bundler) para evitar que o Parcel
 * resolva o pacote como Node.js e gere um stub vazio.
 *
 * Estrutura do modelo:
 *   Input  → "float_input"        [N, 51]  float32
 *   Output → "label"              [N]      int64   (0=legítimo, 1=phishing)
 *   Output → "probabilities"      ZipMap  [{0: p_legit, 1: p_phish}]
 *             ou Float32Array [p_legit, p_phishing] se convertido com zipmap=False
 */

import { logger } from "./logger"
import { extractFeatures, featuresToFloat32Array, FEATURE_ORDER } from "./features"

const CONFIDENCE_THRESHOLD  = 0.85
const PHISHING_THRESHOLD    = 0.75  // threshold de decisão (padrão sklearn = 0.50 gera muitos falsos positivos)
const INPUT_NAME = "float_input"

// ORT global exposto pelo script tag (window.ort)
declare const ort: any

let session: any = null
let ortLoaded = false

export interface PredictionResult {
  url: string
  isPhishing: boolean
  confidence: number
  confidencePct: string
  label: "PHISHING" | "LEGITIMO"
  analysis: string
  inferenceMs: number
}

// ============================================================
// Carregamento do ORT via script tag
// ============================================================

function loadOrtScript(): Promise<void> {
  if (ortLoaded) return Promise.resolve()

  return new Promise((resolve, reject) => {
    const existing = document.getElementById("ort-script")
    if (existing) {
      ortLoaded = true
      resolve()
      return
    }

    const script = document.createElement("script")
    script.id  = "ort-script"
    script.src = chrome.runtime.getURL("assets/ort.min.js")
    script.onload = () => {
      console.log("[ORT] Script carregado. window.ort:", typeof (window as any).ort)
      ortLoaded = true
      resolve()
    }
    script.onerror = (e) => reject(new Error("Falha ao carregar ort.wasm.min.js: " + e))
    document.head.appendChild(script)
  })
}

// ============================================================
// Carregamento do modelo
// ============================================================

export async function loadModel(): Promise<void> {
  if (session) {
    console.log("[ORT] Modelo já carregado.")
    return
  }

  console.log("[ORT] Carregando script ORT...")
  await loadOrtScript()

  const ort = (window as any).ort
  if (!ort) throw new Error("window.ort não disponível após carregar script")
  if (!ort.env?.wasm) throw new Error("ort.env.wasm não disponível")

  const modelUrl = chrome.runtime.getURL("assets/modelo/modelo_phishing_ort14.onnx")
  console.log("[ORT] Carregando modelo:", modelUrl)

  ort.env.wasm.numThreads = 1
  ort.env.wasm.wasmPaths  = chrome.runtime.getURL("assets/")
  console.log("[ORT] wasmPaths:", ort.env.wasm.wasmPaths)

  session = await ort.InferenceSession.create(modelUrl, {
    executionProviders: ["wasm"],
  })

  console.log("[ORT] Sessão criada! inputs:", JSON.stringify(session.inputNames), "outputs:", JSON.stringify(session.outputNames))
  logger.info("Modelo ONNX carregado", { inputs: session.inputNames, features: FEATURE_ORDER.length })
}

// ============================================================
// Inferência
// ============================================================

export async function predictUrl(url: string): Promise<PredictionResult> {
  if (!session) await loadModel()

  logger.info("Recebida requisição de análise", { url })
  const t0 = performance.now()

  const ort = (window as any).ort

  const features    = extractFeatures(url)
  const featureData = featuresToFloat32Array(features)

  // Log das features para diagnóstico
  const featObj: Record<string, number> = {}
  FEATURE_ORDER.forEach((k, i) => { featObj[k] = featureData[i] })
  console.log("[ORT] Features:", featObj)

  const inputTensor = new ort.Tensor("float32", featureData, [1, FEATURE_ORDER.length])
  const results     = await session.run({ [INPUT_NAME]: inputTensor })

  // Usa os nomes reais do modelo
  const labelKey = session.outputNames[0]
  const probaKey = session.outputNames[1]

  const predLabel = Number((results[labelKey].data as BigInt64Array)[0])

  // skl2onnx por padrão gera ZipMap: [{0: p_legit, 1: p_phish}]
  // Se convertido com zipmap=False, gera Float32Array [p_legit, p_phishing]
  let phishingProb: number
  const probaOut = results[probaKey]
  if (probaOut.value !== undefined) {
    // ZipMap — array de objetos {classIndex: prob}
    const zipMap = probaOut.value as Array<{ [k: number]: number }>
    phishingProb = zipMap[0][1]
  } else {
    // Float32Array flat [p_legit, p_phishing]
    phishingProb = (probaOut.data as Float32Array)[1]
  }

  const inferenceMs   = Math.round(performance.now() - t0)
  const isPhishing    = phishingProb >= PHISHING_THRESHOLD
  const confidence    = isPhishing ? phishingProb : 1.0 - phishingProb
  const confidencePct = (confidence * 100).toFixed(2) + "%"
  const label         = isPhishing ? "PHISHING" : "LEGITIMO"
  const analysis      = buildAnalysis(isPhishing, confidence)

  console.log("[ORT] Resultado:", label, "p_phishing:", phishingProb.toFixed(4), "p_legit:", (1 - phishingProb).toFixed(4), inferenceMs + "ms")

  logger.logDecision({
    timestamp: new Date().toISOString(),
    url, isPhishing, confidence, confidencePct, label, analysis,
    featuresUsed: FEATURE_ORDER.length, inferenceMs,
  })

  return { url, isPhishing, confidence, confidencePct, label, analysis, inferenceMs }
}

// ============================================================
// Helpers
// ============================================================

function buildAnalysis(isPhishing: boolean, confidence: number): string {
  const confPct = (confidence * 100).toFixed(2)
  const label   = isPhishing ? "phishing" : "legítimo"

  if (confidence >= CONFIDENCE_THRESHOLD) {
    return (
      `GBM classificou como ${label} com confiança de ${confPct}%. ` +
      `Decisão confiável.`
    )
  }
  return (
    `GBM classificou como ${label}, porém com confiança de apenas ${confPct}%. ` +
    `Resultado incerto — considere verificar manualmente.`
  )
}
