/**
 * Exemplo de integração da API de Phishing com extensão Chrome/Firefox
 *
 * Este arquivo mostra como integrar a API de fallback com sua extensão
 */

// Configuração da API
const API_CONFIG = {
    baseUrl: 'http://localhost:8000',
    timeout: 5000, // 5 segundos
    confidenceThreshold: 0.7
};

/**
 * Classe para gerenciar a detecção de phishing
 */
class PhishingDetector {
    constructor(apiUrl = API_CONFIG.baseUrl) {
        this.apiUrl = apiUrl;
    }

    /**
     * Verifica se a API está online
     */
    async checkAPIHealth() {
        try {
            const response = await fetch(`${this.apiUrl}/health`, {
                method: 'GET',
                signal: AbortSignal.timeout(API_CONFIG.timeout)
            });

            if (!response.ok) {
                throw new Error(`API retornou status ${response.status}`);
            }

            const data = await response.json();
            return data.status === 'healthy';
        } catch (error) {
            console.error('API de fallback não disponível:', error);
            return false;
        }
    }

    /**
     * Extrai features de uma URL
     * Adapte conforme as features que seu RandomForest usa
     */
    extractFeatures(url) {
        const urlObj = new URL(url);

        return {
            url_length: url.length,
            has_ip: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname),
            has_https: urlObj.protocol === 'https:',
            num_dots: (url.match(/\./g) || []).length,
            num_hyphens: (url.match(/-/g) || []).length,
            num_underscores: (url.match(/_/g) || []).length,
            has_at_symbol: url.includes('@'),
            path_length: urlObj.pathname.length,
            num_subdomains: urlObj.hostname.split('.').length - 2,
            has_suspicious_tld: this.hasSuspiciousTLD(urlObj.hostname),
            // Adicione mais features conforme necessário
        };
    }

    /**
     * Verifica se o domínio tem TLD suspeito
     */
    hasSuspiciousTLD(hostname) {
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq'];
        return suspiciousTLDs.some(tld => hostname.endsWith(tld));
    }

    /**
     * Simula predição do RandomForest
     * SUBSTITUA isso pela sua implementação real do RandomForest
     */
    async predictWithRandomForest(features) {
        // Aqui você deve usar seu modelo RandomForest real
        // Este é apenas um exemplo mockado

        // Exemplo: calcular score baseado em features suspeitas
        let suspiciousScore = 0;

        if (features.has_ip) suspiciousScore += 0.3;
        if (!features.has_https) suspiciousScore += 0.2;
        if (features.has_at_symbol) suspiciousScore += 0.25;
        if (features.url_length > 100) suspiciousScore += 0.15;
        if (features.has_suspicious_tld) suspiciousScore += 0.1;

        const isPhishing = suspiciousScore > 0.5;
        const confidence = Math.min(0.95, 0.5 + suspiciousScore);

        return {
            prediction: isPhishing,
            confidence: confidence
        };
    }

    /**
     * Analisa URL usando RandomForest e fallback para Transformer se necessário
     */
    async analyzeURL(url) {
        try {
            // 1. Extrair features
            const features = this.extractFeatures(url);
            console.log('Features extraídas:', features);

            // 2. Predição com RandomForest
            const rfResult = await this.predictWithRandomForest(features);
            console.log('Resultado RandomForest:', rfResult);

            // 3. Se confiança é alta, retornar resultado direto
            if (rfResult.confidence >= API_CONFIG.confidenceThreshold) {
                return {
                    isPhishing: rfResult.prediction,
                    confidence: rfResult.confidence,
                    modelUsed: 'RandomForest',
                    analysis: `RandomForest detectou com alta confiança (${(rfResult.confidence * 100).toFixed(1)}%)`
                };
            }

            // 4. Confiança baixa - usar API de fallback
            console.log('Confiança baixa, consultando API de fallback...');

            const apiResult = await this.callFallbackAPI(features, rfResult.confidence, rfResult.prediction, url);

            return apiResult;

        } catch (error) {
            console.error('Erro na análise:', error);

            // Fallback para resultado do RF em caso de erro na API
            const rfResult = await this.predictWithRandomForest(this.extractFeatures(url));

            return {
                isPhishing: rfResult.prediction,
                confidence: rfResult.confidence,
                modelUsed: 'RandomForest (API indisponível)',
                analysis: `API de fallback indisponível. Usando apenas RandomForest.`,
                error: error.message
            };
        }
    }

    /**
     * Chama a API de fallback
     */
    async callFallbackAPI(features, rfConfidence, rfPrediction, url) {
        const response = await fetch(`${this.apiUrl}/predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                features: features,
                rf_confidence: rfConfidence,
                rf_prediction: rfPrediction,
                url: url
            }),
            signal: AbortSignal.timeout(API_CONFIG.timeout)
        });

        if (!response.ok) {
            throw new Error(`API retornou status ${response.status}`);
        }

        const data = await response.json();

        return {
            isPhishing: data.is_phishing,
            confidence: data.final_confidence,
            modelUsed: data.model_used,
            rfConfidence: data.rf_confidence,
            transformerConfidence: data.transformer_confidence,
            analysis: data.analysis
        };
    }

    /**
     * Analisa múltiplas URLs em lote
     */
    async analyzeBatch(urls) {
        const requests = urls.map(url => {
            const features = this.extractFeatures(url);
            const rfResult = this.predictWithRandomForest(features);

            return {
                features: features,
                rf_confidence: rfResult.confidence,
                rf_prediction: rfResult.prediction,
                url: url
            };
        });

        const response = await fetch(`${this.apiUrl}/predict-batch`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requests),
            signal: AbortSignal.timeout(API_CONFIG.timeout * 2) // Mais tempo para batch
        });

        if (!response.ok) {
            throw new Error(`API retornou status ${response.status}`);
        }

        return await response.json();
    }
}

// ==============================================================
// EXEMPLO DE USO NA EXTENSÃO
// ==============================================================

// Instanciar detector
const detector = new PhishingDetector();

// Exemplo 1: Analisar URL atual
async function checkCurrentPage() {
    const currentURL = window.location.href;
    console.log(`Analisando: ${currentURL}`);

    const result = await detector.analyzeURL(currentURL);

    console.log('Resultado:', result);

    // Mostrar alerta se for phishing
    if (result.isPhishing) {
        showPhishingWarning(result);
    }
}

// Exemplo 2: Analisar todos os links da página
async function checkAllLinks() {
    const links = document.querySelectorAll('a[href]');
    const urls = Array.from(links).map(link => link.href);

    console.log(`Analisando ${urls.length} links...`);

    // Analisar em lotes de 10
    const batchSize = 10;
    for (let i = 0; i < urls.length; i += batchSize) {
        const batch = urls.slice(i, i + batchSize);
        const results = await detector.analyzeBatch(batch);

        results.forEach((result, index) => {
            if (result.is_phishing) {
                console.warn(`Link suspeito encontrado: ${batch[index]}`);
                // Marcar link como suspeito na página
                markLinkAsSuspicious(batch[index]);
            }
        });
    }
}

// Exemplo 3: Listener para clicks em links
document.addEventListener('click', async (event) => {
    const link = event.target.closest('a[href]');

    if (link) {
        const url = link.href;

        // Verificar se deve analisar (ignora links internos, etc)
        if (shouldAnalyzeURL(url)) {
            // Prevenir navegação imediata
            event.preventDefault();

            // Analisar URL
            const result = await detector.analyzeURL(url);

            // Se for phishing, mostrar aviso
            if (result.isPhishing) {
                const proceed = confirm(
                    `⚠️ ATENÇÃO: Este link pode ser perigoso!\n\n` +
                    `Modelo: ${result.modelUsed}\n` +
                    `Confiança: ${(result.confidence * 100).toFixed(1)}%\n` +
                    `Análise: ${result.analysis}\n\n` +
                    `Deseja continuar mesmo assim?`
                );

                if (!proceed) {
                    return; // Não navegar
                }
            }

            // Navegar para o link
            window.location.href = url;
        }
    }
});

// ==============================================================
// FUNÇÕES AUXILIARES
// ==============================================================

function shouldAnalyzeURL(url) {
    // Ignora links internos, âncoras, javascript:, etc
    return url.startsWith('http') && !url.includes(window.location.hostname);
}

function showPhishingWarning(result) {
    // Criar banner de aviso no topo da página
    const banner = document.createElement('div');
    banner.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        background: #ff4444;
        color: white;
        padding: 15px;
        text-align: center;
        z-index: 999999;
        font-family: Arial, sans-serif;
    `;

    banner.innerHTML = `
        <strong>⚠️ AVISO DE SEGURANÇA</strong><br>
        Esta página pode ser uma tentativa de phishing!<br>
        <small>Confiança: ${(result.confidence * 100).toFixed(1)}% | Modelo: ${result.modelUsed}</small>
    `;

    document.body.insertBefore(banner, document.body.firstChild);
}

function markLinkAsSuspicious(url) {
    const links = document.querySelectorAll(`a[href="${url}"]`);
    links.forEach(link => {
        link.style.cssText += `
            background: #ffcccc !important;
            border: 2px solid #ff0000 !important;
            padding: 2px !important;
        `;
        link.title = '⚠️ Link potencialmente perigoso';
    });
}

// ==============================================================
// INICIALIZAÇÃO
// ==============================================================

// Verificar saúde da API ao carregar
detector.checkAPIHealth().then(healthy => {
    if (healthy) {
        console.log('✓ API de fallback está online');
    } else {
        console.warn('⚠ API de fallback não está disponível - usando apenas RandomForest');
    }
});

// Exportar para uso em outros scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { PhishingDetector, API_CONFIG };
}
