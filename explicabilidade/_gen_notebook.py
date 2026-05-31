# -*- coding: utf-8 -*-
"""Gera explicabilidade_modelos.ipynb (notebook Colab T4).

Monta o .ipynb via json para evitar erros de escape. Rode:
    python _gen_notebook.py
"""
import json
from pathlib import Path

cells = []

def md(src):
    cells.append({"cell_type": "markdown", "metadata": {}, "source": src})

def code(src):
    cells.append({
        "cell_type": "code",
        "metadata": {},
        "execution_count": None,
        "outputs": [],
        "source": src,
    })

# ---------------------------------------------------------------------------
md("""# Explicabilidade dos Modelos do TCC — SHAP & Atenção

**Objetivo:** gerar explicabilidade para os **três modelos em produção** do detector de phishing:

| Modelo | Tipo | Técnica de explicabilidade |
|---|---|---|
| **DomURLs-BERT** (`amahdaouy/DomURLs_BERT` fine-tuned) | Transformer (URL) | SHAP de tokens + Atenção |
| **DistilBERT email** (`cybersectony/phishing-email-detection-distilbert_v2.4.1`) | Transformer (texto de email) | SHAP de tokens + Atenção |
| **CatBoost** (`catboost_cascata.cbm`) | Gradient boosting (24 features) | SHAP nativo (TreeSHAP) |

**Ambiente:** Google Colab com GPU **T4** (Runtime > Change runtime type > T4 GPU).
A GPU acelera os transformers; o CatBoost roda em CPU.

**Saídas:** figuras `.png`/`.html` salvas em `OUTPUT_DIR` (Google Drive), prontas para o capítulo
*Desenvolvimento* do TCC.

> **Por que SHAP + atenção?** SHAP dá atribuição de importância rigorosa e comparável entre os
> três modelos (mesmo arcabouço teórico de Shapley values). A atenção complementa nos transformers,
> mostrando visualmente em quais tokens o modelo "olha". Para o CatBoost usamos TreeSHAP nativo,
> que trata corretamente as 3 features categóricas (`registrar`, `country_code`, `tls_issuer`).""")

# ---------------------------------------------------------------------------
code("""# ============================================================
# 1. GPU + Instalação de dependências
# ============================================================
import torch
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
if torch.cuda.is_available():
    print(f'GPU: {torch.cuda.get_device_name(0)} '
          f'({torch.cuda.get_device_properties(0).total_memory/1e9:.1f} GB)')
else:
    print('AVISO: sem GPU. Os transformers rodarao na CPU (mais lento, mas funciona).')
    print('Para acelerar: Runtime > Change runtime type > T4 GPU')
print(f'Device: {device}')

# shap e catboost nao vem no Colab por padrao; transformers/torch ja vem.
!pip install -q shap catboost""")

# ---------------------------------------------------------------------------
code("""# ============================================================
# 2. Imports
# ============================================================
import os, json, gc, html
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # backend nao-interativo p/ salvar PNG de forma estavel
import matplotlib.pyplot as plt
import shap
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

print('shap        :', shap.__version__)
import transformers; print('transformers:', transformers.__version__)
import catboost;     print('catboost    :', catboost.__version__)""")

# ---------------------------------------------------------------------------
code("""# ============================================================
# 3. Configuracao (ajuste os caminhos se necessario)
# ============================================================
# DomURLs-BERT fine-tuned (mesma convencao do notebook de fine-tuning)
DOMURLS_DIR  = '/content/drive/MyDrive/TCC-Finetuning-DomURLs-BERT/modelo-final'

# CatBoost cascata (mesma convencao do notebook de treino do CatBoost)
CATBOOST_DIR      = '/content/drive/MyDrive/phishing_catboost_cascata'
CATBOOST_CBM      = f'{CATBOOST_DIR}/catboost_cascata.cbm'
CATBOOST_CSV      = f'{CATBOOST_DIR}/dataset_cascata_20k.csv'
FEATURE_COLS_JSON = f'{CATBOOST_DIR}/feature_columns.json'

# DistilBERT email — baixado direto do HuggingFace Hub (nao precisa de Drive)
EMAIL_MODEL_ID = 'cybersectony/phishing-email-detection-distilbert_v2.4.1'

# Saida
OUTPUT_DIR = '/content/drive/MyDrive/TCC-Explicabilidade'

MAX_LENGTH_URL   = 192    # igual ao usado no fine-tuning do DomURLs-BERT
MAX_LENGTH_EMAIL = 512
N_BACKGROUND_CB  = 200    # background p/ TreeSHAP do CatBoost
N_EXPLAIN_CB     = 2000   # amostras p/ beeswarm do CatBoost (subset p/ velocidade)
RANDOM_STATE     = 42

# ----- Exemplos representativos para os transformers -----
# DomURLs-BERT foi treinado no formato multimodal "[URL] ... [WHOIS] ... [EXTRA] ...".
# Incluimos tambem URLs cruas (formato atual de producao) para comparar.
EXEMPLOS_URL = [
    ('[URL] https://www.google.com [WHOIS] unknown [EXTRA] length=24 tls=1', 'LEGIT'),
    ('[URL] https://www.bb.com.br [WHOIS] unknown [EXTRA] length=22 tls=1',  'LEGIT'),
    ('[URL] http://192.168.1.1.login.xyz/steal [WHOIS] unknown [EXTRA] length=38 tls=0', 'PHISH'),
    ('[URL] http://bb-seguranca.ml/acesso [WHOIS] unknown [EXTRA] length=32 tls=0',      'PHISH'),
    ('[URL] http://paypal-verify.xyz/account [WHOIS] unknown [EXTRA] length=35 tls=0',   'PHISH'),
    ('https://www.google.com',               'LEGIT'),   # URL crua
    ('http://192.168.1.1.login.xyz/steal',   'PHISH'),   # URL crua
]

# DistilBERT email: o modelo opera em ingles (a API traduz PT->EN antes).
EXEMPLOS_EMAIL = [
    ('From: security@paypal-verify.com\\n'
     'Subject: Your account has been suspended\\n\\n'
     'Dear customer, we detected unusual activity on your account. '
     'Click http://paypal-verify.xyz/account to verify your identity within 24 hours '
     'or your account will be permanently closed.', 'PHISH'),
    ('From: noreply@github.com\\n'
     'Subject: Your weekly digest\\n\\n'
     'Here is a summary of activity in your repositories this week. '
     'Thanks for using GitHub!', 'LEGIT'),
]
print('Config carregada.')""")

# ---------------------------------------------------------------------------
code("""# ============================================================
# 4. Montar Google Drive + criar pasta de saida
# ============================================================
from google.colab import drive
drive.mount('/content/drive')
os.makedirs(OUTPUT_DIR, exist_ok=True)
print('Saida:', OUTPUT_DIR)

def savefig(name):
    \"\"\"Salva a figura matplotlib atual no OUTPUT_DIR.\"\"\"
    path = os.path.join(OUTPUT_DIR, name)
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print('  salvo:', path)""")

# ---------------------------------------------------------------------------
code("""# ============================================================
# 5. Funcoes auxiliares (SHAP de texto + atencao) reutilizadas pelos 2 BERTs
# ============================================================
def make_logit_fn(mdl, tok, dev, max_length):
    \"\"\"f(list[str]) -> LOGITS (n, n_classes). Explicamos o logit, nao a prob softmax:
    perto da saturacao o softmax quase nao muda ao mascarar tokens (atribuicoes ~0,
    \"+0\"). O logit tem escala maior e produz contribuicoes por token legiveis.\"\"\"
    def f(texts):
        texts = [str(t) for t in (texts.tolist() if hasattr(texts, 'tolist') else texts)]
        enc = tok(texts, return_tensors='pt', padding=True,
                  truncation=True, max_length=max_length)
        enc = {k: v.to(dev) for k, v in enc.items()}
        with torch.no_grad():
            logits = mdl(**enc).logits
        return logits.cpu().numpy()
    return f

def _limpar_token(t):
    t = str(t)
    return t[2:] if t.startswith('##') else t.replace('\\u0120', '').replace('\\u010a', '')

def barra_tokens_limpa(values, tokens, titulo, fname, topk=15):
    \"\"\"Barra horizontal limpa por token (sem dendrograma/+0/labels mesclados).\"\"\"
    values = np.asarray(values, dtype=float)
    tokens = [_limpar_token(t) for t in tokens]
    absv = np.abs(values)
    vmax = absv.max() if absv.size else 0.0
    cand = [j for j in np.argsort(absv)[::-1][:topk] if vmax > 0 and absv[j] >= 0.01 * vmax]
    if not cand:
        cand = list(np.argsort(absv)[::-1][:min(topk, len(values))])
    cand = sorted(cand, key=lambda j: values[j])
    v = values[cand]
    labels = [tokens[j] if tokens[j].strip() else '·' for j in cand]
    colors = ['#ff0051' if x > 0 else '#008bfb' for x in v]
    plt.figure(figsize=(7.5, max(3, len(v) * 0.42)))
    plt.barh(range(len(v)), v, color=colors)
    plt.yticks(range(len(v)), labels, fontsize=9)
    plt.axvline(0, color='k', lw=0.8)
    span = max(abs(v.min()), abs(v.max())) if v.size else 1.0
    for i, x in enumerate(v):
        plt.text(x + (0.01 * span if x >= 0 else -0.01 * span), i, f'{x:+.2f}',
                 va='center', ha='left' if x >= 0 else 'right', fontsize=8, color=colors[i])
    plt.xlim(-span * 1.25, span * 1.25)
    plt.xlabel('contribuicao SHAP p/ logit de phishing')
    plt.title(titulo, fontsize=9)
    savefig(fname)

def explicar_shap_texto(mdl, tok, dev, exemplos, max_length, phish_idx,
                        label_names, prefixo):
    \"\"\"Gera SHAP de tokens: HTML interativo (todos) + barra limpa por exemplo.\"\"\"
    f = make_logit_fn(mdl, tok, dev, max_length)
    masker = shap.maskers.Text(tok)
    explainer = shap.Explainer(f, masker, output_names=label_names)

    textos = [e[0] for e in exemplos]
    sv = explainer(textos)  # Explanation (n_textos, n_tokens, n_classes)

    html_str = shap.plots.text(sv[:, :, phish_idx], display=False)
    html_path = os.path.join(OUTPUT_DIR, f'{prefixo}_shap_texto.html')
    with open(html_path, 'w', encoding='utf-8') as fh:
        fh.write(html_str if isinstance(html_str, str) else str(html_str))
    print('  salvo:', html_path)

    for i, (texto, esperado) in enumerate(exemplos):
        svi = sv[i, :, phish_idx]
        barra_tokens_limpa(svi.values, svi.data,
                           f'{prefixo} | ex{i} ({esperado}) -> logit phishing\\n{texto[:70]}',
                           f'{prefixo}_shap_bar_ex{i}_{esperado}.png')
    return sv

def attention_rollout(attentions):
    \"\"\"Attention rollout (Abnar & Zuidema, 2020): propaga atencao entre camadas.\"\"\"
    result = None
    for a in attentions:
        a = a[0].mean(0)                       # media das cabecas -> (seq, seq)
        a = a + torch.eye(a.size(0), device=a.device)
        a = a / a.sum(dim=-1, keepdim=True)
        result = a if result is None else a @ result
    return result                               # (seq, seq)

def explicar_atencao(mdl, tok, dev, texto, max_length, titulo, prefixo, idx):
    \"\"\"Gera 2 figuras: importancia por token (rollout do CLS) + heatmap ultima camada.\"\"\"
    enc = tok(texto, return_tensors='pt', truncation=True, max_length=max_length)
    enc = {k: v.to(dev) for k, v in enc.items()}
    with torch.no_grad():
        out = mdl(**enc, output_attentions=True)
    toks = tok.convert_ids_to_tokens(enc['input_ids'][0])
    atts = out.attentions                       # tuple(n_layers) -> (1, heads, seq, seq)
    if atts is None:
        raise RuntimeError("attentions=None — carregue o modelo com attn_implementation='eager'")

    # (a) importancia por token = atencao do [CLS] via rollout
    # remove tokens especiais ([CLS]/[SEP]/[PAD]...) que dominam o rollout
    roll = attention_rollout(atts)
    cls_attn = roll[0].cpu().numpy()
    especiais = set(tok.all_special_tokens)
    validos = [j for j in range(len(toks)) if toks[j] not in especiais] or list(range(len(toks)))
    cls_v = np.array([cls_attn[j] for j in validos])
    toks_v = [_limpar_token(toks[j]) for j in validos]
    sel = np.argsort(cls_v)[::-1][:20]
    sel = sel[np.argsort(cls_v[sel])]
    plt.figure(figsize=(7.5, max(3, len(sel) * 0.32)))
    plt.barh(range(len(sel)), cls_v[sel], color='#cc3333')
    plt.yticks(range(len(sel)), [toks_v[j] for j in sel], fontsize=9)
    plt.xlabel('Atencao do [CLS] (rollout, sem tokens especiais)')
    plt.title(f'{titulo}\\n{texto[:70]}', fontsize=9)
    savefig(f'{prefixo}_atencao_tokens_ex{idx}.png')

    # (b) heatmap da ultima camada (media das cabecas)
    last = atts[-1][0].mean(0).cpu().numpy()
    n = min(len(toks), 40)
    plt.figure(figsize=(8, 7))
    plt.imshow(last[:n, :n], cmap='viridis', aspect='auto')
    plt.colorbar(fraction=0.046)
    plt.xticks(range(n), toks[:n], rotation=90, fontsize=6)
    plt.yticks(range(n), toks[:n], fontsize=6)
    plt.title(f'{titulo} — atencao ultima camada (media cabecas)', fontsize=9)
    savefig(f'{prefixo}_atencao_heatmap_ex{idx}.png')

print('Funcoes auxiliares definidas.')""")

# ===========================================================================
# PARTE A — DomURLs-BERT
# ===========================================================================
md("""---
## Parte A — DomURLs-BERT (classificador de URLs)

Carrega o modelo fine-tuned do Drive, gera **SHAP de tokens** (quais partes da URL puxam para
phishing) e **atenção** (rollout do `[CLS]` + heatmap). Repare nos tokens especiais
`[URL]`, `[WHOIS]`, `[EXTRA]` aprendidos no fine-tuning.""")

code("""# ------------------------------------------------------------
# A1. Carregar DomURLs-BERT
# ------------------------------------------------------------
assert os.path.exists(DOMURLS_DIR), (
    f'Modelo nao encontrado em {DOMURLS_DIR}. '
    'Ajuste DOMURLS_DIR (celula 3) ou copie a pasta modelo-final/ para o Drive.')

dom_tok = AutoTokenizer.from_pretrained(DOMURLS_DIR)
dom_mdl = AutoModelForSequenceClassification.from_pretrained(
    DOMURLS_DIR, attn_implementation='eager').to(device).eval()

print('id2label:', dom_mdl.config.id2label)
print('vocab   :', dom_mdl.config.vocab_size)
DOM_LABELS = [dom_mdl.config.id2label[i] for i in range(dom_mdl.config.num_labels)]
# indice da classe phishing (procura 'phish' no nome; fallback = 1)
DOM_PHISH = next((i for i, l in dom_mdl.config.id2label.items()
                  if 'phish' in str(l).lower()), 1)
print('classe phishing -> indice', DOM_PHISH, f'({DOM_LABELS[DOM_PHISH]})')""")

code("""# ------------------------------------------------------------
# A2. SHAP de tokens — DomURLs-BERT
# ------------------------------------------------------------
sv_dom = explicar_shap_texto(dom_mdl, dom_tok, device, EXEMPLOS_URL,
                             MAX_LENGTH_URL, DOM_PHISH, DOM_LABELS, 'domurls')""")

code("""# ------------------------------------------------------------
# A3. Atencao — DomURLs-BERT (um exemplo phishing + um legitimo)
# ------------------------------------------------------------
explicar_atencao(dom_mdl, dom_tok, device,
                 '[URL] http://paypal-verify.xyz/account [WHOIS] unknown [EXTRA] length=35 tls=0',
                 MAX_LENGTH_URL, 'DomURLs-BERT (phishing)', 'domurls', idx=0)
explicar_atencao(dom_mdl, dom_tok, device,
                 '[URL] https://www.google.com [WHOIS] unknown [EXTRA] length=24 tls=1',
                 MAX_LENGTH_URL, 'DomURLs-BERT (legitimo)', 'domurls', idx=1)

del dom_mdl, dom_tok; gc.collect()
if torch.cuda.is_available(): torch.cuda.empty_cache()""")

# ===========================================================================
# PARTE B — DistilBERT email
# ===========================================================================
md("""---
## Parte B — DistilBERT (phishing de email)

Modelo `cybersectony/phishing-email-detection-distilbert_v2.4.1`, baixado do Hub.
Mesmo procedimento: **SHAP de tokens** + **atenção**. O texto é o email completo
(`From:` / `Subject:` / corpo), em inglês (na API há tradução PT→EN antes).""")

code("""# ------------------------------------------------------------
# B1. Carregar DistilBERT email
# ------------------------------------------------------------
eml_tok = AutoTokenizer.from_pretrained(EMAIL_MODEL_ID)
eml_mdl = AutoModelForSequenceClassification.from_pretrained(
    EMAIL_MODEL_ID, attn_implementation='eager').to(device).eval()

print('id2label:', eml_mdl.config.id2label)
EML_LABELS = [eml_mdl.config.id2label[i] for i in range(eml_mdl.config.num_labels)]
# A API usa o indice 1 como P(phishing); confirmamos lendo id2label.
EML_PHISH = next((i for i, l in eml_mdl.config.id2label.items()
                  if 'phish' in str(l).lower()), 1)
print('classe phishing -> indice', EML_PHISH, f'({EML_LABELS[EML_PHISH]})')""")

code("""# ------------------------------------------------------------
# B2. SHAP de tokens — DistilBERT email
# ------------------------------------------------------------
sv_eml = explicar_shap_texto(eml_mdl, eml_tok, device, EXEMPLOS_EMAIL,
                             MAX_LENGTH_EMAIL, EML_PHISH, EML_LABELS, 'email')""")

code("""# ------------------------------------------------------------
# B3. Atencao — DistilBERT email (phishing + legitimo)
# ------------------------------------------------------------
for i, (texto, esperado) in enumerate(EXEMPLOS_EMAIL):
    explicar_atencao(eml_mdl, eml_tok, device, texto, MAX_LENGTH_EMAIL,
                     f'DistilBERT email ({esperado})', 'email', idx=i)

del eml_mdl, eml_tok; gc.collect()
if torch.cuda.is_available(): torch.cuda.empty_cache()""")

# ===========================================================================
# PARTE C — CatBoost
# ===========================================================================
md("""---
## Parte C — CatBoost (24 features estruturais + WHOIS/TLS)

TreeSHAP nativo do CatBoost (`get_feature_importance(type='ShapValues')`), que trata
corretamente as 3 features categóricas. Geramos **beeswarm** (visão global), **bar**
(importância média) e **waterfall** (decisão individual de um phishing e um legítimo).""")

code("""# ------------------------------------------------------------
# C1. Carregar CatBoost + dados
# ------------------------------------------------------------
from catboost import CatBoostClassifier, Pool

assert os.path.exists(CATBOOST_CBM), f'CBM nao encontrado: {CATBOOST_CBM} (ajuste a celula 3)'
cb = CatBoostClassifier(); cb.load_model(CATBOOST_CBM)

with open(FEATURE_COLS_JSON) as fh:
    feat = json.load(fh)
COLS = feat['feature_columns']
CAT  = feat['cat_features']
print(f'{len(COLS)} features ({len(CAT)} categoricas: {CAT})')

df_cb = pd.read_csv(CATBOOST_CSV)
X = df_cb[COLS].copy()
for c in CAT:                      # categoricas como string (formato do treino)
    X[c] = X[c].astype(str)
y = df_cb['label'].values
print('dataset:', X.shape)""")

code("""# ------------------------------------------------------------
# C2. Calcular ShapValues (TreeSHAP nativo) num subset
# ------------------------------------------------------------
n = min(N_EXPLAIN_CB, len(X))
rng = np.random.RandomState(RANDOM_STATE)
idx = rng.choice(len(X), size=n, replace=False)
Xs = X.iloc[idx].reset_index(drop=True)
ys = y[idx]

pool = Pool(Xs, cat_features=CAT)
shap_raw = cb.get_feature_importance(pool, type='ShapValues')  # (n, n_feat+1)
base_values = shap_raw[:, -1]
shap_values = shap_raw[:, :-1]
print('ShapValues:', shap_values.shape, '| base medio:', float(base_values.mean()))

# data numerica p/ coloracao do beeswarm (categoricas -> codigos)
X_enc = Xs.copy()
for c in CAT:
    X_enc[c] = X_enc[c].astype('category').cat.codes
expl = shap.Explanation(values=shap_values, base_values=base_values,
                        data=X_enc.values, feature_names=COLS)""")

code("""# ------------------------------------------------------------
# C3. Beeswarm + Bar (visao global) — CatBoost
# ------------------------------------------------------------
shap.plots.beeswarm(expl, max_display=24, show=False)
plt.title('CatBoost — SHAP beeswarm (impacto por feature)', fontsize=10)
savefig('catboost_shap_beeswarm.png')

shap.plots.bar(expl, max_display=24, show=False)
plt.title('CatBoost — importancia media |SHAP|', fontsize=10)
savefig('catboost_shap_bar.png')""")

code("""# ------------------------------------------------------------
# C4. Waterfall — decisao individual (1 phishing + 1 legitimo)
# ------------------------------------------------------------
i_phish = int(np.where(ys == 1)[0][0])
i_legit = int(np.where(ys == 0)[0][0])
for tag, i in [('phishing', i_phish), ('legitimo', i_legit)]:
    shap.plots.waterfall(expl[i], max_display=15, show=False)
    plt.title(f'CatBoost — waterfall ({tag}) | url: {df_cb.iloc[idx[i]]["url"][:60]}',
              fontsize=9)
    savefig(f'catboost_shap_waterfall_{tag}.png')""")

# ---------------------------------------------------------------------------
md("""---
## Resumo

As figuras foram salvas em `OUTPUT_DIR` (Google Drive):

**DomURLs-BERT** — `domurls_shap_texto.html`, `domurls_shap_bar_ex*.png`,
`domurls_atencao_tokens_ex*.png`, `domurls_atencao_heatmap_ex*.png`

**DistilBERT email** — `email_shap_texto.html`, `email_shap_bar_ex*.png`,
`email_atencao_tokens_ex*.png`, `email_atencao_heatmap_ex*.png`

**CatBoost** — `catboost_shap_beeswarm.png`, `catboost_shap_bar.png`,
`catboost_shap_waterfall_{phishing,legitimo}.png`

Baixe do Drive e insira no capítulo **Desenvolvimento** do TCC. Para trocar os exemplos
explicados, edite `EXEMPLOS_URL` / `EXEMPLOS_EMAIL` (célula 3) e re-rode a seção correspondente.""")

code("""# Lista final dos arquivos gerados
print('Arquivos em', OUTPUT_DIR, ':')
for f in sorted(os.listdir(OUTPUT_DIR)):
    print('  ', f)""")

# ---------------------------------------------------------------------------
nb = {
    "cells": cells,
    "metadata": {
        "accelerator": "GPU",
        "colab": {"provenance": [], "gpuType": "T4"},
        "kernelspec": {"display_name": "Python 3", "name": "python3"},
        "language_info": {"name": "python"},
    },
    "nbformat": 4,
    "nbformat_minor": 0,
}

out = Path(__file__).parent / "explicabilidade_modelos.ipynb"
out.write_text(json.dumps(nb, ensure_ascii=False, indent=1), encoding="utf-8")
print("Notebook gerado:", out, "| celulas:", len(cells))
