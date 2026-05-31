#!/usr/bin/env python3
"""
Q3 da banca — avaliacao do DistilBERT de e-mail sobre dataset rotulado (EN).

Avalia `cybersectony/phishing-email-detection-distilbert_v2.4.1` sobre o dataset
publico `zefang-liu/phishing-email-dataset` (coluna 'Email Text' + 'Email Type'
em {'Safe Email','Phishing Email'}).

O modelo tem 4 classes (model card):
    LABEL_0 = legitimate_email   LABEL_1 = phishing_url
    LABEL_2 = legitimate_url     LABEL_3 = phishing_url_alt (phishing)
Ou seja, as classes de PHISHING sao 1 e 3; as LEGITIMAS sao 0 e 2.

Reporta 3 estrategias de decisao para deixar explicito o efeito da escolha:
  - api_prob1 : phishing se prob[1] > 0.7  (exatamente o que a API faz hoje)
  - argmax_13 : phishing se argmax(prob) in {1,3}  (uso recomendado pelo card)
  - soma_13   : phishing se prob[1]+prob[3] > 0.5  (soma das classes de phishing)

REQUER: transformers, torch, datasets (todos presentes). Roda em CPU, sem GPU.

Uso:
    python q3_email_eval.py [--n 4000] [--batch 16]
"""
import argparse
import json
import random
from pathlib import Path

import torch

MODEL_ID = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
DATASET_ID = "zefang-liu/phishing-email-dataset"
OUT = Path(__file__).resolve().parent / "resultados"
EMAIL_THRESHOLD = 0.7  # EMAIL_PHISHING_THRESHOLD da API


def metricas(y_true, y_pred):
    tp = fp = tn = fn = 0
    for yt, yp in zip(y_true, y_pred):
        if yt and yp:
            tp += 1
        elif yt and not yp:
            fn += 1
        elif not yt and yp:
            fp += 1
        else:
            tn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    acc = (tp + tn) / len(y_true) if y_true else 0.0
    den = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = ((tp * tn - fp * fn) / den) if den else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 4),
            "accuracy": round(acc, 4), "mcc": round(mcc, 4)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=4000, help="tamanho da amostra (estratificada)")
    ap.add_argument("--batch", type=int, default=16)
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)

    from datasets import load_dataset
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    print(f"Carregando dataset {DATASET_ID}...")
    ds = load_dataset(DATASET_ID, split="train")
    textos, labels = [], []
    for r in ds:
        t = r.get("Email Text")
        tp = r.get("Email Type")
        if not t or not isinstance(t, str) or not t.strip() or tp not in ("Safe Email", "Phishing Email"):
            continue
        textos.append(t)
        labels.append(1 if tp == "Phishing Email" else 0)
    print(f"Exemplos validos: {len(textos)} "
          f"(phishing={sum(labels)}, legit={len(labels) - sum(labels)})")

    # Amostra estratificada deterministica
    rng = random.Random(42)
    idx_phish = [i for i, y in enumerate(labels) if y == 1]
    idx_legit = [i for i, y in enumerate(labels) if y == 0]
    rng.shuffle(idx_phish)
    rng.shuffle(idx_legit)
    metade = args.n // 2
    escolhidos = idx_phish[:metade] + idx_legit[:metade]
    rng.shuffle(escolhidos)
    X = [textos[i] for i in escolhidos]
    y = [labels[i] for i in escolhidos]
    print(f"Amostra avaliada: {len(X)} (phishing={sum(y)}, legit={len(y) - sum(y)})")

    print(f"Carregando modelo {MODEL_ID} (CPU)...")
    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)
    model.eval()

    # Inferencia em lote -> coleta prob[0..3]
    p1, p3, argm = [], [], []
    for b in range(0, len(X), args.batch):
        lote = X[b:b + args.batch]
        inputs = tok(lote, return_tensors="pt", truncation=True, max_length=512, padding=True)
        with torch.no_grad():
            probs = torch.softmax(model(**inputs).logits, dim=-1)
        for row in probs:
            p1.append(row[1].item())
            p3.append(row[3].item())
            argm.append(int(torch.argmax(row).item()))
        if (b // args.batch) % 20 == 0:
            print(f"  {min(b + args.batch, len(X))}/{len(X)}")

    estrategias = {
        "api_prob1_thr0.7": [1 if v > EMAIL_THRESHOLD else 0 for v in p1],
        "argmax_classes_1_3": [1 if a in (1, 3) else 0 for a in argm],
        "soma_p1_p3_thr0.5": [1 if (a + b) > 0.5 else 0 for a, b in zip(p1, p3)],
    }
    cenarios = {nome: metricas(y, pred) for nome, pred in estrategias.items()}

    resumo = {
        "descricao": "Q3: avaliacao do DistilBERT de e-mail (4 classes) sobre dataset EN rotulado.",
        "gerado_em": "2026-05-31",
        "modelo": MODEL_ID,
        "dataset": DATASET_ID,
        "n_avaliado": len(X),
        "phishing": sum(y),
        "legit": len(y) - sum(y),
        "limiar_api": EMAIL_THRESHOLD,
        "mapeamento_labels": {"0": "legitimate_email", "1": "phishing_url",
                              "2": "legitimate_url", "3": "phishing_url_alt"},
        "nota": ("EN apenas (sem PT). Possivel sobreposicao treino-teste: o modelo pode "
                 "ter sido treinado em fontes que incluem este dataset; tratar como teto "
                 "otimista. A API de producao usa so a estrategia api_prob1 (ignora LABEL_3)."),
        "cenarios": cenarios,
    }
    jp = OUT / "q3_email_eval.json"
    with open(jp, "w", encoding="utf-8") as fh:
        json.dump(resumo, fh, indent=2, ensure_ascii=False)
    print(f"Salvo: {jp}")

    print("\n=== Metricas por estrategia de decisao ===")
    print(f"{'estrategia':<22} {'F1':>7} {'acc':>7} {'recall':>7} {'prec':>7} {'FPR':>7} {'MCC':>7}")
    for nome, m in cenarios.items():
        print(f"{nome:<22} {m['f1']:>7.4f} {m['accuracy']:>7.4f} {m['recall']:>7.4f} "
              f"{m['precision']:>7.4f} {m['fpr']:>7.4f} {m['mcc']:>7.4f}")


if __name__ == "__main__":
    main()
