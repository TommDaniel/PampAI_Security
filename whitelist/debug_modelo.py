"""
Debug profundo do DomURLs-BERT — roda localmente sem a API.

Carrega o modelo e tokenizer diretamente e testa varios formatos de input
para identificar se o problema e:
  1. Labels invertidas (config diz 0=legit, 1=phish, mas treinamento inverteu)
  2. Formato de feature_text incompativel com treinamento
  3. Modelo base (pre-trained) sem fine-tuning adequado
  4. Modelo sempre retorna mesma classe (bias extremo)

Uso:
  cd phishing-api
  python ../whitelist/debug_modelo.py [--model-path model]
"""

import argparse
import json
import sys
import os

def main():
    parser = argparse.ArgumentParser(description="Debug profundo do DomURLs-BERT")
    parser.add_argument("--model-path", default="model",
                        help="Caminho para o diretorio do modelo")
    args = parser.parse_args()

    # Verificar modelo
    if not os.path.isdir(args.model_path):
        print(f"Diretorio do modelo nao encontrado: {args.model_path}")
        print("Execute este script a partir da pasta phishing-api/")
        sys.exit(1)

    print("=" * 70)
    print("  DEBUG PROFUNDO DO DomURLs-BERT")
    print("=" * 70)

    # Carregar config
    config_path = os.path.join(args.model_path, "config.json")
    with open(config_path) as f:
        config = json.load(f)
    print(f"\n  Modelo: {config.get('_name_or_path', '?')}")
    print(f"  id2label: {config.get('id2label', '?')}")
    print(f"  num_labels: {config.get('num_labels', '?')}")

    # Carregar modelo
    print("\n  Carregando modelo e tokenizer...")
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(args.model_path)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_path)
    model.eval()
    device = torch.device("cpu")
    model.to(device)
    print(f"  Modelo carregado em {device}")

    # ============================================================
    # TESTE 1: Inputs variados para detectar bias
    # ============================================================
    print(f"\n{'='*70}")
    print("  TESTE 1: Inputs variados (detectar bias)")
    print(f"{'='*70}")

    test_inputs = [
        # Formato completo da API
        "[URL] https://www.google.com/ [WHOIS] unknown [EXTRA] length=24 dom_length=14 dot=2 hyphen=0 slash=3 at=0 params=0 shortened=0 tls=1 vowels_domain=3 email=0",
        "[URL] http://192.168.1.1.fake-login.xyz/steal [WHOIS] unknown [EXTRA] length=42 dom_length=28 dot=5 hyphen=2 slash=2 at=0 params=0 shortened=0 tls=0 vowels_domain=4 email=0",
        # Apenas URL (como DomURLs-BERT original espera?)
        "https://www.google.com/",
        "http://192.168.1.1.fake-login.xyz/steal",
        # URL com protocolo
        "https://www.bb.com.br/site/",
        "http://bb-seguranca-atualizar.tk/login",
        # Texto aleatorio (deve dar ~50/50)
        "hello world this is a test",
        # String vazia
        "",
        # Apenas dominio
        "google.com",
        "phishing-site.tk",
    ]

    print(f"\n  {'Input (truncado)':55s} | {'Logit[0]':>8s} | {'Logit[1]':>8s} | {'P(legit)':>8s} | {'P(phish)':>8s} | {'Label':>10s}")
    print(f"  {'-'*55}-+-{'-'*8}-+-{'-'*8}-+-{'-'*8}-+-{'-'*8}-+-{'-'*10}")

    for text in test_inputs:
        inputs = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=128,
            padding=True,
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits[0]
            probs = torch.softmax(logits, dim=-1)

        p_legit = probs[0].item()
        p_phish = probs[1].item()
        label = "PHISHING" if p_phish > 0.5 else "LEGITIMO"
        display = text[:55] if text else "(vazio)"

        print(f"  {display:55s} | {logits[0].item():>8.3f} | {logits[1].item():>8.3f} | {p_legit:>7.1%} | {p_phish:>7.1%} | {label:>10s}")

    # ============================================================
    # TESTE 2: Verificar se o modelo e o DomURLs-BERT original
    # ============================================================
    print(f"\n{'='*70}")
    print("  TESTE 2: Verificar identidade do modelo")
    print(f"{'='*70}")

    # Checar se tem os tokens especiais do DomURLs-BERT
    special_tokens = ["[URL]", "[WHOIS]", "[EXTRA]", "[AGE]", "[REG]", "[EXPIRE]"]
    for token in special_tokens:
        token_id = tokenizer.convert_tokens_to_ids(token)
        unk_id = tokenizer.convert_tokens_to_ids("[UNK]")
        status = "CONHECIDO" if token_id != unk_id else "DESCONHECIDO (UNK)"
        print(f"  Token '{token}': ID={token_id} ({status})")

    # Checar vocab size
    print(f"\n  Vocab size: {tokenizer.vocab_size}")
    print(f"  Model vocab: {config.get('vocab_size', '?')}")

    # ============================================================
    # TESTE 3: Formato original DomURLs-BERT
    # ============================================================
    print(f"\n{'='*70}")
    print("  TESTE 3: Testar formato original do DomURLs-BERT")
    print(f"{'='*70}")
    print("  (o paper original pode usar formato diferente do nosso [URL]...[EXTRA])")

    # DomURLs-BERT foi treinado com URLs brutas ou com formato especial?
    # Vamos testar ambos
    url_formats = [
        ("URL bruta", "https://www.google.com"),
        ("URL bruta HTTP", "http://www.google.com"),
        ("Apenas dominio", "google.com"),
        ("Formato [URL]", "[URL] https://www.google.com"),
        ("Formato completo", "[URL] https://www.google.com [WHOIS] unknown [EXTRA] length=22 tls=1"),
        ("URL bruta phish", "http://192.168.1.1.login.xyz"),
        ("Formato [URL] phish", "[URL] http://192.168.1.1.login.xyz"),
        ("Formato completo phish", "[URL] http://192.168.1.1.login.xyz [WHOIS] unknown [EXTRA] length=30 tls=0"),
    ]

    print(f"\n  {'Formato':25s} | {'Input (truncado)':45s} | {'P(legit)':>8s} | {'P(phish)':>8s} | {'Label':>10s}")
    print(f"  {'-'*25}-+-{'-'*45}-+-{'-'*8}-+-{'-'*8}-+-{'-'*10}")

    for fmt_name, text in url_formats:
        inputs = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=128,
            padding=True,
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            probs = torch.softmax(outputs.logits[0], dim=-1)

        p_legit = probs[0].item()
        p_phish = probs[1].item()
        label = "PHISHING" if p_phish > 0.5 else "LEGITIMO"
        display = text[:45]

        print(f"  {fmt_name:25s} | {display:45s} | {p_legit:>7.1%} | {p_phish:>7.1%} | {label:>10s}")

    # ============================================================
    # TESTE 4: Batch de URLs conhecidas (ground truth)
    # ============================================================
    print(f"\n{'='*70}")
    print("  TESTE 4: URLs conhecidas com ground truth")
    print(f"{'='*70}")

    ground_truth = [
        ("https://www.google.com", "LEGITIMO"),
        ("https://www.bb.com.br", "LEGITIMO"),
        ("https://github.com", "LEGITIMO"),
        ("https://www.gov.br", "LEGITIMO"),
        ("https://www.netflix.com", "LEGITIMO"),
        ("http://192.168.1.1.login.xyz/steal", "PHISHING"),
        ("http://goggle-login.tk/signin", "PHISHING"),
        ("http://bb-seguranca.ml/acesso", "PHISHING"),
        ("http://paypal-verify.xyz/account", "PHISHING"),
        ("http://netflix-update.tk/billing", "PHISHING"),
    ]

    correct = 0
    total = len(ground_truth)

    print(f"\n  {'URL':45s} | {'Esperado':>10s} | {'P(legit)':>8s} | {'P(phish)':>8s} | {'Predicao':>10s} | {'Status':>6s}")
    print(f"  {'-'*45}-+-{'-'*10}-+-{'-'*8}-+-{'-'*8}-+-{'-'*10}-+-{'-'*6}")

    for url, expected in ground_truth:
        # Testar com URL bruta (formato mais simples)
        inputs = tokenizer(
            url,
            return_tensors="pt",
            truncation=True,
            max_length=128,
            padding=True,
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            probs = torch.softmax(outputs.logits[0], dim=-1)

        p_legit = probs[0].item()
        p_phish = probs[1].item()
        predicted = "PHISHING" if p_phish > 0.5 else "LEGITIMO"
        ok = predicted == expected
        if ok:
            correct += 1

        print(f"  {url:45s} | {expected:>10s} | {p_legit:>7.1%} | {p_phish:>7.1%} | {predicted:>10s} | {'OK' if ok else 'FAIL':>6s}")

    print(f"\n  Accuracy (URL bruta): {correct}/{total} ({correct/total*100:.0f}%)")

    # Testar com formato [URL]
    print(f"\n  Mesmo teste com formato '[URL] <url>':")
    correct2 = 0
    for url, expected in ground_truth:
        text = f"[URL] {url}"
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=128, padding=True)
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            probs = torch.softmax(outputs.logits[0], dim=-1)

        p_legit = probs[0].item()
        p_phish = probs[1].item()
        predicted = "PHISHING" if p_phish > 0.5 else "LEGITIMO"
        ok = predicted == expected
        if ok:
            correct2 += 1

        print(f"  {url:45s} | {expected:>10s} | {p_legit:>7.1%} | {p_phish:>7.1%} | {predicted:>10s} | {'OK' if ok else 'FAIL':>6s}")

    print(f"\n  Accuracy (formato [URL]): {correct2}/{total} ({correct2/total*100:.0f}%)")

    # ============================================================
    # CONCLUSAO
    # ============================================================
    print(f"\n{'='*70}")
    print("  CONCLUSAO")
    print(f"{'='*70}")

    if correct >= total * 0.8:
        print("  Modelo funciona com URL bruta.")
        print("  Problema provavel: formato [URL]...[EXTRA] nao corresponde ao treinamento.")
        print("  CORRECAO: alterar create_feature_text() para enviar apenas a URL.")
    elif correct2 >= total * 0.8:
        print("  Modelo funciona com formato [URL].")
        print("  Problema pode estar nas features extras.")
    else:
        best = max(correct, correct2)
        if best < total * 0.5:
            print("  Modelo classifica quase tudo como a mesma classe.")
            print("  Possiveis causas:")
            print("    1. Modelo nao foi fine-tuned (ainda e o base pre-treinado)")
            print("    2. Fine-tuning corrompeu os pesos")
            print("    3. Tokenizer incompativel com os pesos do modelo")
            print("    4. Labels invertidas no treinamento (apesar do config.json)")
            print("\n  Teste: inverta a logica (use probabilities[0][0] como phishing_prob)")
            print("  Se a accuracy melhorar, o treinamento usou labels invertidas.")
        else:
            print(f"  Accuracy parcial ({best}/{total}). Modelo tem alguma capacidade")
            print("  mas pode estar com problemas no formato de input.")

    print("=" * 70)


if __name__ == "__main__":
    main()
