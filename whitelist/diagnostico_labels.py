"""
Diagnostico rapido: verifica se as labels do modelo estao invertidas.

Uso (na maquina onde o modelo esta carregado):
  python diagnostico_labels.py [--model-path ../phishing-api/model]

Se nao tiver o modelo local, use --api-url para testar via API.
"""

import argparse
import json
import sys


def check_model_config(model_path: str):
    """Verifica id2label no config.json do modelo."""
    import os

    config_path = os.path.join(model_path, "config.json")
    if not os.path.isfile(config_path):
        print(f"  config.json nao encontrado em {model_path}")
        return

    with open(config_path) as f:
        config = json.load(f)

    print(f"\n  Modelo: {config.get('_name_or_path', 'desconhecido')}")
    print(f"  Arquitetura: {config.get('architectures', ['?'])}")
    print(f"  Num labels: {config.get('num_labels', '?')}")

    id2label = config.get("id2label", {})
    label2id = config.get("label2id", {})

    print(f"\n  id2label: {json.dumps(id2label, indent=4)}")
    print(f"  label2id: {json.dumps(label2id, indent=4)}")

    if id2label:
        label_0 = id2label.get("0", id2label.get(0, "?"))
        label_1 = id2label.get("1", id2label.get(1, "?"))
        print(f"\n  Classe 0 = {label_0}")
        print(f"  Classe 1 = {label_1}")

        # Checar se o codigo da API esta correto
        # O codigo assume: classe 0 = legitimo, classe 1 = phishing
        code_assumes_0 = "legitimo"
        code_assumes_1 = "phishing"

        l0 = str(label_0).lower()
        l1 = str(label_1).lower()

        if any(k in l1 for k in ["phish", "malicious", "spam", "1"]) and \
           any(k in l0 for k in ["legit", "benign", "safe", "0"]):
            print("\n  RESULTADO: Labels CORRETAS (classe 0=legitimo, 1=phishing)")
            print("  O problema NAO e inversao de labels.")
        elif any(k in l0 for k in ["phish", "malicious", "spam"]) and \
             any(k in l1 for k in ["legit", "benign", "safe"]):
            print("\n  RESULTADO: Labels INVERTIDAS!")
            print("  O modelo usa classe 0=phishing, 1=legitimo")
            print("  Mas o codigo assume classe 0=legitimo, 1=phishing")
            print("\n  CORRECAO: trocar probabilities[0][1] por probabilities[0][0] em app.py")
        else:
            print(f"\n  RESULTADO: Labels nao-padrao ({label_0}, {label_1})")
            print("  Verifique manualmente qual classe e phishing.")
    else:
        print("\n  ATENCAO: id2label nao encontrado no config.json!")
        print("  Verifique o mapeamento de classes manualmente.")


def check_via_api(api_url: str):
    """Testa via API para inferir se labels estao invertidas."""
    import requests

    print(f"\n  Testando via API ({api_url})...")

    # URLs obvias para teste
    tests = [
        ("https://www.google.com/", "LEGITIMO"),
        ("http://192.168.1.1.fake-login.xyz/steal", "PHISHING"),
    ]

    for url, expected in tests:
        features = {
            "length": len(url), "dom_length": 10, "dot": url.count("."),
            "hyphen": url.count("-"), "slash": url.count("/"), "at": 0,
            "params": 0, "shortened": 0, "tls": 1 if "https" in url else 0,
            "vowels_domain": 3, "email": 0,
        }
        try:
            r = requests.post(
                f"{api_url}/predict",
                json={"url": url, "client_features": features},
                timeout=30,
            )
            data = r.json()
            status = "OK" if data["label"] == expected else "INVERTIDO"
            print(f"    {url[:45]:47s} -> {data['label']:10s} (conf: {data['confidence']}) [{status}]")
        except Exception as e:
            print(f"    {url[:45]:47s} -> ERRO: {e}")

    print("\n  Se ambos estao INVERTIDO, as classes do modelo estao trocadas.")
    print("  Correcao: trocar probabilities[0][1] por probabilities[0][0] em app.py")


def main():
    parser = argparse.ArgumentParser(description="Diagnostico de labels do modelo")
    parser.add_argument("--model-path", default="../phishing-api/model",
                        help="Caminho para o diretorio do modelo")
    parser.add_argument("--api-url", default=None,
                        help="URL da API (se o modelo nao estiver local)")
    args = parser.parse_args()

    print("=" * 60)
    print("  DIAGNOSTICO DE LABELS DO MODELO DomURLs-BERT")
    print("=" * 60)

    check_model_config(args.model_path)

    if args.api_url:
        check_via_api(args.api_url)
    else:
        print("\n  Dica: use --api-url http://localhost:8000 para testar via API")

    print("=" * 60)


if __name__ == "__main__":
    main()
