#!/usr/bin/env python3
"""
Script de teste para a Phishing Detection API
"""

import requests
import json
from typing import Dict, Any


API_URL = "http://localhost:8000"


def test_health():
    """Testa o endpoint de health check"""
    print("=" * 60)
    print("Testando Health Check...")
    print("=" * 60)

    try:
        response = requests.get(f"{API_URL}/health")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"Erro: {e}")
        return False


def test_predict_high_confidence():
    """Testa predição com alta confiança do RandomForest"""
    print("\n" + "=" * 60)
    print("Teste 1: RandomForest com ALTA confiança (deve usar RF)")
    print("=" * 60)

    payload = {
        "features": {
            "url_length": 25,
            "has_ip": False,
            "num_dots": 2,
            "has_https": True,
            "has_at_symbol": False,
            "num_subdomains": 1
        },
        "rf_confidence": 0.92,
        "rf_prediction": False,
        "url": "https://google.com"
    }

    try:
        response = requests.post(f"{API_URL}/predict", json=payload)
        print(f"Status Code: {response.status_code}")
        print(f"Request: {json.dumps(payload, indent=2)}")
        print(f"\nResponse:")
        result = response.json()
        print(json.dumps(result, indent=2, ensure_ascii=False))

        assert result["model_used"] == "RandomForest", "Deveria usar RandomForest"
        print("\n✓ Teste passou: RandomForest foi usado corretamente")
        return True

    except Exception as e:
        print(f"✗ Erro: {e}")
        return False


def test_predict_low_confidence():
    """Testa predição com baixa confiança do RandomForest"""
    print("\n" + "=" * 60)
    print("Teste 2: RandomForest com BAIXA confiança (deve usar Transformer)")
    print("=" * 60)

    payload = {
        "features": {
            "url_length": 150,
            "has_ip": True,
            "num_dots": 8,
            "has_https": False,
            "has_at_symbol": True,
            "num_subdomains": 5,
            "suspicious_words": ["login", "verify", "account"]
        },
        "rf_confidence": 0.55,
        "rf_prediction": True,
        "url": "http://192.168.1.1.suspicious-login-verify.com/@phishing"
    }

    try:
        response = requests.post(f"{API_URL}/predict", json=payload)
        print(f"Status Code: {response.status_code}")
        print(f"Request: {json.dumps(payload, indent=2)}")
        print(f"\nResponse:")
        result = response.json()
        print(json.dumps(result, indent=2, ensure_ascii=False))

        assert result["model_used"] == "Transformer", "Deveria usar Transformer"
        print("\n✓ Teste passou: Transformer foi usado corretamente")
        return True

    except Exception as e:
        print(f"✗ Erro: {e}")
        return False


def test_predict_disagreement():
    """Testa caso onde modelos discordam"""
    print("\n" + "=" * 60)
    print("Teste 3: Modelos discordam (baixa confiança RF)")
    print("=" * 60)

    payload = {
        "features": {
            "url_length": 60,
            "has_ip": False,
            "num_dots": 3,
            "has_https": True
        },
        "rf_confidence": 0.60,
        "rf_prediction": True,  # RF diz que é phishing
        "url": "https://example-test.com"
    }

    try:
        response = requests.post(f"{API_URL}/predict", json=payload)
        print(f"Status Code: {response.status_code}")
        print(f"Request: {json.dumps(payload, indent=2)}")
        print(f"\nResponse:")
        result = response.json()
        print(json.dumps(result, indent=2, ensure_ascii=False))

        print("\n✓ Teste passou: API respondeu corretamente")
        return True

    except Exception as e:
        print(f"✗ Erro: {e}")
        return False


def test_predict_batch():
    """Testa endpoint de predição em lote"""
    print("\n" + "=" * 60)
    print("Teste 4: Predições em lote")
    print("=" * 60)

    payload = [
        {
            "features": {"url_length": 25, "has_ip": False},
            "rf_confidence": 0.85,
            "rf_prediction": False,
            "url": "https://google.com"
        },
        {
            "features": {"url_length": 150, "has_ip": True},
            "rf_confidence": 0.45,
            "rf_prediction": True,
            "url": "http://suspicious.com"
        }
    ]

    try:
        response = requests.post(f"{API_URL}/predict-batch", json=payload)
        print(f"Status Code: {response.status_code}")
        print(f"\nResponse:")
        result = response.json()
        print(json.dumps(result, indent=2, ensure_ascii=False))

        assert len(result) == 2, "Deveria retornar 2 resultados"
        print("\n✓ Teste passou: Batch funcionou corretamente")
        return True

    except Exception as e:
        print(f"✗ Erro: {e}")
        return False


def main():
    """Executa todos os testes"""
    print("\n🚀 Iniciando testes da Phishing Detection API\n")

    # Verificar se a API está online
    if not test_health():
        print("\n❌ API não está respondendo. Verifique se está rodando em http://localhost:8000")
        return

    # Executar testes
    results = []
    results.append(("Health Check", test_health()))
    results.append(("Alta Confiança RF", test_predict_high_confidence()))
    results.append(("Baixa Confiança RF", test_predict_low_confidence()))
    results.append(("Modelos Discordam", test_predict_disagreement()))
    results.append(("Predição em Lote", test_predict_batch()))

    # Resumo
    print("\n" + "=" * 60)
    print("RESUMO DOS TESTES")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✓ PASSOU" if result else "✗ FALHOU"
        print(f"{status}: {name}")

    print(f"\nResultado: {passed}/{total} testes passaram")

    if passed == total:
        print("\n🎉 Todos os testes passaram!")
    else:
        print(f"\n⚠️  {total - passed} teste(s) falharam")


if __name__ == "__main__":
    main()
