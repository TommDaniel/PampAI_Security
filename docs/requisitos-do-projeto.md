# Requisitos do Projeto — PampAI Security

**Documento técnico-suplementar do Trabalho de Conclusão de Curso (TCC).**

Este documento complementa a Seção 1.1 (Problema da Pesquisa) do Capítulo 1 da monografia. Ele consolida o detalhamento das definições operacionais, das questões derivadas, do escopo e limitações, e dos critérios de sucesso adotados na fase de proposta do TCC.

**Discente:** Daniel Felipe Tomm
**Orientador:** Prof. Dr. Sandro da Silva Camargo
**Curso:** Engenharia de Computação — Universidade Federal do Pampa (Unipampa), campus Bagé
**Trabalho:** Detecção de phishing em tempo real no navegador por extensão web com aprendizado de máquina
**Produto associado:** PampAI Security — extensão Chrome (Manifest V3) + API FastAPI + dashboard administrativo + plataforma multi-tenant

**Pergunta central da pesquisa:** *como identificar tentativas de phishing diretamente no navegador e em webmails, com boa taxa de acerto e impacto mínimo na experiência de navegação do usuário?*

> **Notação de referências.** As referências bibliográficas mencionadas neste documento usam a notação `[ref. TCC: ChaveBibtex]`, que aponta para entradas catalogadas conforme ABNT NBR 6023 no arquivo `Monografia-TCC/TEXTO-Bibliografia.bib` da monografia. Os metadados completos de cada referência (autor, ano, título, periódico, DOI) estão consolidados no `.bib` do TCC. Em expansões de sigla, este documento adota o em-dash padrão de markdown — distinto da convenção LaTeX da monografia.

---

## 1. Definições operacionais

- **Latência aceitável de verificação:** o atraso adicional introduzido pela verificação é tratado como aceitável quando não é percebido pelo usuário como incômodo em relação ao tempo típico de carregamento de páginas [ref. TCC: NielsenUsability1993]. Adotam-se os percentis 50 (P50) e 95 (P95) de tempo de resposta como medidas observadas em experimentos.
- **Boa taxa de acerto:** combina taxa de verdadeiros positivos (*True Positive Rate* — TPR) elevada com taxa de falsos positivos (*False Positive Rate* — FPR) baixa em conjunto de teste fora da amostra [ref. TCC: HeGarcia2009; Li2024PhishingSoA]. Como metas-alvo da fase de proposta, fixou-se TPR em torno de 90 % e FPR próxima ou inferior a 0,5 %. Esses valores serviram de referência para as decisões de projeto; os resultados reais são apresentados no capítulo de Resultados e Discussão da monografia.
- **Conjunto mínimo de métricas:** além de TPR e FPR, foram adotadas F1-*score*, área sob a curva ROC (*Area Under the Curve* — AUC), Coeficiente de Correlação de Matthews (*Matthews Correlation Coefficient* — MCC) e latência fim-a-fim (P50/P95) [ref. TCC: Bishop2006PRML; Fawcett2006ROC; HeGarcia2009]. O conjunto reduz o risco de leitura enviesada por uma única métrica, em particular pelo paradoxo da acurácia.

---

## 2. Questões derivadas

1. **Quais sinais podem ser extraídos com baixo custo no cliente** sem degradar a experiência do usuário? Exemplos considerados incluem atributos lexicais do Localizador Padrão de Recursos (*Uniform Resource Locator* — URL), características básicas do documento *HyperText Markup Language* (HTML) e metadados leves do domínio.
2. **Qual arquitetura favorece o equilíbrio entre precisão e impacto na navegação?** A hipótese inicial considerava uma abordagem em camadas com verificação leve no navegador e verificação robusta no servidor, acionada apenas em casos ambíguos. A arquitetura efetivamente adotada e o pivô em relação à hipótese inicial são apresentados no Capítulo de Desenvolvimento da monografia.
3. **Como lidar com deriva de conceito e estratégias de evasão** (homógrafos, domínios recém-registrados, ofuscação) preservando TPR alto e FPR baixo ao longo do tempo?
4. **Como garantir privacidade e transparência** na decisão do modelo, minimizando coleta de dados sensíveis e oferecendo justificativas compreensíveis das classificações?
5. **Como avaliar de forma rigorosa** em dados representativos de tráfego real, com protocolo reprodutível e o conjunto de métricas adotado?

As cinco questões orientaram o desenvolvimento e a análise dos resultados; nem todas foram exaustivamente respondidas. O trabalho avançou principalmente na identificação de sinais leves, na implementação da arquitetura final e na rodada de avaliação experimental e validação prática. Deriva de conceito, evasão sistemática e transparência por explicações locais foram tratadas em profundidade reduzida e registradas como trabalhos futuros (no capítulo de Conclusões da monografia).

---

## 3. Escopo e limitações

- **Dentro do escopo:** detecção de phishing em páginas web acessadas via navegador de desktop compatível com *Manifest Version* 3 (MV3), no momento do acesso ou do redirecionamento; e análise de phishing em mensagens de e-mail exibidas nos webmails Gmail e Outlook, integrada à mesma extensão.
- **Fora do escopo:** análise de mensagens instantâneas (por exemplo, WhatsApp e Telegram); análise de mensagens de texto curtas (*Short Message Service* — SMS); inspeção de tráfego de rede fora do contexto do navegador; e bloqueio baseado exclusivamente em listas de URLs mantidas manualmente, sem componente de aprendizado.
- **Restrições práticas:** limitações de unidade central de processamento (CPU) e de memória no navegador; permissões e restrições impostas pelo MV3; operação sob conectividade variável; atualização periódica do modelo sem interromper o uso; e ambiente computacional disponível ao autor, cujos efeitos sobre a quantidade e a profundidade dos experimentos são detalhados no capítulo de Resultados e Discussão da monografia.

---

## 4. Critérios de sucesso

Os critérios a seguir foram declarados na fase de proposta e orientaram as decisões de projeto; o atendimento de cada um é discutido no capítulo de Resultados e Discussão da monografia.

- **Desempenho:** aproximar-se das metas-alvo de TPR e FPR, monitorando a latência fim-a-fim introduzida pela solução.
- **Eficiência:** uso de memória e CPU compatíveis com a navegação típica, sem travamentos perceptíveis nem aumento expressivo no consumo de recursos.
- **Experiência do usuário:** mensagens claras, poucas interrupções e ausência de *falsos alarmes* recorrentes que levem o usuário a ignorar os avisos.
- **Privacidade e transparência:** processamento local por padrão quando viável, envio mínimo de dados quando o apoio remoto for necessário e justificativas sucintas das decisões.
- **Reprodutibilidade:** registro e disponibilização do protocolo de avaliação, da divisão de dados e dos parâmetros relevantes, de modo a permitir a replicação dos resultados obtidos.

---

## 5. Referência cruzada com a monografia

| Tópico deste documento | Capítulo/seção correspondente na monografia |
|---|---|
| Pergunta central | §1.1 — Problema da Pesquisa (versão enxuta) |
| Definições operacionais (§1) | Cap. 3 — Metodologia (métricas e procedimento experimental) e Cap. 5 — Resultados e Discussão |
| Questões derivadas (§2) | Cap. 3 — Metodologia, Cap. 5 — Resultados e Discussão, Cap. 6 — Conclusões (trabalhos futuros) |
| Escopo e limitações (§3) | §1.1 — Problema da Pesquisa (síntese) e Cap. 6 — Conclusões (§Limitações) |
| Critérios de sucesso (§4) | Cap. 5 — Resultados e Discussão (atendimento de cada critério) |

---

## 6. Histórico de revisões

| Data | Versão | Alteração |
|---|---|---|
| 2026-05-17 | 1.0 | Criação do documento. Conteúdo migrado da §1.1 do `Problema.tex` (estado pós-B3, com referências bibliográficas Nielsen 1993, He & Garcia 2009, Li 2024, Bishop 2006 e Fawcett 2006 preservadas como notas inline `[ref. TCC: ChaveBibtex]`). |
