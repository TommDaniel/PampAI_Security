# Roteiro de defesa verbal — perguntas Q5 e Q14

Perguntas da banca que **não exigem mudança no texto** do TCC — basta uma resposta
falada de 30s a 1min na arguição. Companion de `respostas-banca.md` (que cobre as
perguntas resolvidas com código/texto: Q2, Q4, Q8, Q3).

> Princípio: enquadrar como **prova de conceito**, reconhecer a limitação real sem
> rodeio e mostrar que ela é **trabalho futuro endereçável**, não um furo de método.

---

## Q5 — Tradução PT→EN no módulo de e-mail

**Pergunta:** o pipeline traduz português→inglês antes de inferir com um DistilBERT
treinado em inglês. (i) Palavras-chave de phishing em português podem se perder na
tradução? (ii) O modelo foi calibrado em distribuição de e-mails em inglês, que
pode não corresponder ao phishing brasileiro?

### Resposta falada (~1 min)
"As duas preocupações são legítimas e o trabalho não as esconde — o módulo de
e-mail é assumido como **prova de conceito de integração**, não como classificador
de produção para o português. Sobre a distribuição: eu **medi** o desempenho em
inglês (F1 de 0,988 sobre 4 mil e-mails), mas reporto esse número como **teto
otimista**, porque o checkpoint de terceiros pode ter visto esse dataset no treino,
e **não reivindico** desempenho em português — não há medição em PT. Sobre a
tradução: a análise de explicabilidade que eu gerei mostra que o modelo se apoia em
sinais que **sobrevivem à tradução** — o verbo de ação ('click'), o senso de
urgência ('suspended', 'detected'), a imitação de marca ('paypal') e o link
('http'). Esses gatilhos são estruturais e atravessam o par PT→EN. O que pode se
perder são iscas idiomáticas específicas do português, e isso eu não quantifiquei.
A correção definitiva é trocar o checkpoint por um **modelo treinado direto em
e-mails em português**, eliminando a etapa de tradução — está registrado como
trabalho futuro, e a arquitetura já permite essa troca sem mexer no resto."

### Cola de 1 linha
> É POC de integração; medi EN (F1 0,988, **teto otimista**) e **não reivindico
> PT**; a atenção mostra que os sinais fortes (click / urgência / marca / link)
> sobrevivem à tradução; modelo PT-nativo é trabalho futuro e a arquitetura aceita
> a troca.

### Se insistirem ("mas e as iscas em português?")
"Concordo que existe perda potencial e que ela não foi medida — é exatamente por
isso que o módulo não entra nas métricas principais do trabalho e que nenhuma
afirmação de campo em português é feita. Medir esse erro de tradução exige um
conjunto de e-mails rotulados em português brasileiro, que é escasso; montá-lo é
parte do trabalho futuro do pipeline de e-mail."

### Âncora no texto (se pedirem onde está)
- `Resumo.tex` — e-mail descrito "em caráter de prova de conceito".
- `Resultados.tex` (§Limitações) — avaliação EN + as duas ressalvas (só EN; possível
  contaminação = teto otimista).
- `Resultados.tex` (§Explicabilidade) — atenção/SHAP do DistilBERT (click, security,
  paypal, suspended) e a ressalva de que a decisão opera sobre o texto traduzido.

---

## Q14 — Por que não comparou com VisualPhishNet?

**Pergunta:** você cita VisualPhishNet (Abdelnabi, 2020) na Revisão como abordagem
visual via CNN tripla. Por que não comparou diretamente com ele em alguma rodada?

### Resposta falada (~45 s)
"Porque é uma **modalidade diferente**, e a comparação direta não seria justa nem
informativa. O VisualPhishNet detecta phishing por **semelhança visual**: ele
renderiza o screenshot da página e o compara, com uma CNN tripla, contra um **banco
de imagens de marcas legítimas** protegidas. A entrada dele é a página renderizada e
ele depende de uma biblioteca curada de marcas-alvo. O meu trabalho classifica a
**string da URL** mais sinais de WHOIS e DOM, antes e sem precisar renderizar a
página, em tempo constante para o que já está nas listas. São entradas diferentes
(imagem da página vs. texto da URL) e paradigmas diferentes (correspondência visual
por marca vs. classificação genérica). Coloquei o VisualPhishNet na revisão para
**mapear o estado da arte da linha visual**, não como baseline a superar — bater os
dois no mesmo benchmark exigiria construir todo um pipeline visual e o banco de
marcas, que está fora do escopo. Na verdade, as duas abordagens são
**complementares**: uma camada visual sobre a página renderizada poderia ser somada
à minha arquitetura no futuro."

### Cola de 1 linha
> Modalidade diferente: VisualPhishNet compara o **screenshot** da página contra um
> banco de marcas via CNN tripla; meu trabalho classifica a **string da URL**. Não é
> comparação direta (entradas e paradigmas distintos); citei como estado da arte
> visual, e seria **camada complementar**, não baseline.

### Se insistirem ("mas dava pra rodar os dois no seu dataset")
"Não diretamente: o meu conjunto é de URLs, e o VisualPhishNet precisa da página
renderizada e de um banco de marcas de referência. Rodá-lo exigiria coletar os
screenshots de cada URL e definir o conjunto de marcas protegidas — é um trabalho de
montagem de pipeline visual, não um ajuste de hiperparâmetro. Por isso a comparação
fica como possível extensão, e não como omissão de um baseline equivalente."

### Âncora no texto
- `Revisao.tex` — VisualPhishNet (`Abdelnabi2020VisualPhishNet`) citado como
  abordagem visual no panorama de trabalhos relacionados.

---

## Lembrete geral para a defesa
- Para **toda** pergunta de "por que não X?": reconhecer → enquadrar como escopo de
  POC / modalidade distinta → apontar como trabalho futuro endereçável.
- Nunca prometer desempenho que não foi medido (PT no e-mail, cobertura vs. Safe
  Browsing, FPR ≤0,5%). As negações de precisão ("não reivindico", "não meço") são
  blindagem, não fraqueza.
