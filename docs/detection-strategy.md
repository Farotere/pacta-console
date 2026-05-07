# Stratégie de détection — réflexions

## Problème actuel (regex)

Les regex détectent les **données structurées** : email, IBAN, SS, cartes, JWT, clés API.
Elles ne détectent pas le **contexte sémantique**.

Exemple concret :
- `mdp=test` → détecté ✓
- `mon mdp est test` → non détecté ✗ (la valeur "test" n'est pas isolable par regex)
- `le mot de passe c'est toto123` → non détecté ✗
- `my password is abc` → non détecté ✗

Pour couvrir ces cas avec uniquement des regex, il faudrait :
- Lister tous les synonymes (mdp, password, pwd, secret, pass, passe, clé, code...)
- Dans toutes les langues
- Gérer les structures grammaticales infinies (est, c'est, :, =, →, après "est", "vaut"...)
- C'est ingérable à maintenir et générateur de faux positifs.

## Ce que l'IA permettrait

Un petit modèle de NLP (Named Entity Recognition) ou un LLM local pourrait comprendre :
> "mon mdp est test" → PASSWORD: test
> "le code d'accès est 1234" → PASSWORD: 1234

**Problème du LLM local** : latence 2-5s par requête → inacceptable dans un proxy temps réel.

## Architecture cible envisagée

3 couches, dans l'ordre de priorité :

### Couche 1 — Regex (actuel, ~0ms)
Données structurées uniquement : email, IBAN, SS, cartes, JWT, API keys, SIRET...
Faux négatifs acceptés sur le sémantique.

### Couche 2 — NER/ML léger (~30-80ms, acceptable)
Petit modèle entraîné sur des phrases françaises/anglaises contenant des passwords, noms, adresses en langage naturel.
- Options : spaCy avec modèle `fr_core_news_sm`, GLiNER, ou un classificateur sklearn
- Entraîné sur : "mon mdp est X", "le mot de passe c'est X", "password is X"...
- Pas besoin de GPU, tourne sur CPU en <100ms

### Couche 3 — LLM optionnel (hors chemin critique)
Uniquement pour les cas ambigus détectés par les couches 1/2 mais pas catégorisés.
Jamais bloquant, jamais synchrone dans le proxy.

## Principe fondamental : inférence locale uniquement

Le modèle ML/NER doit tourner **sur la machine de l'employé**, pas sur les serveurs Pacta.
- Le prompt ne quitte jamais le poste, même pour être analysé
- Seules les métadonnées remontent au backend : `{ type, severity, provider }` — jamais le contenu
- C'est l'opposé des DLP cloud (Nightfall, Securiti) qui envoient les prompts sur leurs serveurs
- Argument commercial : "Pacta n'a jamais accès à vos données, même pour les protéger"

## Question ouverte

Est-ce que Pacta veut être un DLP "best-effort" (regex, couvre 90% des cas réels) 
ou un DLP "exhaustif" (couvre la fuite sémantique, nécessite ML/NER) ?

Le marché actuel (Nightfall, Cyberhaven, Securiti) utilise du ML entraîné sur corpus, pas des LLM.

## Cycle de mise à jour du modèle local

Le modèle NER est un fichier ONNX/GGUF (~50-150MB) distribué comme des signatures antivirus.

### Comment la mise à jour se passe pour les clients

```
Employé allume son PC le matin
  → pacta-agent démarre (service systemd)
  → vérifie en arrière-plan : nouvelle version disponible ?
  → télécharge 80MB silencieusement pendant qu'il prend son café
  → modèle mis à jour, zéro action de l'utilisateur
```

Comme Chrome qui se met à jour tout seul — l'employé ne sait pas que ça se passe.

### Comment l'amélioration collective fonctionne

Les clients ne s'améliorent pas entre eux directement — Pacta est le hub central :

```
Client A → faux positif → signale (label anonyme) → Pacta
Client B → faux positif → signale (label anonyme) → Pacta
                                                        ↓
                                            Pacta réentraîne le modèle
                                                        ↓
                                            Pacta pousse modèle v1.4
                                                        ↓
                                   Client A ET B reçoivent la mise à jour
                                   (les deux profitent du feedback de l'autre)
```

Même principe que Windows Defender : chaque PC envoie un signal à Microsoft,
Microsoft améliore le modèle global, et la mise à jour bénéficie à tout le monde.

### Contrainte clé : taille du modèle

La contrainte de distribution dicte le choix technique :
- DistilBERT fine-tuné : ~60MB → préférable, quelques secondes à télécharger
- GLiNER : ~100MB → acceptable
- Llama 1B quantisé : ~800MB → trop lourd pour des mises à jour fréquentes

Un modèle moins précis mais léger sera toujours préférable à un modèle parfait mais lourd.

## Modes de réaction configurables (à implémenter)

L'admin configure le comportement par niveau de sévérité :

| Mode | Employé | Admin |
|------|---------|-------|
| **Audit** | Rien (transparent) | Voit tout dans la console |
| **Warn** | Toast discret en bas à droite | Alerte temps réel |
| **Block** | Popup bloquante + champ justification | Alerte + log justification |

Exemple de config :
- email, ip_internal → Audit
- password_inline, iban → Warn
- api_key, jwt_token → Block

Techniquement : `notify-send` (Linux) ou lib `plyer` (cross-platform Linux/Mac/Windows).
Une popup bloquante = interception de la requête dans le proxy avant envoi.

## À faire plus tard

- [ ] Évaluer spaCy `fr_core_news_sm` pour la détection NER en français
- [ ] Créer un dataset de test : 50 phrases avec passwords en langage naturel
- [ ] Tester GLiNER (modèle NER zero-shot, léger, multilingue)
- [ ] Mesurer la latence en condition proxy (budget max : 200ms)
