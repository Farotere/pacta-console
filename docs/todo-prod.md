# À faire avant la mise en production

## Auth agent en production

**Situation actuelle (dev)** : l'agent s'authentifie avec email/password depuis `config.yml`, ou utilise un token mocké si les champs sont vides.

**Ce qu'il faut faire en prod** :

1. Ajouter un champ `install_token` dans la table `organizations` (backend)
2. Exposer un endpoint `POST /agents/enroll` qui accepte un `install_token` au lieu d'un Bearer JWT utilisateur
3. Générer et afficher l'`install_token` dans la console admin (page Agents → "Ajouter un agent")
4. Côté agent : lire `install_token` depuis `config.yml`, l'envoyer à `/agents/enroll`, stocker l'`agent_id` retourné
5. Supprimer les champs `email` / `password` de `config.yml` et de `agent/core/config.py`
6. Supprimer `_DEV_MOCK_TOKEN` et le bloc `_login()` dans `agent/core/auth.py`

**Config finale attendue** :
```yaml
api:
  url: "https://app.pacta.fr"
  install_token: "pk_live_xxxxxxxxxxxxxxxx"
```

**Références** : voir modèle `Agent` dans `apps/api-backend/app/models/agent.py`
