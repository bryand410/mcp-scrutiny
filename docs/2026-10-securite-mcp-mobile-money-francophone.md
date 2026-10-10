# État de la sécurité des serveurs MCP dans le Mobile Money francophone

**Octobre 2026** · Bryand Tamouffe Teyo · [`mcp-scrutiny`](https://github.com/bryand410/mcp-scrutiny)

---

## Pourquoi ce rapport

Tous les audits de sécurité MCP publiés cette année ont regardé la même chose : le code. [AgentAudit](https://agentaudit.dev/) a scanné 194 paquets et publié 118 findings — `child_process.exec` sans assainissement, fuite de variables d'environnement, accès disque trop large, chaînes de dépendances. [`agent-audit-kit`](https://github.com/sattyamjjain/agent-audit-kit) a analysé statiquement 2 303 configurations. [`mcp-audit`](https://github.com/marcoslozina/mcp-audit) est un scanner open-source avec un jeu de règles de la même forme.

Aucun n'a regardé la couche que le modèle lit réellement. Aucun n'a regardé l'Afrique.

Ce rapport fait les deux. Il porte sur les serveurs MCP qui déplacent de l'argent en Afrique de l'Ouest et du Centre francophone — une région où le Mobile Money n'est pas un confort mais le système de paiement, où Orange Money et MTN MoMo règlent une part importante du commerce ordinaire, et où les serveurs qu'on branche aujourd'hui à des agents IA n'ont jamais été relus par personne.

**Périmètre.** Sept serveurs. Deux scannés à partir des définitions d'outils extraites des artefacts publiés ; cinq évalués à partir du code, des métadonnées de paquet et de l'état du dépôt. Aucune API appelée. Rien testé contre un endpoint de paiement réel.

---

## Les serveurs

| Serveur | Portée | Outils | État au 10 octobre 2026 |
|---|---|---|---|
| [`@theyahia/orange-money-mcp`](https://www.npmjs.com/package/@theyahia/orange-money-mcp) | Orange Money WebPay, ~12 pays dont le **Cameroun (XAF)** | 8 | v1.1.0, publié le 03/05/2026. Scanné. |
| [`Tahsine/momo-mcp`](https://github.com/Tahsine/momo-mcp) | MTN MoMo, Afrique de l'Ouest francophone | 4 | **1 commit, 05/07/2026, 18h33 → 18h38.** Scanné. |
| [`jmndao/deggo-mcp`](https://github.com/jmndao/deggo-mcp) | Mobile Money sénégalais | — | SDK MCP figé à **0.5.0** ; montées Dependabot vers 1.20.2 dormantes depuis novembre 2025 |
| [`cinetpay/cinetpay-mcp`](https://github.com/cinetpay/cinetpay-mcp) | 10 pays francophones | — | **0 étoile.** Pas de description. |
| [`Bigabou007-dev/warimcp`](https://github.com/Bigabou007-dev/warimcp) | CinetPay + Wave + Hub2/Ecobank + PAPSS | — | **0 étoile** |
| [`senorMk/zambia-fintech-mcp`](https://github.com/senorMk/zambia-fintech-mcp) | Zambie | 9 | **0 étoile** |
| MoMo MCP Server (via [Wycord](https://wycord.com/)) | MTN MoMo, Cameroun cité | — | Docs **cassées** ; embarque plafonds, idempotence, journal d'audit et kill switch |

La dernière ligne est la plus importante, et c'est une bonne nouvelle : **le patron sûr est déjà établi dans cet écosystème.** Un serveur MTN MoMo communautaire documente des portes d'approbation, des plafonds de dépense, un journal d'audit et un interrupteur d'arrêt. Le problème n'est pas que personne ne sait faire. C'est que le patron ne s'est pas propagé.

---

## Constatations

Notées honnêtement. Aucune n'est une vulnérabilité au sens d'un bug exploitable dans le code de quelqu'un. Chacune est une propriété de la surface donnée à un LLM, et chacune se corrige.

### H1 — Une commande d'installation non épinglée sur un serveur qui détient une clé marchande

`servers/orange-money/README.md` recommande ceci dans trois configurations clientes distinctes :

```json
"command": "npx",
"args": ["-y", "@theyahia/orange-money-mcp"],
"env": {
  "ORANGE_MONEY_CLIENT_SECRET": "your_client_secret",
  "ORANGE_MONEY_MERCHANT_KEY": "your_merchant_key",
  "ORANGE_MONEY_COUNTRY": "sn"
}
```

Sans version, `npx` résout le tag à chaque démarrage. Une publication future sur ce nom de paquet s'exécute donc avec le secret client et la clé marchande de l'utilisateur déjà dans l'environnement, et peut appeler `cashout` et `transfer`.

C'est le chemin de `postmark-mcp` en septembre 2025, qui a atteint environ 300 organisations. La différence est ce qu'il y a au bout : là-bas, une copie cachée d'e-mail ; ici, une clé marchande sur un rail de paiement en production.

**Correction :** `"args": ["@theyahia/orange-money-mcp@1.1.0"]`, retirer `-y`, et documenter que la version bouge quand un humain en décide. *Divulgué en [theYahia/WWmcp#73](https://github.com/theYahia/WWmcp/issues/73).*

### H2 — Un PIN partenaire passé en paramètre d'outil

Sur `cashin`, `cashout` et `transfer`, dans le même serveur :

```js
pin: z.string().optional().describe("Partner PIN if required")
```

Un PIN partenaire autorise le mouvement de fonds. En paramètre d'outil, il arrive dans la fenêtre de contexte du modèle, où il peut être lu, recopié dans une réponse, ou capté par une instruction injectée. C'est une clé, pas un argument — sa place est dans la configuration du serveur, à côté de `ORANGE_MONEY_MERCHANT_KEY`.

### H3 — Sortie de fonds sans plafond ni porte d'approbation

`disburse_payment` dans `momo-mcp` envoie de l'argent sans plafond, sans liste blanche de bénéficiaires et sans validation humaine. Sa description l'annonce explicitement :

> *« Contrairement à request_payment, aucune confirmation PIN n'est nécessaire côté bénéficiaire — l'argent est envoyé directement. »*

La description est exacte sur le fonctionnement d'un payout. Le problème est la combinaison : une primitive de sortie de fonds, non bornée, exposée à un modèle, dont la propre documentation lui apprend qu'aucune friction supplémentaire ne s'applique. Un agent dont le contexte a été empoisonné — par une page web, un ticket, un fichier lu — peut l'appeler en boucle.

**Correction :** retirer cette phrase de la description ; ajouter `annotations: {"destructiveHint": true}` pour que les clients MCP demandent confirmation ; ajouter un plafond par appel et par jour lu depuis la configuration. *Divulgué en [Tahsine/momo-mcp#1](https://github.com/Tahsine/momo-mcp/issues/1).*

### H4 — Le modèle rédige le message que la victime lit

`request_payment` accepte `payer_message: str = ""` — texte libre affiché sur le téléphone du payeur, sans gabarit, sans limite de longueur, sans limitation de débit.

C'est le canal de phishing le plus direct que j'aie trouvé dans un serveur MCP. Le modèle compose le message qu'une personne lit avant de saisir son code PIN. *« MTN : confirmez ce prélèvement pour éviter la suspension de votre ligne »* passe tel quel. Un jeu de messages prédéfinis, choisis par l'appelant, fermerait le canal sans retirer la fonctionnalité.

Cette constatation est invisible depuis l'extérieur de la région. En Europe, aucun canal de paiement dominant n'affiche de texte libre sur le combiné d'un humain. À Douala, si.

### H5 — Dépendances en borne basse uniquement

`mcp>=1.28.0`, `httpx>=0.28.0`, `pydantic>=2.13.0`. N'importe quelle version future s'installe silencieusement, y compris une majeure cassante ou une publication compromise. Pour un projet qui touche à des paiements, une borne supérieure ou un verrou vaut la peine.

---

## Ce que le scanner n'a pas pu voir, et une chose qu'il a ratée

H1 a été produite par [`mcp-scrutiny`](https://github.com/bryand410/mcp-scrutiny). H2 à H5 non : aucun scanner ne les trouve, parce que ce ne sont pas des motifs dans du texte. Il faut savoir ce qu'est un PIN marchand, ce que fait une primitive de payout, et ce que représente une notification téléphonique pour la personne qui la reçoit.

Le scan lui-même a rapporté 3 findings HIGH sur 2 serveurs et 12 outils. **Un seul était réel.** Les deux autres étaient des appariements « toxic flow » de faible valeur pratique — `list_supported_countries` lit l'environnement du processus, `cashin` envoie vers l'extérieur, le détecteur les a donc appariés. Techniquement vrai, concrètement du bruit. Les présenter comme HIGH aurait rendu ce rapport plus impressionnant et moins utile.

**Et le scanner a produit un faux positif plus important que tout ce qu'il a trouvé.**

Sur `request_payment` de `momo-mcp`, il a scoré **p=0,84** — « la description se lit comme des instructions au modèle ». C'est une description ordinaire, bien écrite et procédurale, d'un outil de paiement. La cause n'était pas le texte :

- le corpus d'entraînement s'arrêtait à **228 caractères** ;
- il ne contenait **aucun texte dans une langue autre que l'anglais** ;
- donc `log_len` se situait à **6,7 écarts-types** hors de la distribution d'entraînement, et le modèle avait appris que *long veut dire malveillant*.

Tout outil correctement documenté — c'est-à-dire tout outil dans un serveur mature — aurait été signalé. Et un détecteur qui n'a jamais vu de français est inutilisable pour 300 millions de personnes.

C'est corrigé le jour même, avant publication : le corpus contient désormais des descriptions longues avec blocs `Args:`, en anglais et en français, à côté de descriptions malveillantes longues ; la F1 en validation croisée passe de 0,87 à 0,88 ; quatre tests de non-régression verrouillent le tout. Le cas `request_payment` score maintenant **0,008**.

**Il est dans ce rapport parce que c'est la chose la plus utile que l'exercice ait produite.** Un outil de sécurité qui se survend est un passif. Un rapport de sécurité aussi.

La correction a mis au jour la limite la plus sérieuse qui reste, elle aussi divulguée : **les motifs de détection d'injection dans `features.py` sont toujours anglophones.** Une description française disant *« ignorez les instructions précédentes »* score 0,19 contre un seuil de 0,5 — ratée. Suivi en [`mcp-scrutiny#5`](https://github.com/bryand410/mcp-scrutiny/issues/5).

---

## Divulgation

Toutes les constatations ont été signalées aux mainteneurs **avant** publication, et ce rapport cite leurs dépôts plutôt que de caractériser leur travail.

| Constatation | Où | État |
|---|---|---|
| H1, H2, H4 | [theYahia/WWmcp#73](https://github.com/theYahia/WWmcp/issues/73) | ouverte, en attente de réponse |
| H3, H4, H5 | [Tahsine/momo-mcp#1](https://github.com/Tahsine/momo-mcp/issues/1) | ouverte, en attente de réponse |

Les deux projets sont jeunes et aucun n'est malveillant. La bonne lecture de ce rapport n'est pas que ces serveurs sont dangereux — c'est qu'**une surface de paiement réelle a été branchée à des agents LLM dans une douzaine de pays sans aucune couche de revue**, et que la première revue a pris deux jours.

---

## Recommandations

**Pour les mainteneurs de serveurs MCP de paiement :**

1. Épinglez chaque version dans chaque instruction d'installation. Ne publiez jamais un `-y` sans version à côté d'un identifiant.
2. Gardez les secrets hors des paramètres d'outil. Un PIN, une clé, un jeton : configuration, jamais argument.
3. Mettez un plafond et une porte d'approbation sur tout outil de sortie de fonds, et activez `destructiveHint`.
4. Ne laissez jamais le modèle rédiger un texte qu'un humain lira sur une surface de paiement. Utilisez des gabarits.
5. Demandez-vous ce que votre description apprend au modèle. Une description n'est pas de la documentation — elle est livrée comme contexte de confiance.

**Pour les équipes qui les déploient :** lancez `mcp-scrutiny baseline` une fois, committez l'instantané, et différez à chaque scan ultérieur. Le contrôle MCP le plus efficace est le diff, et il lui faut une référence.

**Pour le domaine en général :** les audits existants sont excellents et ils regardent le code. La couche description, et le monde non anglophone, sont libres.

---

## Reproduire

```bash
pip install mcp-scrutiny
mcp-scrutiny scan --tools-json docs/afrmcp-dump.json
```

Les définitions d'outils utilisées ici sont reconstruites depuis les sources publiées, dans `mcp_scrutiny/corpus.py` et les dépôts des serveurs eux-mêmes. Les corrections sont bienvenues sous forme d'issues, et une correction de constatation m'est plus utile qu'une confirmation.

---

*Bryand Tamouffe Teyo — DevSecOps, Douala, Cameroun. Construit `mcp-scrutiny`, un scanner hors-ligne pour les définitions d'outils MCP. [github.com/bryand410](https://github.com/bryand410)*
