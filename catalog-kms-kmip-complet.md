# Cahier des charges complété — KMS avec IHM web évoluée et conformité KMIP

> **Version** : 2.0 — Analyse et complétion sur la base du CDC initial  
> **Référentiel normatif** : OASIS KMIP 1.2 / 1.4 / 2.0 / 2.1, NIST SP 800-57, NIST SP 800-131A, RFC 5246 / 8446

---

## 0. Analyse des lacunes — CDC initial vs. exigences KMIP

Avant les sections de fond, le tableau suivant identifie les écarts entre le cahier des charges d'origine et les exigences d'un KMS pleinement conforme KMIP.

| Domaine | Lacune dans le CDC initial | Impact |
|---|---|---|
| Version protocole KMIP | Aucune version cible mentionnée | Risque d'incompatibilité avec les clients existants |
| Modèle d'objets KMIP | Types génériques, non alignés sur la taxonomie KMIP | Mapping incorrect lors de l'implémentation |
| Opérations KMIP | Cycle de vie conceptuel, opérations KMIP non énumérées | Périmètre serveur non borné |
| Attributs KMIP | Aucun attribut KMIP obligatoire ou optionnel listé | Pas de base pour les tests de conformité |
| Encodage & transport | TTLV / JSON / XML non précisés ; port 5696 absent | Interopérabilité incertaine |
| Profils OASIS | Aucun profil cible identifié | Impossibilité de certifier la conformité |
| Authentification KMIP | Modes d'authentification KMIP non spécifiés | Sécurité des accès machine non cadrée |
| Politique d'accès | Modèle Operation Policy (1.x) / Access Policy (2.x) absent | Contrôle d'accès KMIP non défini |
| Opérations batch | Non mentionnées | Performances dégradées pour les clients multi-opérations |
| Opérations cryptographiques | Encrypt/Decrypt/Sign/Verify/MAC via KMIP absents | Clients attendant un serveur crypto ne peuvent pas s'intégrer |
| Key Wrapping | Key Block et mécanismes de wrapping non définis | Export / import de clés non spécifié |
| Split Key | Partage de secret Shamir via KMIP absent | Scénarios de M-of-N non couverts |
| Discover Versions / Query | Opérations de découverte absentes | Clients ne peuvent pas négocier la version |
| Tests d'interopérabilité | Suite OASIS KMIP Interop non référencée | Aucune base de validation tiers |
| HSM via PKCS#11 | Interface PKCS#11 vers HSM non précisée | Connecteur HSM non implémentable sans ce détail |

---

## 1. Objet du document

Ce cahier des charges décrit les exigences fonctionnelles, techniques, de sécurité, d'exploitation et d'ergonomie d'un **Key Management System (KMS)** exposé via une **interface homme-machine (IHM) web** avancée et implémentant un **serveur KMIP conforme au standard OASIS KMIP 2.1** (avec rétrocompatibilité KMIP 1.4).

Le périmètre couvre un serveur centralisé de gestion des clés, des certificats et des secrets cryptographiques, avec des interfaces d'administration, d'exploitation, d'audit et d'intégration applicative. Le serveur KMIP constitue le point d'entrée normalisé pour tous les clients techniques (bases de données, hyperviseurs, systèmes de stockage, agents d'infrastructure).

Le système devra permettre à une organisation de gérer l'intégralité du cycle de vie des objets cryptographiques KMIP, d'assurer la séparation des rôles, d'exposer des API sécurisées REST et KMIP, et de proposer une interface web structurée adaptée à des équipes d'administration, de conformité, d'exploitation et d'intégration.

---

## 2. Contexte et finalité

Le KMS devra répondre à des usages tels que le chiffrement de données applicatives, la protection de bases de données, la gestion de clés de chiffrement pour des infrastructures virtualisées, la gestion de certificats, l'exposition de services compatibles avec des standards du marché, et l'intégration avec des composants matériels de confiance.

### 2.1 Historique et versions KMIP

Le protocole **KMIP (Key Management Interoperability Protocol)** est un standard OASIS dont l'évolution est la suivante :

| Version | Année | Apports principaux |
|---|---|---|
| KMIP 1.0 | 2010 | Protocole initial, opérations de base, encodage TTLV |
| KMIP 1.1 | 2012 | Améliorations mineures, Certificate Request |
| KMIP 1.2 | 2013 | Re-key, Re-certify, MAC, RNG |
| KMIP 1.3 | 2014 | Derive Key, Interop, opérations étendues |
| KMIP 1.4 | 2017 | Virtualisation, cloud, Profile Request |
| KMIP 2.0 | 2019 | Refonte majeure : encodage JSON, Access Policy, Set Attribute |
| KMIP 2.1 | 2020 | Version courante, corrections et ajouts mineurs |

Le serveur cible **doit** supporter KMIP 2.1 et **doit** maintenir la compatibilité avec KMIP 1.4 via l'opération `Discover Versions`. Le support de KMIP 1.2 est souhaitable pour assurer la compatibilité avec les clients legacy.

### 2.2 Positionnement sur le marché

Plusieurs offres du marché exposent une compatibilité KMIP, incluant des solutions avec serveur KMIP dédié ou moteur KMIP intégré. Des implémentations récentes montrent qu'un KMS moderne combine serveur KMIP, API REST et interface web d'administration dans une même plateforme.

---

## 3. Objectifs du projet

Le projet a pour objectifs :

- Fournir un KMS centralisé, hautement sécurisé, administrable via navigateur.
- Implémenter un **serveur KMIP 2.1 conforme** aux profils OASIS cibles.
- Permettre la gestion du cycle de vie complet des objets cryptographiques KMIP.
- Offrir une IHM web structurée, orientée rôles et adaptée à des usages avancés.
- Exposer des interfaces d'intégration standardisées : REST et KMIP.
- Permettre une intégration avec un HSM via PKCS#11 ou une racine matérielle de confiance.
- Assurer traçabilité, auditabilité et conformité KMIP.
- Réussir les tests d'interopérabilité OASIS KMIP.
- Faciliter l'exploitation quotidienne par des équipes distinctes.

---

## 4. Périmètre fonctionnel

### 4.1 Objets cryptographiques gérés

Le KMS devra gérer l'ensemble des **Managed Cryptographic Objects** définis par KMIP 2.1 :

| Type KMIP | Description | Priorité |
|---|---|---|
| `Symmetric Key` | Clés symétriques (AES, 3DES, ChaCha20, etc.) | Obligatoire |
| `Private Key` | Clés privées asymétriques (RSA, EC, Ed25519, etc.) | Obligatoire |
| `Public Key` | Clés publiques associées | Obligatoire |
| `Certificate` | Certificats X.509 v3 | Obligatoire |
| `Certificate Request` | CSR (PKCS#10) | Obligatoire |
| `Secret Data` | Secrets applicatifs (passwords, tokens, passphrases) | Obligatoire |
| `Opaque Object` | Objets opaques (données non interprétées) | Souhaitable |
| `Split Key` | Fragments de clé pour partage de secret (Shamir M-of-N) | Souhaitable |
| `PGP Key` | Clés PGP/OpenPGP | Optionnel |

> Les types `Symmetric Key`, `Private Key`, `Public Key`, `Certificate`, `Certificate Request` et `Secret Data` sont **obligatoires** pour toute implémentation de profil Baseline Server KMIP.

### 4.2 Opérations sur le cycle de vie

Le KMS devra supporter les opérations KMIP standard sur le cycle de vie :

#### Opérations obligatoires (Baseline Server Profile)

| Opération KMIP | Équivalent fonctionnel | Objets concernés |
|---|---|---|
| `Create` | Génération d'une clé symétrique | Symmetric Key |
| `Create Key Pair` | Génération d'une paire de clés | Public + Private Key |
| `Register` | Import d'un objet existant | Tous types |
| `Locate` | Recherche et filtrage | Tous types |
| `Get` | Récupération de l'objet et de sa valeur | Tous types |
| `Get Attributes` | Lecture des attributs d'un objet | Tous types |
| `Get Attribute List` | Liste des attributs présents | Tous types |
| `Set Attribute` | Modification d'un attribut (KMIP 2.x) | Tous types |
| `Activate` | Activation (Pre-Active → Active) | Tous types |
| `Revoke` | Révocation (Active → Deactivated / Compromised) | Tous types |
| `Destroy` | Destruction logique puis physique | Tous types |
| `Query` | Capacités du serveur | N/A |
| `Discover Versions` | Négociation de version | N/A |

#### Opérations fortement souhaitables

| Opération KMIP | Équivalent fonctionnel |
|---|---|
| `Re-key` | Rotation de clé avec préservation de l'identifiant logique |
| `Re-certify` | Renouvellement de certificat |
| `Derive Key` | Dérivation de clé (HKDF, PBKDF2, etc.) |
| `Archive` | Archivage à long terme |
| `Recover` | Restauration depuis archive |
| `Add Attribute` | Ajout d'attribut (KMIP 1.x — compatibilité) |
| `Modify Attribute` | Modification d'attribut (KMIP 1.x — compatibilité) |
| `Delete Attribute` | Suppression d'attribut (KMIP 2.x) |
| `Get Usage Allocation` | Allocation d'usage pour comptage d'opérations |
| `Obtain Lease` | Bail d'accès temporaire à un objet |

#### Opérations cryptographiques via KMIP

| Opération KMIP | Description |
|---|---|
| `Encrypt` | Chiffrement de données via le serveur |
| `Decrypt` | Déchiffrement de données via le serveur |
| `Sign` | Signature numérique |
| `Signature Verify` | Vérification de signature |
| `MAC` | Génération de code MAC (HMAC, CMAC) |
| `RNG Retrieve` | Génération de nombres aléatoires |
| `RNG Seed` | Alimentation de l'entropie du générateur |
| `Hash` | Calcul de condensat cryptographique |

#### Opérations de gestion des clés partagées

| Opération KMIP | Description |
|---|---|
| `Create Split Key` | Création de fragments Shamir M-of-N |
| `Join Split Key` | Reconstruction de la clé depuis les fragments |

---

## 5. Principes d'architecture cible

L'architecture logique devra être structurée autour des composants suivants :

- **Noyau KMS** : moteur de gestion des objets cryptographiques et des politiques.
- **Serveur web IHM** : frontend d'administration et d'exploitation.
- **API Gateway / API service** : exposition REST sécurisée (OpenAPI 3.x).
- **Serveur KMIP** : exposition du protocole KMIP 2.1 sur le port **5696/tcp** (port IANA assigné), avec support TTLV et JSON. Le serveur KMIP est logiquement séparé de l'API REST.
- **Composant d'authentification et d'autorisation** : fédération d'identité, MFA, gestion des rôles et modèle Access Policy.
- **Journal d'audit** : collecte, signature ou scellement, export SIEM.
- **Connecteur HSM** : intégration PKCS#11 vers HSM ou mécanisme équivalent (KMS Software HSM en fallback).
- **Base de métadonnées** : stockage des métadonnées KMIP, politiques, journaux et états des objets.
- **Moteur de tâches planifiées** : rotation, expiration, notifications, campagnes de conformité.
- **Cache et index KMIP** : optimisation des opérations `Locate` sur de grands volumes d'objets.

### 5.1 Séparation des plans

| Plan | Composants | Port / Interface |
|---|---|---|
| Plan de contrôle | IHM web, API REST admin | HTTPS 443 ou 8443 |
| Plan d'intégration KMIP | Serveur KMIP | TCP 5696 (TLS) |
| Plan de données | Noyau KMS, HSM, stockage | Interne uniquement |
| Plan d'audit | Journal, export SIEM | Syslog TLS / API |

---

## 6. Exigences générales d'urbanisation

Le système devra être conçu selon les principes suivants :

- Séparation stricte entre plan de contrôle, plan d'administration et plan de données.
- Cloisonnement multi-environnements : développement, intégration, préproduction, production.
- Possibilité de cloisonnement multi-tenants ou multi-domaines métiers, aligné sur le concept de **Group** KMIP et d'`Application Specific Information`.
- Compatibilité avec un déploiement on-premise, cloud privé ou hybride.
- Support de la haute disponibilité et de la reprise après incident.
- Interfaces documentées et versionnées (OpenAPI pour REST ; conformité OASIS pour KMIP).
- Journalisation systématique des actions sensibles, y compris toutes les opérations KMIP.

---

## 7. Exigences fonctionnelles détaillées

### 7.1 Gestion des objets cryptographiques

Le système devra permettre :

- La création de clés avec choix précis de l'algorithme KMIP (`Cryptographic Algorithm`), de la taille (`Cryptographic Length`), du masque d'usage (`Cryptographic Usage Mask`), de la politique de rotation et du domaine de rattachement.
- La gestion de métadonnées riches : `Name`, `Object Group`, `Application Specific Information`, `Contact Information`, `Custom Attribute`, alias fonctionnel, tags, propriétaire, criticité, environnement, application, classification, date d'expiration, justification métier.
- La définition d'attributs de non-exportabilité via `Cryptographic Usage Mask` (bit `Export`), d'usage restreint, de quorum ou de double validation.
- La visualisation de l'historique complet d'un objet via `Last Change Date`, journal d'audit interne.
- Le suivi des versions successives d'une même clé logique (via `Link` KMIP de type `Previous` / `Next` / `Replacement`).
- La distinction entre identifiant technique interne (`Unique Identifier` KMIP), alias fonctionnel (`Name`) et nom d'intégration externe (`Application Specific Information`).

#### 7.1.1 Algorithmes supportés (obligatoires)

| Catégorie | Algorithmes | Tailles minimales |
|---|---|---|
| Symétrique | AES | 128, 192, 256 bits |
| Symétrique | 3DES (Triple DES) | 112, 168 bits (usage limité) |
| Asymétrique | RSA | 2048, 3072, 4096 bits |
| Asymétrique | ECDSA | P-256, P-384, P-521 |
| Asymétrique | ECDH | P-256, P-384 |
| Asymétrique | Ed25519 / Ed448 | Natif |
| Digest | SHA-256, SHA-384, SHA-512 | N/A |
| MAC | HMAC-SHA256, HMAC-SHA512, AES-CMAC | N/A |

> Conformément à NIST SP 800-131A Rev. 2, les algorithmes RSA < 2048 bits, 3DES ≤ 112 bits et SHA-1 sont **interdits en génération** (uniquement acceptés en vérification pour rétrocompatibilité avec un objet importé).

#### 7.1.2 États du cycle de vie des objets KMIP

```
                     ┌─────────────────────────────────────────┐
                     │         État des objets KMIP             │
                     └─────────────────────────────────────────┘
                        Register/
                          Create
                            │
                            ▼
                      ┌──────────┐    Activate    ┌──────────┐
                      │Pre-Active│──────────────▶│  Active  │
                      └──────────┘               └──────────┘
                            │                         │
                            │                    Revoke / Deactivate
                            │                         │
                            ▼                         ▼
                      ┌──────────┐           ┌──────────────┐
                      │Compromised│          │ Deactivated  │
                      └──────────┘           └──────────────┘
                            │                         │
                       Destroy                   Destroy
                            │                         │
                            ▼                         ▼
                  ┌────────────────────┐     ┌──────────────┐
                  │Destroyed Compromised│    │  Destroyed   │
                  └────────────────────┘     └──────────────┘
```

Toute transition d'état doit être journalisée avec identité de l'acteur, horodatage, motif de révocation (`Revocation Reason`) et résultat.

### 7.2 Gouvernance et politiques

Le KMS devra intégrer un moteur de politiques permettant :

- Des règles de nommage (convention `Name` KMIP, longueur, caractères autorisés).
- Des règles de durée de vie par type d'objet (via `Activation Date`, `Deactivation Date`, `Destroy Date`).
- Des règles d'algorithmes autorisés / interdits (liste blanche d'algorithmes et de longueurs).
- Des règles d'export, de duplication, de destruction et de délégation, basées sur `Cryptographic Usage Mask`.
- Des règles de validation à plusieurs niveaux pour les opérations critiques.
- Des politiques différenciées par tenant, application, zone de sécurité ou équipe.

#### 7.2.1 Modèle de politique d'accès KMIP

**KMIP 1.x — Operation Policy** : La politique est référencée par nom (`Operation Policy Name`) et associe à chaque type d'objet un ensemble d'opérations autorisées (Allow / Allow Items / Deny).

**KMIP 2.x — Access Policy** : Modèle plus fin où chaque Permission est exprimée comme :

```
Permission = {
  Operation : [List of KMIP Operations],
  Object Types : [List of Managed Object Types],
  Privileged : Boolean  // si vrai, l'appelant peut opérer sans être propriétaire
}
```

Le serveur devra supporter les deux modèles pour assurer la rétrocompatibilité.

#### 7.2.2 Profils de politique prédéfinis

| Profil | Usages autorisés | Export | Destroy |
|---|---|---|---|
| `kek-internal` | Wrap/Unwrap uniquement | Non | Dual-control |
| `encrypt-only` | Encrypt + Decrypt | Non | Opérateur |
| `signing` | Sign + Verify | Non | Opérateur |
| `transport` | Export contrôlé | Oui (wrappée) | Opérateur |
| `archival` | Archive / Recover | Non | Admin sécurité |

### 7.3 Workflow d'approbation

Le système devra supporter des workflows configurables pour :

- La création de clés à usage sensible.
- L'export de clés (opération `Get` sur objets marqués non-exportables).
- La suppression définitive (`Destroy`).
- Le changement de politique.
- L'onboarding d'une nouvelle application ou d'un nouveau client KMIP.
- La génération de fragments Split Key et la reconstruction (Join).

Chaque workflow devra pouvoir inclure : demandeur, approbateur(s), contrôle de conformité, justification, horodatage, statut et piste d'audit.

### 7.4 Intégration et interopérabilité

Le système devra exposer :

- Une **API REST** documentée (OpenAPI 3.x), versionnée et sécurisée (JWT Bearer).
- Un **serveur KMIP 2.1** conforme sur port 5696 (TLS 1.3 obligatoire, TLS 1.2 toléré avec négociation).
- Des mécanismes d'émission de certificats clients (mTLS), de gestion TLS mutuelle et de rattachement des clients à des rôles, scopes ou profils KMIP.
- Optionnellement : PKCS#11 wrapper pour exposer des opérations HSM aux applications locales.

#### 7.4.1 Découverte et négociation de version

L'opération `Discover Versions` est **obligatoire**. Elle doit retourner la liste des versions KMIP supportées par le serveur, dans l'ordre de préférence :

```
Discover Versions Response:
  Protocol Version: [2.1, 2.0, 1.4, 1.2]
```

L'opération `Query` est **obligatoire** et doit exposer :
- `Server Information` : version du serveur, capacités
- `Operations` : liste de toutes les opérations supportées
- `Object Types` : liste des types d'objets gérés
- `Vendor Identification` : identification du fournisseur
- `Server Name` / `Server Serial Number`
- `Authentication Suites` supportées

### 7.5 Gestion des clients et applications

Le KMS devra permettre de gérer les entités consommatrices :

- Applications (clients REST).
- Équipements (clients KMIP machine-to-machine).
- Bases de données (TDE, TDE-HSM).
- Hyperviseurs (chiffrement de volumes virtuels).
- Agents d'infrastructure (Kubernetes Secrets, Vault, etc.).
- Clients KMIP avec certificat TLS client dédié.
- Administrateurs et opérateurs humains (IHM).

Pour chaque client KMIP, l'IHM devra permettre de visualiser :

- Identité (`Unique Identifier` client, `Name`, `Device Credential` si applicable).
- Type de client et méthode d'authentification KMIP (certificate, credential, attestation).
- Domaine de rattachement / `Object Group`.
- Permissions effectives (via Access Policy ou Operation Policy).
- Certificats TLS clients actifs et leur date d'expiration.
- Dernière activité et historique d'erreurs.
- Dernières opérations KMIP effectuées (via audit).

---

## 8. Cahier des charges de l'IHM web

### 8.1 Principes UX/UI

L'IHM devra être un **serveur web d'administration structuré**, accessible via navigateur moderne, responsive, sécurisée et conçue pour des usages experts. Elle ne devra pas se limiter à une simple console CRUD, mais fournir une vue opérable du patrimoine cryptographique.

L'interface devra :

- Être orientée rôles.
- Permettre un accès rapide aux actions critiques.
- Offrir une navigation cohérente par domaine fonctionnel.
- Réduire le risque d'erreur humaine par confirmations contextuelles, résumés d'impact et garde-fous.
- Permettre l'analyse et l'audit sans recours systématique à la ligne de commande.
- Exposer la conformité KMIP de chaque objet (version, profil, état).

### 8.2 Structure fonctionnelle de l'IHM

L'IHM devra être organisée au minimum selon les rubriques suivantes :

1. **Tableau de bord**
2. **Objets cryptographiques**
3. **Politiques**
4. **Clients et intégrations**
5. **Workflows et validations**
6. **Journaux et audit**
7. **Conformité et reporting**
8. **Administration système**
9. **Supervision et santé de service**
10. **Paramètres de sécurité**
11. **Serveur KMIP** *(nouveau module)*

### 8.3 Tableau de bord

Le tableau de bord devra fournir :

- Nombre de clés par type KMIP, statut (`State`), domaine et criticité.
- Clés expirées (`Deactivation Date` dépassée), expirant prochainement ou en non-conformité.
- État des connecteurs HSM.
- État des services REST, KMIP (port 5696) et IHM.
- Activité récente (dernières opérations KMIP).
- Alertes de sécurité (objets compromis, tentatives d'accès refusées).
- Actions nécessitant approbation (workflows en attente).
- Événements d'audit majeurs (Destroy, Revoke, Export).
- Indicateurs de performance du serveur KMIP (requêtes/sec, latence).

### 8.4 Module "Objets cryptographiques"

Ce module devra offrir :

- Une liste filtrable multi-critères, incluant les attributs KMIP (`Algorithm`, `State`, `Object Type`, `Object Group`, `Name`, dates).
- Une recherche plein texte et par attributs KMIP (équivalent de l'opération `Locate`).
- Une vue détail riche avec onglets : propriétés KMIP, usages (`Cryptographic Usage Mask`), versions (liens `Previous`/`Next`), dépendances, historique, journal d'accès, conformité.
- Des vues arborescentes ou par taxonomie : domaine, application, environnement, propriétaire, `Object Group`.
- Des opérations en masse sécurisées sur lot d'objets.
- Visualisation du **Key Block** et des métadonnées de wrapping pour les clés exportées.

### 8.5 Module "Politiques"

Ce module devra permettre :

- La création et édition de politiques KMIP (Operation Policy 1.x / Access Policy 2.x).
- La simulation d'impact d'une politique avant publication.
- L'association de politiques à un tenant, un domaine, une application ou un type de clé.
- La comparaison de versions de politiques.
- L'identification des exceptions et dérogations.
- La validation des politiques vis-à-vis des règles algorithmiques de la section 7.1.1.

### 8.6 Module "Clients et intégrations"

Ce module devra gérer :

- Enrôlement d'un client applicatif ou d'un **client KMIP** (avec émission de certificat TLS client).
- Création de profils d'accès KMIP (Access Policy assignée).
- Association à des `Object Group`, scopes, rôles.
- Émission et renouvellement de certificats clients TLS.
- Affichage des paramètres de connexion KMIP (host, port 5696, version, encodage).
- Journal des échanges KMIP et erreurs d'intégration.
- Test de connexion KMIP depuis l'IHM (opération `Discover Versions` de validation).

### 8.7 Module "Audit et conformité"

Ce module devra permettre :

- Recherche multicritère dans les journaux, incluant les opérations KMIP.
- Reconstitution chronologique d'un événement ou d'un incident.
- Export des traces (JSON, CSV, CEF pour SIEM).
- Mise en évidence des opérations KMIP sensibles (`Destroy`, `Revoke`, `Get` sur objets sensibles, `Encrypt`/`Decrypt`).
- Détection des anomalies simples : pics de requêtes KMIP, accès hors horaires, tentatives répétées de `Get` sur objets révoqués.
- Rapports de conformité KMIP prêts à l'usage.

### 8.8 Module "Administration système"

Il devra permettre :

- Gestion des rôles (mapping rôles IHM ↔ Access Policy KMIP).
- Paramétrage OIDC/SAML/LDAP.
- Gestion du MFA.
- Paramétrage TLS, mTLS et certificats serveur KMIP.
- Paramétrage des connecteurs HSM (PKCS#11 provider, slot, PIN).
- Paramétrage des notifications et alertes.
- Paramétrage des sauvegardes, rétention et purge.

### 8.9 Module "Serveur KMIP" *(nouveau)*

Ce module spécifique devra permettre :

- Visualisation de l'état du serveur KMIP (actif/inactif, version servie, port).
- Configuration des versions KMIP servies et de l'encodage par défaut (TTLV ou JSON).
- Gestion des certificats TLS du serveur KMIP (CA, certificat serveur, CRL).
- Liste des clients KMIP connectés et de leurs sessions actives.
- Statistiques d'opérations KMIP par type (Create, Get, Locate, etc.).
- Visualisation des erreurs KMIP (`Result Status`, `Result Reason`, `Result Message`).
- Configuration des limites : taille maximale des batches, timeout de session, algorithmes autorisés.
- Test de conformité KMIP in-situ (sous-ensemble de la suite OASIS).

---

## 9. Exigences de sécurité

### 9.1 Contrôle d'accès

Le système devra supporter :

- Authentification forte pour tous les utilisateurs de l'IHM.
- MFA pour tous les comptes privilégiés.
- Fédération d'identité via OIDC pour l'IHM web ; SAML en option.
- RBAC fin ; idéalement ABAC complémentaire.
- Séparation des rôles (voir section 12).
- Segregation of duties sur les opérations KMIP critiques.
- Sessions limitées dans le temps, révocables, journalisées.

#### 9.1.1 Authentification KMIP

Le serveur KMIP devra supporter les mécanismes d'authentification suivants :

| Mécanisme | Version KMIP | Priorité |
|---|---|---|
| **mTLS — Certificat client TLS** | 1.x, 2.x | Obligatoire |
| Username / Password Credential | 1.x, 2.x | Obligatoire |
| Attestation Credential | 2.0+ | Souhaitable |
| One-Time Password Credential | 2.0+ | Optionnel |
| Device Credential (deprecated) | 1.x | Compatibilité |
| Anonymous (No Authentication) | 1.x, 2.x | Interdit en production |

L'authentification par défaut pour les clients machine devra être **mTLS avec certificat client dédié par application**.

### 9.2 Sécurité cryptographique

Le KMS devra :

- Interdire les algorithmes et tailles faibles selon la table de la section 7.1.1.
- Supporter des profils d'usage stricts via `Cryptographic Usage Mask` par type de clé.
- Permettre la génération interne sécurisée des clés (DRBG conforme NIST SP 800-90A).
- Supporter un ancrage HSM pour les clés maîtres (KEK, Master Key, MKEK) si le contexte l'exige.
- Gérer proprement les certificats clients KMIP et les chaînes de confiance TLS.
- Implémenter le **Key Block** KMIP pour tout export ou transfer de valeur de clé.

#### 9.2.1 Key Block et Key Wrapping

Tout export de valeur de clé via l'opération `Get` devra être effectué dans un **Key Block** KMIP structuré comme suit :

```
Key Block:
  Key Format Type : Raw | Opaque | PKCS1 | PKCS8 | X.509 | ...
  Key Compression Type : (optionnel)
  Key Value :
    Key Material : (valeur chiffrée)
    Attributes : (attributs embarqués)
  Cryptographic Algorithm : (algorithme de wrapping)
  Cryptographic Length : (taille de la clé de wrapping)
  Key Wrapping Data :
    Wrapping Method : Encrypt | MAC/sign | Encrypt then MAC/sign | MAC/sign then Encrypt | TR-31
    Encryption Key Information :
      Unique Identifier : (identifiant de la KEK utilisée)
      Cryptographic Parameters : (mode, IV, algorithme)
    MAC/Signature Value : (optionnel)
    IV/Counter/Nonce : (si applicable)
```

Le serveur devra supporter les formats de wrapping suivants (par priorité) :
1. AES-256-KW (RFC 3394) — wrapping de clé symétrique
2. AES-256-GCM — wrapping authentifié avec AAD
3. RSA-OAEP-SHA256 — wrapping asymétrique
4. TR-31 (standard ANSI/RETAIL) — pour les environnements de paiement

### 9.3 Journalisation et auditabilité

Toute action sensible devra être journalisée. Pour chaque opération KMIP, le journal doit contenir au minimum :

| Champ | Source KMIP |
|---|---|
| Qui | `Authentication` (credential ou certificat client) |
| Quoi | Opération KMIP (`Operation`, `Batch Item`) |
| Quel objet | `Unique Identifier` |
| Quand | Horodatage précis (UTC, ISO 8601) |
| Depuis où | IP source, identifiant de session TLS |
| Résultat | `Result Status`, `Result Reason`, `Result Message` |
| Batch | Numéro de requête et d'item dans le batch |
| Justification | Custom Attribute ou champ hors-bande si applicable |

Les journaux devront être exportables vers un SIEM (Syslog TLS, API push) et protégés contre l'altération (scellement cryptographique, append-only store ou signature périodique).

### 9.4 Résilience et durcissement

Le système devra intégrer :

- Chiffrement des données au repos (clés KMS protégées par KEK en HSM ou Software HSM).
- Sauvegardes chiffrées avec clé de backup séparée et procédure de restauration testée.
- Durcissement OS et middleware.
- Rotation des secrets techniques (certificats serveur KMIP, credentials opérateurs).
- Protection contre brute force (limite de tentatives d'authentification KMIP), CSRF, XSS, SSRF.
- Limitation de débit sur API REST et serveur KMIP (requêtes/sec par client).
- Détection des comportements anormaux (pics de `Get`, accès hors périmètre, opérations `Destroy` en masse).

---

## 10. Exigences techniques

### 10.1 Architecture de déploiement

Le fournisseur ou l'équipe projet devra proposer une architecture de référence comprenant :

- Nœud primaire / secondaire ou cluster HA (minimum 3 nœuds en production).
- Répartition de charge pour l'IHM (HTTPS) et le serveur KMIP (TCP 5696) — le load balancer KMIP doit supporter le mode `passthrough` TLS pour préserver le mTLS end-to-end.
- Stockage persistant redondé pour la base des objets KMIP.
- Procédure de reprise sur sinistre documentée et testée.
- Supervision centralisée.
- Journalisation centralisée.

### 10.2 Protocoles et interfaces

| Protocole | Usage | Détail |
|---|---|---|
| HTTPS | IHM et API REST | TLS 1.3 (TLS 1.2 fallback), HSTS, OCSP Stapling |
| KMIP / TTLV | Clients KMIP binaires | Port 5696, TLS 1.3, mTLS obligatoire |
| KMIP / JSON | Clients KMIP modernes | Port 5696 ou 443, TLS 1.3 |
| PKCS#11 | Connecteur HSM interne | Version PKCS#11 2.40 minimum |
| mTLS | Clients techniques | Certificats émis par CA interne dédiée |
| Syslog TLS | Export audit | RFC 5424 + RFC 5425 |
| OIDC | Authentification IHM | OpenID Connect 1.0, PKCE obligatoire |
| SAML | SSO entreprise | SAML 2.0 (optionnel) |
| LDAP(S) | Annuaire | LDAPv3 sur TLS 636 |
| Prometheus | Métriques | /metrics endpoint, format OpenMetrics |

#### 10.2.1 Encodages KMIP supportés

| Encodage | Description | Priorité |
|---|---|---|
| **TTLV** | Tag-Type-Length-Value binaire (encodage historique) | Obligatoire |
| **JSON** | Encodage JSON selon KMIP 2.0 Annex A | Obligatoire |
| **XML** | Encodage XML selon KMIP 1.x | Souhaitable (rétrocompatibilité) |

Le serveur devra négocier l'encodage via les headers HTTP (`Content-Type: application/json` vs `Content-Type: application/octet-stream`) ou via configuration par client lors de l'enrôlement.

### 10.3 Performance

Le KMS devra atteindre les objectifs suivants (mesurés sur un déploiement HA) :

| Indicateur | Objectif | Critique |
|---|---|---|
| Latence opération KMIP (Create, Get) | P99 < 50 ms | P99 < 200 ms |
| Latence opération KMIP avec HSM | P99 < 150 ms | P99 < 500 ms |
| Latence API REST | P99 < 100 ms | P99 < 500 ms |
| Débit KMIP (opérations/sec, sans HSM) | > 1 000 op/s | > 200 op/s |
| Débit KMIP Locate (objets indexés) | > 500 req/s pour 100k objets | — |
| Nombre d'objets KMIP gérés | > 1 000 000 | > 100 000 |
| Nombre de clients KMIP enregistrés | > 10 000 | > 1 000 |
| Temps de rotation d'une clé (Re-key) | < 1 s | < 5 s |
| RTO (reprise sur incident) | < 15 min | < 1 h |
| RPO (point de reprise données) | < 1 min | < 5 min |

### 10.4 Exploitabilité

Le système devra fournir :

- Journaux techniques exploitables (format structuré JSON/CEF).
- Métriques Prometheus exposées sur `/metrics` avec labels par type d'opération KMIP.
- Endpoints de healthcheck : `/health/live`, `/health/ready`, `/health/kmip`.
- Documentation d'exploitation complète.
- Procédures documentées : installation, mise à jour, sauvegarde, restauration, rotation de certificats TLS serveur, rotation du KEK maître.

#### 10.4.1 Métriques KMIP spécifiques à exposer

```
kmip_operations_total{operation="Create", status="Success"} 
kmip_operations_total{operation="Get", status="OperationFailed"}
kmip_operation_duration_seconds{operation="Create", quantile="0.99"}
kmip_active_sessions_total
kmip_objects_total{type="SymmetricKey", state="Active"}
kmip_objects_total{type="Certificate", state="Deactivated"}
kmip_batch_size_histogram_bucket
kmip_tls_handshake_errors_total
```

---

## 11. Exigences non fonctionnelles pour l'IHM

L'IHM devra respecter les exigences suivantes :

- Compatibilité avec navigateurs d'entreprise modernes (Chrome, Edge, Firefox — 2 dernières versions majeures).
- Responsive design pour poste de travail et tablette ; l'usage mobile pourra être limité à la consultation.
- Accessibilité : WCAG 2.1 AA, contrastes, navigation clavier, libellés explicites.
- Temps de chargement optimisé : premier affichage utile < 3 s sur réseau 10 Mbps.
- Internationalisation FR/EN.
- Gestion des erreurs KMIP (`Result Status`, `Result Reason`) claire et contextualisée dans l'IHM.
- Traçabilité des actions de l'utilisateur dans l'interface.

---

## 12. Modèle de rôles cible

| Rôle | Capacités principales | Opérations KMIP autorisées |
|---|---|---|
| Administrateur sécurité | Politiques, rôles, paramètres de sécurité, validation critique | Tous (via IHM uniquement) |
| Administrateur système | Déploiement, connecteurs, supervision, certificats serveur | Query, Discover Versions, administration |
| Opérateur KMS | Création, rotation, suspension, suivi opérationnel | Create, Create Key Pair, Register, Activate, Revoke, Locate, Get Attributes, Re-key |
| Auditeur | Consultation des traces, rapports, conformité | Locate (lecture seule), Get Attributes, journaux |
| Intégrateur applicatif | Enrôlement client KMIP, consultation de son périmètre | Create (périmètre limité), Get, Encrypt, Decrypt, Sign, Verify |
| Lecteur | Consultation restreinte | Get Attributes, Locate (périmètre restreint) |
| Application / Client KMIP | Opérations machine-to-machine selon profil | Selon Access Policy assignée à l'enrôlement |

---

## 13. Reporting attendu

Le système devra produire ou permettre d'exporter les rapports suivants :

- Inventaire des clés et certificats (par type KMIP, état, domaine).
- Clés arrivant à expiration (dans les 30/60/90 prochains jours).
- Objets non conformes à la politique (algorithme interdit, taille faible, `Cryptographic Usage Mask` incorrect).
- Historique des exports (`Get` sur objets exportables) et destructions (`Destroy`).
- Activité KMIP par application, par opérateur, par tenant (opérations/jour, erreurs/jour).
- État des connecteurs HSM et disponibilité.
- Disponibilité des services IHM, API REST et serveur KMIP (uptime, latences).
- Pistes d'audit KMIP pour une période donnée (exportables au format CEF, JSON, CSV).
- Rapport de conformité KMIP (profils supportés, opérations validées, résultats des tests d'interopérabilité).

---

## 14. Contraintes de réalisation

Le projet devra documenter les choix suivants :

- Open source, source available, commercial ou hybride.
- Dépendance ou non à un HSM physique ; HSM logiciel acceptable pour les environnements non-production.
- Dépendance à une base de données spécifique (PostgreSQL recommandé pour la persistance KMIP).
- Stratégie de montée de version KMIP (support simultané de deux versions majeures).
- Stratégie de réversibilité (export des objets KMIP dans un format standard avant migration).
- Conditions de licence des composants (bibliothèques crypto, PKCS#11, etc.).
- Niveaux de support attendus et SLAs.

---

## 15. Critères d'acceptation

La recette devra vérifier au minimum :

- Création, rotation (`Re-key`), révocation (`Revoke`) et suppression (`Destroy`) d'objets cryptographiques via KMIP et via IHM.
- Cloisonnement correct entre rôles et tenants (tests de refus d'accès KMIP hors périmètre).
- Fonctionnement de l'IHM avec OIDC/MFA.
- Fonctionnement des API REST sécurisées.
- Fonctionnement du serveur KMIP 2.1 avec au moins deux clients de référence :
  - Un client KMIP open source (ex. PyKMIP, kmip4j, BouncyCastle KMIP).
  - Un client KMIP commercial (ex. solution de stockage compatible KMIP, base de données TDE).
- `Discover Versions` retournant [2.1, 2.0, 1.4] correctement.
- `Query` retournant la liste complète des opérations et types d'objets supportés.
- Génération et gestion correcte des certificats clients techniques (émission, renouvellement, révocation).
- Disponibilité des journaux d'audit KMIP et export vers l'outillage de supervision.
- Fonctionnement du workflow de validation sur une opération critique (`Destroy` avec dual-control).
- Key Block correct sur toute opération d'export de clé (`Get` avec wrapping).
- Résilience après redémarrage et test de restauration complète depuis sauvegarde.
- Résultats positifs sur la suite d'interopérabilité OASIS KMIP (section 25).

---

## 16. Jeux d'essais minimaux

Les jeux d'essais devront couvrir :

### Tests fonctionnels de base

- Création de clés AES-128, AES-256, RSA-2048, RSA-4096, P-256, P-384, Ed25519.
- Création de versions successives d'une même clé logique (via `Re-key`, liens `Previous`/`Next`).
- Rotation planifiée et manuelle avec archivage de l'ancienne version.
- Import (`Register`) d'un certificat X.509 et association à une application cliente.
- Enrôlement d'un client KMIP avec certificat TLS dédié et vérification de l'accès restreint au périmètre assigné.

### Tests de conformité KMIP

- `Discover Versions` : vérification des versions retournées.
- `Query` : vérification de la liste des opérations supportées.
- Cycle de vie complet : `Create` → `Activate` → `Get` → `Revoke` → `Destroy`.
- `Locate` avec filtres multiples : `Object Type`, `State`, `Name`, `Cryptographic Algorithm`, date.
- `Get Attributes` pour tous les attributs obligatoires de chaque type d'objet.
- Opération `Set Attribute` (KMIP 2.x) sur un attribut modifiable.
- Refus d'accès hors périmètre (test de rejection avec code `NotAllowed`).
- Refus d'export pour une clé dont le masque d'usage exclut l'export.
- `Get` avec `Key Wrapping Specification` : vérification du Key Block retourné.
- Opération batch : 10 créations de clés dans une seule requête KMIP.
- Opération `Encrypt` / `Decrypt` via KMIP (serveur crypto).

### Tests de sécurité et de résilience

- Journalisation complète d'une opération sensible (`Destroy`).
- Simulation d'indisponibilité d'un nœud (bascule HA).
- Test de restauration depuis sauvegarde chiffrée.
- Test de rejet de connexion sans certificat client sur le port KMIP 5696.
- Test de rejet d'un algorithme interdit par la politique.

---

## 17. Livrables attendus

Les livrables du projet devront inclure :

- Dossier d'architecture générale.
- Dossier d'architecture de sécurité (incluant le modèle de menaces KMIP).
- Spécification des API REST (OpenAPI 3.x) et du serveur KMIP.
- Maquette fonctionnelle ou prototype d'IHM.
- Dossier d'exploitation.
- Plan de tests et procès-verbal de recette.
- Matrice rôles / permissions (IHM et Access Policy KMIP).
- Modèle de données des objets cryptographiques KMIP.
- Documentation d'administration KMIP (configuration, profils, encodages, port 5696).
- Rapport d'interopérabilité KMIP avec résultats des tests par profil.

---

## 18. Recommandations de structuration du futur produit

Pour un produit KMS moderne avec IHM web évoluée et serveur KMIP conforme, la structuration suivante est recommandée :

- **Couche cœur KMS** indépendante de la présentation, exposant une API interne agnostique du protocole.
- **Couche protocolaire KMIP** : adaptateur KMIP → API interne, gestionnaire d'encodage (TTLV/JSON), gestionnaire de session TLS, gestionnaire d'authentification KMIP.
- **Couche protocolaire REST** : API REST OpenAPI 3.x, JWT, RBAC.
- **Couche IAM** séparée avec fédération OIDC/SAML et gestion des rôles.
- **Frontend web** orienté domaines fonctionnels, incluant le module de supervision KMIP.
- **Moteur d'audit et conformité** natif, consommant les événements KMIP en temps réel.
- **Mécanisme de domaines / groupes / tenants** aligné sur `Object Group` et `Application Specific Information` KMIP.

---

## 19. Questions ouvertes à traiter avant lancement

Avant la phase de conception détaillée, les points suivants devront être tranchés :

- Le KMS est-il destiné à un usage interne, mutualisé, ou OEM ?
- Le protocole KMIP doit-il être natif, complet, ou limité à certains profils de clients ? (recommandation : Baseline Server Profile + Complete Server Profile à terme)
- L'export de clés doit-il être totalement interdit hors HSM ? (impacts sur le `Get` KMIP et le wrapping)
- Un HSM physique est-il obligatoire pour certaines catégories de clés ? (KEK, clés maîtres)
- Le besoin porte-t-il aussi sur les certificats, secrets applicatifs et identités machine ? (`Secret Data`, `Certificate` KMIP)
- L'IHM est-elle réservée à l'administration ou également à l'onboarding applicatif self-service ?
- Le système doit-il supporter plusieurs tenants juridiquement isolés (isolation forte via `Object Group` ou isolation logicielle complète) ?
- Le niveau de conformité attendu impose-t-il une certification tierce (FIPS 140-3, Common Criteria) ?
- Quelles versions KMIP les clients existants de l'organisation utilisent-ils ?
- L'organisation dispose-t-elle déjà d'une CA interne pour émettre les certificats clients KMIP ?
- Quels clients KMIP spécifiques doivent être certifiés interopérables (base de données, hyperviseur, solution de stockage) ?

---

## 20. Annexe — Synthèse des exigences prioritaires

| Domaine | Exigence prioritaire |
|---|---|
| Interopérabilité KMIP | Serveur KMIP 2.1 + rétrocompatibilité 1.4, profils Baseline + Complete |
| Opérations KMIP | Create, Create Key Pair, Register, Locate, Get, Activate, Revoke, Destroy, Query, Discover Versions obligatoires |
| Encodage | TTLV (obligatoire) + JSON (obligatoire), XML (souhaitable) |
| Transport KMIP | Port 5696, TLS 1.3, mTLS par certificat client dédié |
| Key Wrapping | Key Block obligatoire pour tout export, AES-KW + RSA-OAEP |
| Authentification KMIP | mTLS certificat client + Username/Password ; Attestation (KMIP 2.x) souhaitable |
| Access Policy | Modèle KMIP 2.x ; compatibilité Operation Policy KMIP 1.x |
| Sécurité | MFA, RBAC fin, mTLS, audit inviolable, refus des algorithmes faibles |
| IHM | Module Serveur KMIP, tableau de bord, recherche avancée, workflows, reporting |
| Gouvernance | Politiques, versions de clés, séparation des rôles, états KMIP |
| Exploitation | HA, supervision, métriques KMIP Prometheus, sauvegarde, restauration |
| Intégration | HSM PKCS#11, IdP OIDC, SIEM, clients applicatifs KMIP |
| Conformité | Traçabilité, tests OASIS, rapports exportables, conformité algorithmique NIST |

---

## 21. Spécification du protocole KMIP

### 21.1 Version et encodage

#### 21.1.1 Versions cibles

Le serveur KMIP devra implémenter les versions suivantes, présentées par ordre de priorité décroissante :

| Version | Support | Notes |
|---|---|---|
| KMIP 2.1 | **Obligatoire** (version primaire) | Access Policy, Set/Delete Attribute, JSON encoding |
| KMIP 2.0 | **Obligatoire** | Même modèle que 2.1, encodage JSON introduit |
| KMIP 1.4 | **Obligatoire** (rétrocompatibilité) | Operation Policy, Add/Modify Attribute |
| KMIP 1.2 | Souhaitable | Re-key, Re-certify, MAC, RNG |
| KMIP 1.1 | Optionnel | Rétrocompatibilité legacy uniquement |

Le mécanisme de négociation de version s'appuie sur l'opération `Discover Versions`. Tout client KMIP doit effectuer une `Discover Versions` avant toute autre opération lors de l'établissement d'une nouvelle session.

#### 21.1.2 Encodage des messages

**TTLV (Tag-Type-Length-Value)** :
- Encodage binaire standard KMIP.
- Obligatoire pour tous les clients et versions.
- Structure : `[Tag: 3 bytes][Type: 1 byte][Length: 4 bytes][Value: N bytes][Padding: 0-7 bytes]`.
- Utiliser le `Content-Type: application/octet-stream` sur transport HTTPS.

**JSON** (KMIP 2.0+) :
- Format texte selon l'Annexe A de la spécification KMIP 2.0.
- Obligatoire pour les nouvelles intégrations.
- Utiliser le `Content-Type: application/json`.
- Les valeurs binaires (clés, IV, digest) sont encodées en Base64url.

**XML** (KMIP 1.x) :
- Supporté pour la rétrocompatibilité uniquement.
- Utiliser le `Content-Type: application/xml`.

#### 21.1.3 Structure d'un message KMIP

```
Request Message:
  Request Header:
    Protocol Version: { Major: 2, Minor: 1 }
    Maximum Response Size: (optionnel, en octets)
    Client Correlation Value: (optionnel, UUID de corrélation)
    Server Correlation Value: (optionnel)
    Timestamp: (horodatage UTC)
    Asynchronous Indicator: (optionnel)
    Authentication: (credential ou certificat TLS)
    Batch Error Continuation Option: Stop | Continue | Undo
    Batch Order Option: Boolean
    Batch Count: N
  Batch Item[0..N]:
    Operation: (e.g., Create, Get, Locate, ...)
    Unique Batch Item ID: (UUID de l'item)
    Request Payload: (corps de la requête spécifique à l'opération)

Response Message:
  Response Header:
    Protocol Version: { Major: 2, Minor: 1 }
    Timestamp: (horodatage UTC de réponse)
    Server Correlation Value: (UUID de corrélation serveur)
    Batch Count: N
  Batch Item[0..N]:
    Operation: (opération exécutée)
    Unique Batch Item ID: (même UUID que dans la requête)
    Result Status: Success | OperationFailed | OperationPending | OperationUndone
    Result Reason: (code de raison si OperationFailed)
    Result Message: (message lisible si OperationFailed)
    Response Payload: (corps de la réponse spécifique à l'opération)
```

### 21.2 Modèle d'objets KMIP

#### 21.2.1 Hiérarchie des objets KMIP

```
Managed Object (abstract)
├── Cryptographic Object (abstract)
│   ├── Key (abstract)
│   │   ├── Symmetric Key
│   │   ├── Public Key
│   │   ├── Private Key
│   │   └── Split Key
│   └── Certificate
│       └── Certificate Request (KMIP 2.0+)
├── Secret Data
├── Opaque Object
└── PGP Key
```

#### 21.2.2 Attributs KMIP par type d'objet

##### Attributs communs à tous les objets

| Attribut KMIP | Type | Obligatoire | Description |
|---|---|---|---|
| `Unique Identifier` | TextString | Oui (assigné par le serveur) | Identifiant unique interne KMIP |
| `Name` | Structure (Name Value + Name Type) | Souhaitable | Noms fonctionnels multiples |
| `Object Type` | Enum | Oui | `Symmetric Key`, `Private Key`, etc. |
| `State` | Enum | Oui | `Pre-Active`, `Active`, `Deactivated`, etc. |
| `Initial Date` | DateTime | Oui | Date de création sur le serveur |
| `Last Change Date` | DateTime | Oui | Date de dernière modification |
| `Object Group` | TextString | Non | Regroupement logique / tenant |
| `Application Specific Information` | Structure | Non | Métadonnées applicatives (namespace, value) |
| `Contact Information` | TextString | Non | Référent métier ou technique |
| `Custom Attribute` | Extensible | Non | Attributs propriétaires préfixés `x-` |
| `Link` | Structure (Link Type + Linked Object ID) | Non | Relations entre objets (Previous, Next, etc.) |
| `Fresh` | Boolean | Non | Indique si l'objet n'a pas encore été utilisé |

##### Attributs des objets cryptographiques (Symmetric Key, Private Key, Public Key)

| Attribut KMIP | Type | Obligatoire | Description |
|---|---|---|---|
| `Cryptographic Algorithm` | Enum | Oui | `AES`, `RSA`, `EC`, `Ed25519`, etc. |
| `Cryptographic Length` | Integer | Oui | Taille en bits |
| `Cryptographic Usage Mask` | Integer (bitmask) | Oui | Usages autorisés (voir 21.2.3) |
| `Key Block` | Structure | Oui | Valeur de la clé et métadonnées de wrapping |
| `Activation Date` | DateTime | Non (recommandé) | Date d'activation prévue ou effective |
| `Deactivation Date` | DateTime | Non (recommandé) | Date de fin de vie planifiée |
| `Process Start Date` | DateTime | Non | Date de début d'usage pour chiffrement |
| `Protect Stop Date` | DateTime | Non | Date d'arrêt de protection (pour déchiffrement uniquement après cette date) |
| `Destroy Date` | DateTime | Non (positionné à la destruction) | Date de destruction |
| `Compromise Occurrence Date` | DateTime | Non (si compromis) | Date estimée de la compromission |
| `Digest` | Structure | Souhaitable | Empreinte de la clé pour vérification d'intégrité |
| `Cryptographic Parameters` | Structure | Non | Paramètres complémentaires (mode, padding, courbe) |
| `Cryptographic Domain Parameters` | Structure | Non | Paramètres de domaine EC (OID de courbe) |
| `Revocation Reason` | Structure | Non (si révoqué) | Code et message de révocation |

##### Attributs des certificats

| Attribut KMIP | Type | Obligatoire | Description |
|---|---|---|---|
| `Certificate Type` | Enum | Oui | `X.509`, `PGP` |
| `Certificate Value` | ByteString | Oui (dans Key Block) | Valeur DER du certificat |
| `Subject Alternative Name` (via `Name`) | TextString | Non | SAN du certificat |
| `Activation Date` | DateTime | Non (déduit du certificat) | NotBefore |
| `Deactivation Date` | DateTime | Non (déduit du certificat) | NotAfter |

##### Attributs des Secret Data

| Attribut KMIP | Type | Obligatoire | Description |
|---|---|---|---|
| `Secret Data Type` | Enum | Oui | `Password`, `Seed` |
| `Key Block` | Structure | Oui | Valeur du secret (chiffrée au repos) |

#### 21.2.3 Cryptographic Usage Mask (bitmask)

| Bit | Valeur hex | Signification |
|---|---|---|
| Sign | 0x00000001 | Peut signer |
| Verify | 0x00000002 | Peut vérifier |
| Encrypt | 0x00000004 | Peut chiffrer |
| Decrypt | 0x00000008 | Peut déchiffrer |
| Wrap Key | 0x00000010 | Peut wrapper une autre clé |
| Unwrap Key | 0x00000020 | Peut unwrapper une autre clé |
| Export | 0x00000040 | Peut être exportée (Get avec valeur) |
| MAC Generate | 0x00000080 | Peut générer un MAC |
| MAC Verify | 0x00000100 | Peut vérifier un MAC |
| Derive Key | 0x00000200 | Peut être utilisée pour dériver une clé |
| Key Agreement | 0x00000400 | Peut être utilisée pour un accord de clé |
| Certificate Sign | 0x00000800 | Peut signer des certificats (CA key) |
| CRL Sign | 0x00001000 | Peut signer des CRL |
| Generate Cryptogram | 0x00002000 | (contexte paiement) |
| Validate Cryptogram | 0x00004000 | (contexte paiement) |
| Translate Encrypt | 0x00008000 | Translation chiffrée |
| Translate Decrypt | 0x00010000 | Translation déchiffrée |
| Translate Wrap | 0x00020000 | Translation avec wrap |
| Translate Unwrap | 0x00040000 | Translation avec unwrap |
| Authenticate | 0x00080000 | Authentification |
| Unrestricted | 0x10000000 | Tous usages autorisés |

Les masques d'usage par défaut recommandés :

| Type de clé | Masque recommandé | Notes |
|---|---|---|
| AES clé de données | `Encrypt | Decrypt` | Sans export |
| AES KEK (Key Encryption Key) | `Wrap Key | Unwrap Key` | Sans export |
| RSA clé de chiffrement | `Encrypt | Decrypt | Export` | Export conditionnel |
| RSA clé de signature | `Sign | Verify` | Sans export |
| ECDH clé d'échange | `Key Agreement` | Sans export |
| HMAC key | `MAC Generate | MAC Verify` | Sans export |
| Secret Data (password) | Aucun bit crypto | Non exportable par défaut |

### 21.3 Opérations KMIP — Spécification détaillée

#### 21.3.1 Opérations de création

##### `Create` (Symmetric Key)

```
Request Payload:
  Object Type: Symmetric Key
  Attributes:
    Cryptographic Algorithm: AES
    Cryptographic Length: 256
    Cryptographic Usage Mask: 0x0000000C  (Encrypt | Decrypt)
    Name: [{ Name Value: "app-db-key-01", Name Type: Descriptive }]
    Activation Date: (optionnel)
    Object Group: "production/finance"
    Application Specific Information: [{ Namespace: "app", Value: "core-banking" }]

Response Payload:
  Unique Identifier: "550e8400-e29b-41d4-a716-446655440000"
  Attributes:
    State: Pre-Active  // ou Active si Activation Date <= now
```

##### `Create Key Pair` (Asymmetric)

```
Request Payload:
  Common Attributes:
    Cryptographic Algorithm: EC
    Cryptographic Domain Parameters: { Recommended Curve: P-256 }
    Object Group: "pki/signing"
  Private Key Attributes:
    Cryptographic Usage Mask: 0x00000001  (Sign)
    Name: [{ Name Value: "signing-private-2024", Name Type: Descriptive }]
  Public Key Attributes:
    Cryptographic Usage Mask: 0x00000002  (Verify)
    Name: [{ Name Value: "signing-public-2024", Name Type: Descriptive }]

Response Payload:
  Private Key Unique Identifier: "..."
  Public Key Unique Identifier: "..."
```

#### 21.3.2 Opérations de recherche — `Locate`

L'opération `Locate` est fondamentale pour tous les clients KMIP. Le serveur doit supporter les attributs de filtrage suivants :

| Attribut de filtrage | Opérateurs | Notes |
|---|---|---|
| `Object Type` | Égalité | Filtre par type d'objet |
| `State` | Égalité | Filtre par état |
| `Name` | Égalité exacte ou partielle | Recherche par nom |
| `Cryptographic Algorithm` | Égalité | Filtre par algorithme |
| `Cryptographic Length` | Égalité, ≥, ≤ | Filtre par taille |
| `Object Group` | Égalité | Filtre par groupe/tenant |
| `Application Specific Information` | Namespace + Value | Filtre par métadonnée applicative |
| `Initial Date` | Plage de dates | Filtre par date de création |
| `Activation Date` | Plage de dates | Filtre par date d'activation |
| `Deactivation Date` | Plage de dates | Détection des expirations |
| `Custom Attribute` | Égalité | Filtrage sur attributs propriétaires |

La réponse `Locate` retourne uniquement les `Unique Identifier` des objets correspondant aux critères. Un paramètre `Maximum Items` et un paramètre `Offset Items` permettent la pagination.

#### 21.3.3 Opération `Re-key`

L'opération `Re-key` (KMIP 1.2+) permet la rotation d'une clé existante :

```
Request Payload:
  Unique Identifier: "id-de-la-clé-à-roter"
  Offset: (optionnel, durée de chevauchement en secondes)
  Template-Attribute:
    Activation Date: (nouvelle date d'activation)
    Deactivation Date: (nouvelle date de déactivation)

Response Payload:
  Unique Identifier: "id-de-la-nouvelle-clé"
  Template-Attribute:
    State: Pre-Active
    // La clé originale passe à Deactivated avec un Link vers la nouvelle clé
    // La nouvelle clé a un Link vers l'ancienne (Previous)
```

#### 21.3.4 Opérations cryptographiques

##### `Encrypt`

```
Request Payload:
  Unique Identifier: "id-de-la-clé-AES"
  Cryptographic Parameters:
    Block Cipher Mode: GCM
    Padding Method: None
    Hashing Algorithm: SHA-256  // pour GCM
  Data: (données à chiffrer, Base64 en JSON)
  IV/Counter/Nonce: (optionnel, généré par le serveur si absent)
  Authenticated Encryption Additional Data: (optionnel, AAD pour GCM)
  Correlation Value: (optionnel, pour opérations multi-parties)
  Init Indicator: Boolean  // init d'une séquence multi-appels
  Final Indicator: Boolean // fin de séquence

Response Payload:
  Data: (données chiffrées)
  IV/Counter/Nonce: (IV utilisé, si généré par le serveur)
  Authenticated Encryption Tag: (tag GCM)
  Correlation Value: (si Init Indicator)
```

### 21.4 Opérations batch

Le serveur KMIP doit supporter les **requêtes batch** (plusieurs opérations dans un seul message) :

- Le champ `Batch Count` indique le nombre d'opérations dans le batch.
- Le champ `Batch Error Continuation Option` définit le comportement en cas d'erreur partielle :
  - `Stop` : arrêt immédiat à la première erreur.
  - `Continue` : poursuite des opérations suivantes malgré l'erreur.
  - `Undo` : annulation de toutes les opérations précédentes si erreur.
- Chaque `Batch Item` a un `Unique Batch Item ID` permettant la corrélation requête/réponse.
- Le serveur doit indiquer pour chaque item son `Result Status` individuel.
- La limite de taille d'un batch devra être configurable (recommandation : 100 opérations max par batch).

### 21.5 Transport et sécurité TLS pour KMIP

#### 21.5.1 Port et transport

| Mode | Port | Transport | Encodage |
|---|---|---|---|
| KMIP standard (TTLV) | **5696/tcp** | TLS | TTLV binaire |
| KMIP HTTPS (JSON) | 443 ou 5695/tcp | HTTPS | JSON ou TTLV |

Le port 5696 est le port officiel IANA pour KMIP. Tout déploiement doit l'utiliser par défaut.

#### 21.5.2 TLS pour KMIP

- **TLS 1.3** : obligatoire, configuration par défaut.
- **TLS 1.2** : autorisé uniquement pour les clients legacy avec approbation explicite.
- **TLS 1.1 et TLS 1.0** : interdits.
- **mTLS** : obligatoire pour les clients machine (le client KMIP doit présenter son certificat).
- **Cipher suites autorisées (TLS 1.3)** : `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`.
- **Cipher suites autorisées (TLS 1.2)** : `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
- **Vérification du certificat serveur** : obligatoire côté client. Pas de `verify=false` admis en production.
- **SNI** : supporté.
- **Session resumption** : supporté (TLS tickets ou session IDs).
- **OCSP Stapling** : recommandé pour le certificat serveur KMIP.

#### 21.5.3 Gestion des certificats TLS du serveur KMIP

- Le certificat serveur KMIP doit être distinct du certificat de l'IHM web.
- Il doit avoir un SAN contenant le FQDN du serveur KMIP (et l'IP si nécessaire).
- Sa durée de validité doit être ≤ 2 ans (recommandation : 1 an avec rotation automatique).
- La CA émettrice doit être une CA interne dédiée (pas une CA publique pour le serveur KMIP).
- La CRL ou l'OCSP de la CA doit être accessible aux clients KMIP.

### 21.6 Authentification et contrôle d'accès KMIP

#### 21.6.1 Mécanismes d'authentification KMIP

Le champ `Authentication` dans le `Request Header` transporte les credentials. Le serveur doit supporter :

**mTLS (Certificat client TLS)** :
```
Authentication:
  Credential:
    Credential Type: Certificate  // identité extraite du CN ou SAN du certificat TLS
    // La valeur du certificat est dans la couche TLS, pas dans le payload KMIP
```

**Username and Password Credential** :
```
Authentication:
  Credential:
    Credential Type: UsernameAndPassword
    Credential Value:
      Username: "app-service-account"
      Password: "..."  // transmis chiffré par TLS
```

**Attestation Credential (KMIP 2.0+)** :
```
Authentication:
  Credential:
    Credential Type: Attestation
    Credential Value:
      Nonce Value: (nonce fourni par le serveur lors d'une interaction préalable)
      Attestation Type: TPM Quote | TCG Integrity Report | SAML Assertion
      Attestation Measurement: (valeur d'attestation signée)
```

#### 21.6.2 Access Policy (KMIP 2.x)

Le modèle KMIP 2.x permet une politique d'accès fine par opération et type d'objet :

```
Access Policy:
  Operation Policy Name: "app-encrypt-only"
  Access Policy Item[]:
    Object Type: Symmetric Key
    Permission[]:
      Operation: Encrypt
      Allow: True
      Privileged: False
    Permission[]:
      Operation: Decrypt
      Allow: True
      Privileged: False
    Permission[]:
      Operation: Get  // export de la valeur
      Allow: False    // interdit
    Permission[]:
      Operation: Destroy
      Allow: False    // interdit
```

#### 21.6.3 Operation Policy (KMIP 1.x — compatibilité)

Le modèle KMIP 1.x utilise des noms de politique prédéfinis. Le serveur doit maintenir la compatibilité avec les politiques nommées suivantes :

| Nom de politique | Usages | Notes |
|---|---|---|
| `default` | Toutes opérations pour les objets de l'appelant | Politique de base |
| `restricted` | Get Attributes, Locate uniquement | Lecture seule |
| `deny-all` | Aucune opération | Suspension |

---

## 22. Profils KMIP et conformité OASIS

### 22.1 Profils OASIS à implémenter

Les profils OASIS KMIP définissent des ensembles cohérents d'opérations, d'objets et de comportements. Le serveur doit cibler les profils suivants :

#### Profils serveur prioritaires

| Profil OASIS | Priorité | Description |
|---|---|---|
| **Baseline Server KMIP Profile** | Obligatoire | Opérations de base, Symmetric Key et Certificate |
| **Complete Server KMIP Profile** | Obligatoire | Toutes opérations et tous types d'objets |
| **Storage Array Without Self-Encrypting Drive Server Profile** | Souhaitable | Pour l'intégration avec les baies de stockage |
| **Storage Array With Self-Encrypting Drive Server Profile** | Souhaitable | Pour les SED |
| **HTTPS Server Profile** | Obligatoire | KMIP sur HTTPS (JSON) |
| **JSON Profile** | Obligatoire (KMIP 2.x) | Encodage JSON |
| **Basic Cryptographic Server KMIP Profile** | Souhaitable | Encrypt/Decrypt/Sign/Verify via KMIP |
| **Advanced Cryptographic Server KMIP Profile** | Optionnel | MAC, RNG, Hash via KMIP |
| **Tape Library Server Profile** | Optionnel | Pour les bibliothèques à bandes |

#### 22.1.1 Contenu du Baseline Server Profile

Le Baseline Server Profile requiert la prise en charge de :
- **Object Types** : Symmetric Key, Public Key, Private Key, Certificate, Certificate Request, Secret Data
- **Operations** : Create, Create Key Pair, Register, Locate, Get, Get Attributes, Get Attribute List, Activate, Revoke, Destroy, Discover Versions, Query
- **Attributes obligatoires** : Unique Identifier, Name, Object Type, Cryptographic Algorithm, Cryptographic Length, Cryptographic Usage Mask, State, Initial Date

#### 22.1.2 Contenu du Complete Server Profile

Le Complete Server Profile étend le Baseline avec :
- **Object Types** : + Opaque Object, Split Key, PGP Key
- **Operations** : + Re-key, Re-certify, Derive Key, Archive, Recover, Add Attribute, Modify Attribute, Delete Attribute, Set Attribute, Obtain Lease, Get Usage Allocation, Check, Cancel, Poll
- **Attributes optionnels** : Tous les attributs définis dans la spécification

### 22.2 Tests de conformité OASIS

L'implémentation devra passer les tests de la **OASIS KMIP Interoperability Test Suite** disponibles à titre de référence normative.

#### 22.2.1 Catégories de tests

| Catégorie | Description | Couverture |
|---|---|---|
| TC-BL | Baseline tests | Opérations Create, Get, Locate, Destroy |
| TC-CS | Complete Server tests | Toutes opérations Complete Profile |
| TC-CR | Cryptographic tests | Encrypt, Decrypt, Sign, Verify |
| TC-SK | Split Key tests | Create Split Key, Join Split Key |
| TC-TL | Transport et TLS tests | Connexion TLS, mTLS, certificats |
| TC-AU | Authentification tests | Credentials KMIP, rejet non-authentifié |
| TC-AP | Access Policy tests | Isolation des ressources, refus d'accès |

#### 22.2.2 Clients KMIP de référence pour les tests

Les tests d'interopérabilité devront être exécutés avec les clients suivants :

| Client | Type | Référence |
|---|---|---|
| PyKMIP | Open source Python | Tests unitaires et d'intégration |
| kmip4j | Open source Java | Intégration applicative Java |
| OpenKMIP | Open source Go | Intégration cloud-native |
| Client commercial de référence | Commercial | Selon environnement cible de l'organisation |

---

## 23. Implémentation du serveur KMIP — Exigences détaillées

### 23.1 Opérations obligatoires (Baseline Server Profile)

Chaque opération listée ci-dessous doit être implémentée avec les codes de résultat corrects.

#### `Discover Versions`

- Retourne la liste des versions KMIP supportées.
- **Ne nécessite pas d'authentification** (peut être appelée avant la phase d'authentification).
- Doit retourner les versions dans l'ordre décroissant (de la plus récente à la plus ancienne).

#### `Query`

La réponse doit inclure les champs suivants :

```
Response Payload:
  Operations: [liste de toutes les opérations supportées]
  Object Types: [liste de tous les types d'objets supportés]
  Vendor Identification: "Nom du fournisseur"
  Server Information: "Version serveur"
  Conformance Clause: [liste des profils supportés]
  Authentication Suites: [mécanismes d'authentification supportés]
  Application Namespaces: [namespaces Application Specific Information supportés]
  Extension Information: [extensions propriétaires si applicable]
```

### 23.2 Gestion des erreurs KMIP

Le serveur doit retourner des `Result Status` et `Result Reason` précis :

| Result Status | Codes Result Reason fréquents | Signification |
|---|---|---|
| `OperationFailed` | `PermissionDenied` | Opération refusée par Access Policy |
| `OperationFailed` | `NotFound` | Objet `Unique Identifier` inexistant |
| `OperationFailed` | `InvalidField` | Attribut manquant ou mal formé |
| `OperationFailed` | `InvalidMessage` | Message KMIP mal structuré |
| `OperationFailed` | `ItemNotFound` | Locate : aucun objet correspondant |
| `OperationFailed` | `InvalidCSRFormat` | Certificate Request invalide |
| `OperationFailed` | `ResponseTooLarge` | Maximum Response Size dépassé |
| `OperationFailed` | `EncodingOptionError` | Encodage non supporté par le serveur |
| `OperationFailed` | `KeyValueNotPresent` | Tentative de Get sur objet non exportable |
| `OperationFailed` | `CryptographicFailure` | Opération crypto interne échouée |
| `OperationPending` | N/A | Opération asynchrone en attente |

### 23.3 Key Wrapping — Détail d'implémentation

Lors d'un `Get` avec `Key Wrapping Specification` :

```
Key Wrapping Specification:
  Wrapping Method: Encrypt  // AES-KW, RSA-OAEP, etc.
  Encryption Key Information:
    Unique Identifier: "id-de-la-KEK"
    Cryptographic Parameters:
      Block Cipher Mode: NISTKeyWrap  // ou GCM, etc.
      Padding Method: None           // pour NISTKeyWrap
  MAC/Signature Key Information: (optionnel, pour modes Encrypt-then-MAC)
  Attribute Names: [liste d'attributs à embarquer dans le Key Block]
  Encoding Option: TTLVEncoding | NoEncoding | QueryField
```

Le Key Block retourné doit inclure :
- La valeur de la clé chiffrée (wrapped).
- Le `Key Format Type` (Raw, PKCS1, PKCS8, etc.).
- Les `Key Wrapping Data` avec toutes les métadonnées nécessaires au unwrapping.
- Les attributs embarqués (selon `Attribute Names`).

### 23.4 Split Key (Shamir Secret Sharing)

Le serveur doit supporter les opérations `Create Split Key` et `Join Split Key` pour les scénarios M-of-N :

```
Create Split Key Request:
  Unique Identifier: "id-de-la-clé-source"
  Split Key Parts: 5           // N total de fragments
  Key Part Identifier: 1       // numéro de ce fragment (1..N)
  Split Key Threshold: 3       // M minimum pour reconstituer
  Split Key Method: PolynomialSharingGF2_16 | XOR

Response (pour chaque fragment):
  Unique Identifier: "id-du-fragment-i"
  // La clé source peut être détruite ou conservée selon la politique
```

```
Join Split Key Request:
  Split Key Parts:
    Unique Identifier[]: ["fragment-1-id", "fragment-2-id", "fragment-3-id"]
  Unique Identifier: "id-de-la-clé-à-reconstituer"  // optionnel
  Object Type: Symmetric Key

Response:
  Unique Identifier: "id-de-la-clé-reconstituée"
```

### 23.5 Dérivation de clé — `Derive Key`

```
Derive Key Request:
  Unique Identifier: "id-de-la-clé-mère"
  Derivation Method: HKDF | PBKDF2 | NIST800_108-CTR | NIST800_108-FB | ...
  Derivation Parameters:
    Hash Algorithm: SHA-256
    Salt Value: (pour HKDF)
    Info Value: (pour HKDF)
    Iteration Count: 100000  // pour PBKDF2
  Template-Attribute:
    Object Type: Symmetric Key
    Cryptographic Algorithm: AES
    Cryptographic Length: 256
    Cryptographic Usage Mask: 0x0000000C

Response:
  Unique Identifier: "id-de-la-clé-dérivée"
```

---

## 24. Enrôlement et gestion des clients KMIP

### 24.1 Processus d'enrôlement d'un client KMIP

L'enrôlement d'un nouveau client KMIP doit suivre le processus suivant :

1. **Demande d'enrôlement** (via IHM ou API REST, par un Intégrateur applicatif ou Opérateur KMS) :
   - Nom du client, type (application, équipement, base de données, etc.)
   - Domaine de rattachement / `Object Group`
   - Access Policy à assigner
   - Justification métier

2. **Approbation** (par un Opérateur KMS ou Administrateur sécurité selon la politique) :
   - Vérification de la justification
   - Validation du périmètre d'accès

3. **Génération du certificat client TLS** :
   - Le KMS génère une paire de clés RSA-2048 ou EC-P256 pour le client.
   - Il génère et signe le certificat client (via la CA interne dédiée KMIP).
   - Le CN du certificat contient l'identifiant unique du client.
   - La durée de validité est paramétrable (recommandation : 1 an).

4. **Remise des matériaux de connexion** :
   - Certificat client (PEM).
   - Clé privée client (PEM, chiffrée par un mot de passe à usage unique).
   - Certificat de la CA KMS pour la vérification du serveur.
   - Paramètres de connexion : host, port (5696), version KMIP, encodage.

5. **Configuration côté client** :
   - Le client configure son keystore/truststore.
   - Vérification de la connexion via `Discover Versions`.

### 24.2 Renouvellement et révocation des certificats clients

- **Renouvellement** : 30 jours avant expiration, alerte automatique + workflow de renouvellement.
- **Révocation** : 
  - Via l'IHM : révocation immédiate du certificat client (ajout à la CRL ou OCSP).
  - Le serveur KMIP doit vérifier la CRL ou l'OCSP avant d'accepter toute connexion.
  - Délai de propagation de la révocation : < 5 minutes.

### 24.3 Journalisation des sessions KMIP

Pour chaque session TLS établie sur le port 5696, le serveur doit journaliser :

```json
{
  "timestamp": "2026-01-15T10:30:00Z",
  "event_type": "kmip_session_established",
  "client_cn": "app-banking-core",
  "client_cert_serial": "0x4A2F...",
  "client_ip": "10.1.2.3",
  "tls_version": "TLSv1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "session_id": "abc123...",
  "kmip_version_negotiated": "2.1"
}
```

---

## 25. Plan de tests d'interopérabilité KMIP

### 25.1 Organisation des tests

Les tests d'interopérabilité devront être organisés en deux phases :

**Phase 1 — Tests unitaires serveur** (automatisés, CI/CD) :
- Tests de chaque opération KMIP isolément.
- Tests des codes de retour (`Result Status`, `Result Reason`).
- Tests des attributs obligatoires.
- Tests de gestion des erreurs (messages malformés, objets inexistants, accès refusé).

**Phase 2 — Tests d'interopérabilité client-serveur** (intégration) :
- Tests avec clients KMIP de référence (PyKMIP, kmip4j, OpenKMIP).
- Tests de scénarios complets (cycle de vie d'une clé, rotation, export wrappé).
- Tests de conformité aux profils OASIS.

### 25.2 Matrice de tests KMIP

| ID Test | Opération | Scénario | Version KMIP | Résultat attendu |
|---|---|---|---|---|
| T-001 | Discover Versions | Sans authentification | 1.4, 2.1 | Liste des versions |
| T-002 | Query | Après authentification | 2.1 | Capacités complètes |
| T-003 | Create | AES-256, Encrypt+Decrypt | 2.1 | Unique Identifier retourné, State=Pre-Active |
| T-004 | Activate | T-003 → Active | 2.1 | State=Active |
| T-005 | Get | Avec Key Wrapping | 2.1 | Key Block correct |
| T-006 | Get | Sans Key Wrapping, clé non-exportable | 2.1 | PermissionDenied |
| T-007 | Locate | Filtre par Algorithm + State | 2.1 | Liste des UIDs |
| T-008 | Get Attributes | Tous attributs d'un Symmetric Key | 2.1 | Attributs obligatoires présents |
| T-009 | Revoke | Raison = Key Compromise | 2.1 | State=Compromised |
| T-010 | Destroy | Objet Compromised | 2.1 | State=Destroyed Compromised |
| T-011 | Re-key | Rotation d'une clé active | 2.1 | Nouvelle clé, Link Previous |
| T-012 | Encrypt | AES-256-GCM via KMIP | 2.1 | Données chiffrées + Tag |
| T-013 | Decrypt | Données T-012 | 2.1 | Données originales |
| T-014 | Batch | 10 Create dans une requête | 2.1 | 10 UIDs retournés |
| T-015 | Batch avec erreur | Continue option | 2.1 | Items valides réussis, item invalide échoué |
| T-016 | Create Key Pair | EC P-256, Sign+Verify | 2.1 | 2 UIDs (Private + Public) |
| T-017 | Sign / Verify | Paire T-016 | 2.1 | Signature valide |
| T-018 | Register | Import d'un certificat X.509 | 2.1 | UID retourné |
| T-019 | Locate (pagination) | 10000 objets, offset 100 | 2.1 | 100 items, sans timeout |
| T-020 | Accès non autorisé | Client sans certificat valide | 2.1 | Rejet TLS avant KMIP |
| T-021 | Accès hors périmètre | Get sur objet d'un autre groupe | 2.1 | PermissionDenied |
| T-022 | Create Split Key | M=3, N=5 | 2.1 | 5 fragments créés |
| T-023 | Join Split Key | 3 fragments de T-022 | 2.1 | Clé reconstituée |
| T-024 | KMIP 1.4 compat | Create + Get + Destroy (encodage TTLV) | 1.4 | Succès avec client 1.4 |

---

## 26. Connecteur HSM — Exigences détaillées

### 26.1 Interface PKCS#11

Le connecteur HSM devra s'appuyer sur l'interface **PKCS#11 version 2.40** (ou supérieure). Les fonctions PKCS#11 suivantes devront être utilisées :

| Fonction PKCS#11 | Usage dans le KMS |
|---|---|
| `C_Initialize` / `C_Finalize` | Initialisation du provider HSM |
| `C_OpenSession` / `C_CloseSession` | Gestion des sessions HSM |
| `C_Login` / `C_Logout` | Authentification auprès du HSM |
| `C_GenerateKey` | Génération de clé symétrique dans le HSM |
| `C_GenerateKeyPair` | Génération de paire de clés dans le HSM |
| `C_WrapKey` | Wrapping d'une clé KMS par le KEK HSM |
| `C_UnwrapKey` | Unwrapping pour accès à la valeur |
| `C_Encrypt` / `C_Decrypt` | Opérations crypto déléguées au HSM |
| `C_Sign` / `C_Verify` | Signature / Vérification dans le HSM |
| `C_GenerateRandom` | Génération d'aléa depuis le HSM (TRNG) |
| `C_DestroyObject` | Destruction d'une clé dans le HSM |
| `C_GetInfo` / `C_GetSlotInfo` | Supervision du HSM |

### 26.2 Architecture HSM dans le KMS

Les clés devront être catégorisées selon leur résidence :

| Catégorie | Résidence | Protection |
|---|---|---|
| Master KEK (MKEK) | HSM (token/slot dédié) | Ne quitte jamais le HSM |
| Key Encryption Key (KEK) | HSM ou Software HSM | Wrappée par MKEK si Software HSM |
| Clés utilisateur critiques (haute valeur) | Wrappées par KEK HSM, stockées en base | Unwrapping à chaque usage |
| Clés utilisateur standard | Wrappées par KEK Software, stockées en base | Compromis performance/sécurité |
| Clés de session | Éphémères en mémoire | Jamais persistées |

### 26.3 Fournisseurs HSM supportés

Le connecteur PKCS#11 devra être testé avec les fournisseurs suivants (en ordre de priorité selon le contexte de déploiement) :

| Fournisseur | Type | Notes |
|---|---|---|
| Thales Luna Network HSM | Hardware HSM réseau | Référence en entreprise |
| Entrust nShield | Hardware HSM réseau | Alternative courante |
| AWS CloudHSM | HSM cloud managé | Déploiements AWS |
| Azure Dedicated HSM | HSM cloud managé | Déploiements Azure |
| SoftHSM2 (opensc) | Software HSM | Développement et test uniquement |
| PKCS#11 générique | Tout provider PKCS#11 2.40+ | Via configuration |

---

## 27. Conformité normative et réglementaire

### 27.1 Références normatives

| Référentiel | Applicabilité |
|---|---|
| OASIS KMIP 2.1 | Protocole KMIP — référence primaire |
| OASIS KMIP 1.4 | Rétrocompatibilité clients legacy |
| NIST SP 800-57 Part 1 Rev. 5 | Recommandations gestion des clés |
| NIST SP 800-131A Rev. 2 | Algorithmes et longueurs de clés — transitional/acceptable |
| NIST SP 800-90A Rev. 1 | Générateurs de nombres aléatoires (DRBG) |
| NIST SP 800-111 | Chiffrement des données au repos |
| FIPS 140-3 | Modules cryptographiques (si certification exigée) |
| RFC 5246 | TLS 1.2 |
| RFC 8446 | TLS 1.3 |
| RFC 5280 | Certificats X.509 v3 |
| RFC 5958 | PKCS#8 (format de clé privée) |
| RFC 3394 | AES Key Wrap |
| RFC 5649 | AES Key Wrap with Padding |
| RFC 8017 | PKCS#1 v2.2 (RSA) |
| PKCS#11 v2.40 | Interface HSM |

### 27.2 Considérations réglementaires

Selon le secteur d'activité et la juridiction, les contraintes suivantes peuvent s'appliquer :

| Réglementation | Impact sur le KMS |
|---|---|
| RGPD / GDPR | Chiffrement des données personnelles, droit à l'effacement (destruction de clé) |
| NIS2 | Mesures de sécurité pour les entités essentielles et importantes |
| DSP2 / PCI-DSS | Gestion des clés de paiement (TR-31, HSM certifié) |
| eIDAS | Signature électronique avancée et qualifiée |
| Directive NIS | Continuité de service, journalisation |
| Politique ANSSI | Référentiel français, recommandations crypto RGS |

---

## 28. Glossaire KMIP

| Terme | Définition |
|---|---|
| **Access Policy** | Modèle de contrôle d'accès KMIP 2.x, associant des permissions à des opérations et types d'objets |
| **Batch Item** | Unité d'opération dans une requête KMIP batch |
| **Cryptographic Usage Mask** | Bitmask définissant les usages autorisés d'un objet cryptographique |
| **Derive Key** | Opération KMIP de dérivation d'une clé depuis une clé mère |
| **Discover Versions** | Opération KMIP de négociation de version entre client et serveur |
| **Initial Date** | Date et heure de création de l'objet sur le serveur KMIP |
| **KEK (Key Encryption Key)** | Clé utilisée pour chiffrer (wrapper) d'autres clés |
| **Key Block** | Structure KMIP encapsulant la valeur d'une clé et ses métadonnées de wrapping |
| **KMIP** | Key Management Interoperability Protocol — standard OASIS |
| **Locate** | Opération KMIP de recherche d'objets par attributs |
| **MKEK (Master Key Encryption Key)** | KEK de plus haut niveau, généralement stockée dans un HSM |
| **mTLS** | Mutual TLS — authentification bidirectionnelle par certificat |
| **Object Group** | Attribut KMIP permettant le regroupement logique d'objets |
| **Opaque Object** | Objet KMIP dont le contenu est opaque au serveur (données binaires arbitraires) |
| **Operation Policy** | Modèle de contrôle d'accès KMIP 1.x, référencé par nom |
| **Pre-Active** | État initial d'un objet KMIP, non encore utilisable |
| **Re-key** | Opération KMIP de rotation de clé avec lien vers la clé précédente |
| **Secret Data** | Type d'objet KMIP pour stocker des secrets non cryptographiques (mots de passe, tokens) |
| **Split Key** | Fragments d'une clé divisée selon un schéma M-of-N (Shamir Secret Sharing) |
| **TTLV** | Tag-Type-Length-Value — encodage binaire standard des messages KMIP |
| **Unique Identifier** | Identifiant unique assigné par le serveur KMIP à chaque objet |
| **Wrapping Method** | Méthode de chiffrement utilisée pour protéger la valeur d'une clé lors d'un export |
