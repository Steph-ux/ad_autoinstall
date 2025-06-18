# Script PowerShell d’Automatisation d’Active Directory

## 📌 Description

Ce script PowerShell automatise la création et la gestion d’un domaine Active Directory (AD) sous Windows Server.  
Il permet notamment :

- ✅ L’installation d’un domaine AD dans une nouvelle forêt avec promotion du contrôleur principal
- ✅ La configuration complète du DNS (zone primaire, redirecteurs)
- ✅ L’ajout d’un second contrôleur de domaine (DC) en réplication
- ✅ La création et liaison de GPOs spécifiques à des groupes de sécurité
- ✅ L’application de stratégies de sécurité globale (politiques de mot de passe, audit, arrêt sécurisé)
- ✅ Une interface interactive avec menu pour sélectionner les actions à réaliser
- ✅ Vérifications pour ne pas dupliquer les configurations existantes
- ✅ Gestion des erreurs et journalisation dans un fichier log

---

## 🧱 Prérequis

- Windows Server (2012 R2, 2016, 2019, 2022) avec rôle **AD DS** disponible
- PowerShell exécuté **en mode administrateur**
- Droits suffisants pour installer et configurer **AD, DNS, GPOs**
- Accès en écriture dans `%TEMP%` ou `C:\Windows\Temp` pour fichiers temporaires

---

## ⚙️ Fonctionnalités

| Option du menu | Description |
|----------------|-------------|
| **1. Installer domaine AD + DNS + promotion contrôleur principal + config DNS + stratégies globales** | Création d’une nouvelle forêt AD complète avec DNS et paramètres de base |
| **2. Ajouter un second contrôleur de domaine (DC)** | Promotion d’un serveur existant en second DC avec réplication |
| **3. Créer des GPOs spécifiques et les lier à un groupe** | Création automatique de GPOs (ex: désactivation USB, blocage panneau de config) appliqués à un groupe AD existant |
| **4. Appliquer stratégies de sécurité globale** | Application de politiques mot de passe, audit et sécurité locale |
| **5. Quitter** | Sortie du script |

---

## ▶️ Utilisation

1. **Ouvrir PowerShell en mode administrateur**
2. **Placer le script dans un dossier accessible**, ex : `C:\Scripts`
3. **Lancer le script** :
   ```powershell
    Set-ExecutionPolicy Bypass -Scope Process
   .\ad_autoinstall.ps1
