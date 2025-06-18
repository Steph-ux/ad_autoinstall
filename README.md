Script PowerShell d’Automatisation d’Active Directory
Description
Ce script PowerShell automatise la création et la gestion d’un domaine Active Directory (AD) sous Windows Server.
Il permet notamment :

L’installation d’un domaine AD dans une nouvelle forêt avec promotion du contrôleur principal

La configuration complète du DNS (zone primaire, redirecteurs)

L’ajout d’un second contrôleur de domaine (DC) en réplication

La création et liaison de GPOs spécifiques à des groupes de sécurité

L’application de stratégies de sécurité globale (politiques de mot de passe, audit, arrêt sécurisé)

Une interface interactive avec menu pour sélectionner les actions à réaliser

Vérifications pour ne pas dupliquer les configurations existantes

Gestion des erreurs et journalisation dans un fichier log

Prérequis
Windows Server (2012 R2, 2016, 2019, 2022) avec rôle AD DS disponible

PowerShell exécuté en mode administrateur

Droits suffisants pour installer et configurer AD, DNS, GPOs

Accès en écriture dans %TEMP% ou C:\Windows\Temp pour fichiers temporaires

Fonctionnalités
Option du menu	Description
1. Installer domaine AD + DNS + promotion contrôleur principal + config DNS + stratégies globales	Création d’une nouvelle forêt AD complète avec DNS et paramètres de base
2. Ajouter un second contrôleur de domaine (DC)	Promotion d’un serveur existant en second DC avec réplication
3. Créer des GPOs spécifiques et les lier à un groupe	Création automatique de GPOs (ex: désactivation USB, blocage panneau de config) appliqués à un groupe AD existant
4. Appliquer stratégies de sécurité globale	Application de politiques mot de passe, audit et sécurité locale
5. Quitter	Sortie du script

Utilisation
Ouvrir PowerShell en mode administrateur

Placer le script dans un dossier accessible (ex: C:\Scripts)

Lancer le script :

powershell
Copier
Modifier
.\ad_autoinstall.ps1
Suivre les instructions à l’écran pour choisir les options et renseigner les paramètres demandés (nom de domaine, mot de passe DSRM, nom du second DC, groupe AD pour GPOs, etc.)

Le script vérifie l’existant pour éviter les duplications

À la fin de chaque action, un résumé est affiché et l’on peut continuer ou quitter

Exemples
Installer le domaine principal (option 1)
Le script demande le nom FQDN du domaine (ex: corp.local)

Le nom NetBIOS (ex: CORP)

Le mot de passe DSRM (mode restauration)

Installe le rôle AD DS, DNS, crée la forêt, la zone DNS, configure les redirecteurs

Applique les stratégies de sécurité globales par défaut

Ajouter un second contrôleur (option 2)
Demande le FQDN du second serveur DC

Vérifie la connectivité réseau

Promote le serveur en DC secondaire

Créer des GPOs (option 3)
Liste des GPOs prédéfinis (ex: désactivation USB, blocage panneau de configuration)

Demande le groupe de sécurité AD cible (ex: GPO_USB_Disabled)

Vérifie l’existence du groupe dans AD

Crée et lie la GPO à ce groupe

Appliquer stratégies de sécurité (option 4)
Configure la longueur minimale des mots de passe et la complexité

Active l’audit système et logon

Interdit l’arrêt de la machine sans authentification

Affiche un rapport et journalise l’opération

Notes importantes
Le script doit être exécuté en administrateur pour fonctionner correctement

Les chemins de fichiers temporaires sont par défaut dans C:\Windows\Temp pour éviter des problèmes de permission

Pour certains paramètres d’audit, le script utilise auditpol et net accounts en remplacement de secedit afin d’éviter des erreurs connues

En cas de domaine déjà existant, le script détecte et propose de passer à l’étape suivante sans écraser les configurations

Les logs sont sauvegardés dans un fichier ad_autoinstall.log dans le même dossier que le script

Dépannage
Erreur de droits : Assurez-vous que la console PowerShell est lancée en mode administrateur

Échec promotion AD DS : Vérifier que les noms de domaine (FQDN, NetBIOS) respectent la syntaxe valide

Problème DNS : Confirmer la configuration réseau et la disponibilité du serveur DNS principal

Erreurs avec secedit : Le script contourne parfois avec net accounts et auditpol pour une meilleure compatibilité

Logs détaillés : Consulter ad_autoinstall.log et C:\Windows\Temp\secedit.log pour plus d’informations

Contribution
Tu peux modifier et améliorer le script selon tes besoins. Toute contribution ou demande d’aide est la bienvenue.

Licence
Script fourni « tel quel » sans garantie. Utilisation à vos risques.

