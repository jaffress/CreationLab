# Lab Active Directory Vulnérable – DAT 

## Présentation

Ce projet propose un environnement de laboratoire complet pour l’apprentissage de la sécurité Active Directory, la manipulation d’un domaine Windows, l’administration réseau, et l’analyse de services vulnérables. Il s’appuie sur la virtualisation (VirtualBox), l’automatisation PowerShell, et l’intégration d’un serveur Linux avec application vulnérable.

## Fonctionnalités principales
- Installation et vérification d’ISOs Windows et Ubuntu
- Déploiement d’un contrôleur de domaine Active Directory (AD DS) avec DNS
- Ajout d’un client Windows au domaine
- Configuration réseau statique, SMB, WinRM, RDP
- Génération d’un environnement AD réaliste avec BadBlood
- Déploiement d’un serveur Ubuntu avec SSH et application vulnérable (VulnerableLightApp)
- Documentation détaillée avec captures d’écran et explications pédagogiques

## Structure du projet
- `docs/DAT.md` : Documentation technique détaillée (étapes, commandes, explications, images)
- `docs/images/` : Captures d’écran illustrant chaque étape

## Prérequis
- VirtualBox (ou équivalent)
- ISOs Windows Server, Windows 10/11, Ubuntu Desktop
- 8 Go RAM minimum, 60 Go disque libre recommandé
- Accès Internet pour téléchargement des ISOs et outils

## Installation rapide
1. Télécharger les ISOs depuis les sites officiels
2. Vérifier les hashes SHA256
3. Créer les VMs (Windows Server, Windows Client, Ubuntu)
4. Suivre pas à pas le fichier `docs/DAT.md`

## Ressources utiles
- [PowerShell Get-FileHash](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash)
- [BadBlood (GitHub)](https://github.com/davidprowe/BadBlood)
- [VulnerableLightApp](https://github.com/Aif4thah/VulnerableLightApp)

## Auteur & crédits
- Réalisé par Elif J. dans le cadre du DAT Simplon 2025
- Encadrement pédagogique : équipe Simplon
- Merci à la communauté open source pour les outils et scripts utilisés

---

Pour toute question ou suggestion : ouvrez une issue ou contactez l’auteur.


