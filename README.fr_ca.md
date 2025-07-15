<div align="center">
    <h1>🛡️Audit des Comptes Administrateurs🛡️</h1>
    <img src="logo.png" width="230">
    <br/>

[Voir la version anglaise](./README.md)
</div>

## Description

**Audit des Comptes Administrateurs** est un outil CLI Rust permettant d’auditer les attributions de rôles et la propriété des groupes dans Azure, en mettant l’accent sur l’identification des utilisateurs non-administrateurs ayant reçu des privilèges élevés ou étant propriétaires de groupes de sécurité. L’outil récupère toutes les attributions de rôles, utilisateurs et groupes, puis génère un rapport JSON listant les utilisateurs non-admin avec des attributions de rôles directes ou via des groupes, ainsi que les propriétaires de groupes non-admin.

- Conçu pour les environnements Azure
- Résultats exportés au format JSON
- Aide à identifier les potentielles élévations de privilèges

## Utilisation

```sh
admin_account_audit <chemin_sortie> [--overwrite-existing]
```

- `<chemin_sortie>` : Chemin du fichier JSON de sortie.
- `--overwrite-existing` : Écrase le fichier de sortie s’il existe déjà.

## Exemple

```sh
admin_account_audit output.json --overwrite-existing
```

## Droits d’auteur

Droits d’auteur appartiennent à © Sa Majesté le Roi du chef du Canada, qui est représenté par le ministre de l’Agriculture et de l’Agroalimentaire, 2024