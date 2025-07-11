# vanity-btc
## Bitcoin Vanity: Get an address that contains YOUR NAME (or somthing else)

Générateur d'Adresses Bitcoin Vanity en Rust Un programme Rust pour générer des adresses Bitcoin sécurisées, incluant des adresses personnalisées (vanity addresses) contenant un mot ou un préfixe spécifique, en utilisant la cryptographie ECDSA avec la courbe secp256k1. Attention : **Ce projet est à des fins éducatives uniquement.** N'utilisez pas les clés générées pour de vrais Bitcoins sans un générateur audité et sécurisé ! 

Ce programme permet de :
- Générer des clés privées sécurisées et leurs clés publiques associées.
- Créer des adresses Bitcoin au format P2PKH (Legacy, commençant par 1).
- Générer des adresses vanity contenant un mot spécifique (ex. : aa, bb) ou commençant par un préfixe.
- Vérifier la validité cryptographique des clés et adresses générées.
- Afficher les détails : clé privée (HEX et WIF), clé publique (compressée et non compressée), et adresse Bitcoin.

Le programme utilise des bibliothèques modernes comme secp256k1 pour la cryptographie, sha2 et ripemd pour le hachage, et rand pour la génération aléatoire sécurisée. FonctionnalitésGénération de clés privées sécurisées avec la courbe elliptique secp256k1.

## Création d'adresses Bitcoin P2PKH avec encodage Base58.
- Mode vanity : Trouve des adresses contenant un mot ou un préfixe spécifique.
- Validation cryptographique pour garantir l'intégrité des clés et adresses.
- Affichage des statistiques (nombre de tentatives, temps écoulé, vitesse) pour les adresses vanity.
- Informations techniques sur la cryptographie Bitcoin (courbe secp256k1, hachage, etc.).

## PrérequisRust : Installez Rust et Cargo via rustup.
Un environnement de développement compatible (Linux, macOS, Windows).
Les dépendances listées dans Cargo.toml.

## Installation

Clonez le dépôt :bash

```git clone https://github.com/<votre-nom>/bitcoin-address-generator.git```
```cd bitcoin-address-generator```

Ajoutez les dépendances dans votre Cargo.toml :toml

```
[dependencies]
secp256k1 = { version = "0.29", features = ["rand"] }
rand = "0.8"
sha2 = "0.10"
ripemd = "0.1"
hex = "0.4"
```

Compilez et exécutez :bash

```
cargo run
```

## UtilisationLancer le programme :
Exécutez cargo run pour lancer le programme par défaut. Il va :Générer une adresse Bitcoin et vérifier sa validité cryptographique.
Chercher des adresses vanity contenant les mots "aa" et "bb".
Générer une adresse Bitcoin standard avec tous les détails.
Afficher des informations techniques sur la cryptographie utilisée.

## Personnaliser les adresses vanity :
Modifiez la liste target_words dans la fonction main pour chercher d'autres mots :rust
```
let target_words = vec!["monnom", "cool"];
```

Note : Les mots longs augmentent considérablement le temps de génération.

