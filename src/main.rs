use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, SecretKey, PublicKey as Secp256k1PublicKey};

// Structure pour représenter une clé privée Bitcoin
#[derive(Debug, Clone)]
struct PrivateKey {
    secret_key: SecretKey,
}

// Structure pour représenter une clé publique Bitcoin
#[derive(Debug, Clone)]
struct PublicKey {
    public_key: Secp256k1PublicKey,
}

// Structure pour représenter une adresse Bitcoin
#[derive(Debug)]
struct BitcoinAddress {
    private_key: PrivateKey,
    public_key: PublicKey,
    address: String,
}

impl PrivateKey {
    // Génère une nouvelle clé privée cryptographiquement sécurisée
    fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let secret_key = SecretKey::new(&mut rng);
        PrivateKey { secret_key }
    }
    
    // Convertit la clé privée en format WIF (Wallet Import Format)
    fn to_wif(&self) -> String {
        let mut extended_key = Vec::new();
        extended_key.push(0x80); // Version byte pour mainnet
        extended_key.extend_from_slice(&self.secret_key.secret_bytes());
        extended_key.push(0x01); // Suffix pour clé publique compressée
        
        // Double SHA256 pour le checksum
        let hash1 = Sha256::digest(&extended_key);
        let hash2 = Sha256::digest(&hash1);
        
        // Ajouter les 4 premiers bytes du hash comme checksum
        extended_key.extend_from_slice(&hash2[0..4]);
        
        // Encoder en base58
        base58_encode(&extended_key)
    }
    
    // Convertit la clé privée en format hexadécimal
    fn to_hex(&self) -> String {
        hex::encode(&self.secret_key.secret_bytes())
    }
    
    // Génère la clé publique correspondante avec la vraie multiplication scalaire
    fn to_public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        
        // ✅ VRAIE multiplication scalaire : pubkey = privkey × G
        // Ceci effectue la vraie multiplication sur la courbe elliptique secp256k1
        let public_key = Secp256k1PublicKey::from_secret_key(&secp, &self.secret_key);
        
        PublicKey { public_key }
    }
    
    // Obtient les bytes bruts de la clé privée
    fn as_bytes(&self) -> [u8; 32] {
        self.secret_key.secret_bytes()
    }
}

impl PublicKey {
    // Convertit la clé publique en format hexadécimal (compressée)
    fn to_hex(&self) -> String {
        hex::encode(&self.public_key.serialize())
    }
    
    // Convertit la clé publique en format hexadécimal (non-compressée)
    fn to_hex_uncompressed(&self) -> String {
        hex::encode(&self.public_key.serialize_uncompressed())
    }
    
    // Génère l'adresse Bitcoin P2PKH (Legacy) correspondante
    fn to_address(&self) -> String {
        // Utiliser la clé publique compressée pour l'adresse
        let pubkey_bytes = self.public_key.serialize();
        
        // Étape 1: SHA256 de la clé publique compressée
        let sha256_hash = Sha256::digest(&pubkey_bytes);
        
        // Étape 2: RIPEMD160 du résultat SHA256
        let mut ripemd_hasher = Ripemd160::new();
        ripemd_hasher.update(&sha256_hash);
        let ripemd_hash = ripemd_hasher.finalize();
        
        // Étape 3: Ajouter le version byte (0x00 pour P2PKH mainnet)
        let mut extended_hash = Vec::new();
        extended_hash.push(0x00);
        extended_hash.extend_from_slice(&ripemd_hash);
        
        // Étape 4: Double SHA256 pour le checksum
        let hash1 = Sha256::digest(&extended_hash);
        let hash2 = Sha256::digest(&hash1);
        
        // Étape 5: Ajouter les 4 premiers bytes du checksum
        extended_hash.extend_from_slice(&hash2[0..4]);
        
        // Étape 6: Encoder en base58
        base58_encode(&extended_hash)
    }
    
    // Obtient les bytes de la clé publique compressée
    fn as_bytes(&self) -> [u8; 33] {
        self.public_key.serialize()
    }
    
    // Obtient les bytes de la clé publique non-compressée
    fn as_bytes_uncompressed(&self) -> [u8; 65] {
        self.public_key.serialize_uncompressed()
    }
}

impl BitcoinAddress {
    // Génère une nouvelle adresse Bitcoin complète avec vraie cryptographie
    fn generate() -> Self {
        let private_key = PrivateKey::generate();
        let public_key = private_key.to_public_key();
        let address = public_key.to_address();
        
        BitcoinAddress {
            private_key,
            public_key,
            address,
        }
    }
    
    // Génère une adresse contenant un mot spécifique
    fn generate_vanity(target: &str, case_sensitive: bool) -> (Self, u64) {
        let mut attempts = 0u64;
        
        loop {
            attempts += 1;
            let address = Self::generate();
            
            let contains_target = if case_sensitive {
                address.address.contains(target)
            } else {
                address.address.to_lowercase().contains(&target.to_lowercase())
            };
            
            if contains_target {
                return (address, attempts);
            }
            
            // Afficher le progrès toutes les 50000 tentatives
            if attempts % 50000 == 0 {
                println!("   ... {} tentatives effectuées", attempts);
            }
        }
    }
    
    // Génère une adresse commençant par un préfixe spécifique
    fn generate_prefix(prefix: &str, case_sensitive: bool) -> (Self, u64) {
        let mut attempts = 0u64;
        
        loop {
            attempts += 1;
            let address = Self::generate();
            
            let starts_with_prefix = if case_sensitive {
                address.address[1..].starts_with(prefix) // [1..] pour ignorer le '1' initial
            } else {
                address.address[1..].to_lowercase().starts_with(&prefix.to_lowercase())
            };
            
            if starts_with_prefix {
                return (address, attempts);
            }
            
            // Afficher le progrès toutes les 50000 tentatives
            if attempts % 50000 == 0 {
                println!("   ... {} tentatives effectuées", attempts);
            }
        }
    }
    
    // Affiche toutes les informations de l'adresse
    fn display(&self) {
        println!("=== Adresse Bitcoin générée ===");
        println!("Clé privée (HEX): {}", self.private_key.to_hex());
        println!("Clé privée (WIF): {}", self.private_key.to_wif());
        println!("Clé publique compressée (HEX): {}", self.public_key.to_hex());
        println!("Clé publique non-compressée (HEX): {}", self.public_key.to_hex_uncompressed());
        println!("Adresse Bitcoin: {}", self.address);
        println!("===============================");
    }
    
    // Affiche avec statistiques de génération
    fn display_with_stats(&self, attempts: u64, elapsed: std::time::Duration) {
        println!("=== Adresse Bitcoin Vanity générée ===");
        println!("Tentatives: {}", attempts);
        println!("Temps écoulé: {:?}", elapsed);
        println!("Vitesse: {:.2} adresses/sec", attempts as f64 / elapsed.as_secs_f64());
        println!("Clé privée (HEX): {}", self.private_key.to_hex());
        println!("Clé privée (WIF): {}", self.private_key.to_wif());
        println!("Clé publique compressée (HEX): {}", self.public_key.to_hex());
        println!("Adresse Bitcoin: {}", self.address);
        println!("=====================================");
    }
    
    // Vérifie la validité cryptographique de l'adresse
    fn verify_cryptographic_validity(&self) -> bool {
        // Vérifier que la clé publique correspond bien à la clé privée
        let secp = Secp256k1::new();
        let expected_pubkey = Secp256k1PublicKey::from_secret_key(&secp, &self.private_key.secret_key);
        
        // Vérifier que l'adresse correspond bien à la clé publique
        let expected_address = self.public_key.to_address();
        
        expected_pubkey == self.public_key.public_key && expected_address == self.address
    }
}

// Encodage Base58 avec gestion des grands nombres
fn base58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    // Compter les zéros en tête
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();
    
    // Utiliser un vecteur pour gérer les grands nombres
    let mut digits = vec![0u8];
    
    // Convertir byte par byte pour éviter l'overflow
    for &byte in data {
        let mut carry = byte as u32;
        
        for digit in digits.iter_mut() {
            carry += (*digit as u32) * 256;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    
    // Ajouter les '1' pour les zéros en tête
    let mut result = vec![ALPHABET[0]; leading_zeros];
    
    // Convertir les digits en caractères (en inversant l'ordre)
    for &digit in digits.iter().rev() {
        if digit != 0 || !result.is_empty() || leading_zeros == 0 {
            result.push(ALPHABET[digit as usize]);
        }
    }
    
    // Si le résultat est vide, retourner '1'
    if result.is_empty() {
        result.push(ALPHABET[0]);
    }
    
    String::from_utf8(result).unwrap()
}

fn main() {
    println!("█████   ███   █████   █████████   █████       █████   ███   █████   █████████   █████        ");
    println!("░░███   ░███  ░░███   ███░░░░░███ ░░███       ░░███   ░███  ░░███   ███░░░░░███ ░░███         ");
    println!(" ░███   ░███   ░███  ░███    ░███  ░███        ░███   ░███   ░███  ░███    ░███  ░███       ");
    println!(" ░███   ░███   ░███  ░███████████  ░███        ░███   ░███   ░███  ░███████████  ░███       ");
    println!(" ░░███  █████  ███   ░███░░░░░███  ░███        ░░███  █████  ███   ░███░░░░░███  ░███       ");
    println!("  ░░░█████░█████░    ░███    ░███  ░███      █  ░░░█████░█████░    ░███    ░███  ░███      █");
    println!("    ░░███ ░░███      █████   █████ ███████████    ░░███ ░░███      █████   █████ ███████████");
    println!("     ░░░   ░░░      ░░░░░   ░░░░░ ░░░░░░░░░░░      ░░░   ░░░      ░░░░░   ░░░░░ ░░░░░░░░░░░ ");
    println!("(c) 2025 Makertronic. All rights reserved.");
    println!("🚀 Générateur d'adresses Bitcoin Vanity avec VRAIE cryptographie ECDSA");
    println!("Version 1.0");
           
    // Exemple 1: Recherche d'adresses contenant des mots courts
    println!("📝 Recherche de mots courts dans l'adresse");
    let target_words = vec!["make", "maker", "nico", "ti"]; // Mots courts pour démonstration
    
    for word in target_words {
        println!("🔍 Recherche d'une adresse contenant '{}'...", word);
        let start_time = std::time::Instant::now();
        
        let (address, attempts) = BitcoinAddress::generate_vanity(word, false);
        let elapsed = start_time.elapsed();
        
        println!("✅ Trouvé après {} tentatives en {:?}!", attempts, elapsed);
        address.display_with_stats(attempts, elapsed);
        
        // Vérification cryptographique
        if address.verify_cryptographic_validity() {
            println!("✅ Adresse cryptographiquement valide!");
        } else {
            println!("❌ Erreur: Adresse invalide!");
        }
        println!();
    }
    
    // Exemple 2: Génération d'une adresse simple avec tous les détails
    println!("🎲 Mode 2: Génération d'une adresse complète");
    let address = BitcoinAddress::generate();
    address.display();
    
    // Informations techniques sur secp256k1
    println!("\n🔬 Informations techniques:");
    println!("- Courbe elliptique: secp256k1 (y² = x³ + 7)");
    println!("- Champ fini: p = 2²⁵⁶ - 2³² - 2⁹ - 2⁸ - 2⁷ - 2⁶ - 2⁴ - 1");
    println!("- Ordre: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    println!("- Point générateur G: coordonnées fixes sur la courbe");
    println!("- Multiplication scalaire: Clé_publique = clé_privée × G");
    println!("- Sécurité: Problème du logarithme discret elliptique");
    
    println!("\n⚠️  ATTENTION: Même avec de la vraie cryptographie, ces clés");
    println!("   sont à des fins de démonstration. Utilisez un générateur");
    println!("   audité et sécurisé pour de vrais Bitcoin!");
}