use bech32::{Bech32, Hrp};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

const MESH_NAME: &str = "podman-test";
const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Derive node_addr (16 bytes) from a mesh name and node name.
/// Returns (node_addr_bytes, x_only_pubkey_bytes).
fn derive_node_addr(
    secp: &Secp256k1<secp256k1::All>,
    mesh_name: &str,
    node_name: &str,
) -> ([u8; 16], [u8; 32]) {
    let nsec_bytes: [u8; 32] = Sha256::digest(format!("{mesh_name}|{node_name}")).into();
    let secret_key = SecretKey::from_slice(&nsec_bytes).expect("valid secret key");
    let keypair = Keypair::from_secret_key(secp, &secret_key);
    let (x_only_pubkey, _parity) = keypair.x_only_public_key();
    let pubkey_bytes = x_only_pubkey.serialize();

    let hash: [u8; 32] = Sha256::digest(pubkey_bytes).into();
    let mut node_addr = [0u8; 16];
    node_addr.copy_from_slice(&hash[..16]);

    (node_addr, pubkey_bytes)
}

/// Pretty-print a node's full details.
fn print_node(mesh_name: &str, node_name: &str, node_addr: &[u8; 16], pubkey_bytes: &[u8; 32]) {
    let hrp = Hrp::parse("npub").unwrap();
    let npub = bech32::encode::<Bech32>(hrp, pubkey_bytes).unwrap();

    println!("  node name: {node_name}");
    println!("  mesh:      {mesh_name}");
    println!("  npub:      {npub}");
    println!("  node_addr: {}", hex::encode(node_addr));
    println!();
}

/// Show existing nodes.
fn show_nodes() {
    let secp = Secp256k1::new();

    println!("=== Current nodes (mesh: {MESH_NAME}) ===");
    println!();
    for node in ["a", "b", "c"] {
        let (node_addr, pubkey_bytes) = derive_node_addr(&secp, MESH_NAME, node);
        print_node(MESH_NAME, node, &node_addr, &pubkey_bytes);
    }
}

/// Grind all rootXXXX suffixes (36^4 = 1,679,616 candidates) for smallest node_addr.
fn grind_root() {
    let secp = Secp256k1::new();
    let total = ALPHABET.len().pow(4);

    println!("=== Grinding rootXXXX ({total} candidates, mesh: {MESH_NAME}) ===");
    println!();

    let mut best_addr = [0xFFu8; 16];
    let mut best_name = String::new();
    let mut best_pubkey = [0u8; 32];
    let mut checked: usize = 0;

    for &a in ALPHABET {
        for &b in ALPHABET {
            for &c in ALPHABET {
                for &d in ALPHABET {
                    let chars = [a, b, c, d];
                    let suffix = std::str::from_utf8(&chars).unwrap();
                    let node_name = format!("root{suffix}");

                    let (node_addr, pubkey_bytes) = derive_node_addr(&secp, MESH_NAME, &node_name);
                    checked += 1;

                    if node_addr < best_addr {
                        best_addr = node_addr;
                        best_name = node_name;
                        best_pubkey = pubkey_bytes;

                        let hrp = Hrp::parse("npub").unwrap();
                        let npub = bech32::encode::<Bech32>(hrp, &pubkey_bytes).unwrap();
                        println!(
                            "  [{checked:>7}/{total}] new best: {:16}  node_addr={}  npub={npub}",
                            best_name,
                            hex::encode(&best_addr),
                        );
                    }
                }
            }
        }
    }

    println!();
    println!("=== Winner ===");
    println!();
    print_node(MESH_NAME, &best_name, &best_addr, &best_pubkey);
}

/// Grind random keypairs until we find an npub starting with the target prefix.
fn grind_vanity(prefix: &str) {
    let secp = Secp256k1::new();
    let hrp = Hrp::parse("npub").unwrap();
    let mut rng = rand::thread_rng();

    println!("=== Grinding vanity npub (target: {prefix}...) ===");
    println!();

    let mut checked: u64 = 0;
    let mut best_match_len: usize = 5; // "npub1" is always matched, start reporting from 6+

    loop {
        // Generate random keypair
        let (secret_key, _) = secp.generate_keypair(&mut rng);
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (x_only_pubkey, _parity) = keypair.x_only_public_key();
        let pubkey_bytes = x_only_pubkey.serialize();

        let npub = bech32::encode::<Bech32>(hrp, &pubkey_bytes).unwrap();
        checked += 1;

        // Check how many chars match the prefix
        let match_len = npub
            .chars()
            .zip(prefix.chars())
            .take_while(|(a, b)| a == b)
            .count();

        if match_len > best_match_len {
            best_match_len = match_len;
            let nsec_hex = hex::encode(secret_key.secret_bytes());
            println!(
                "  [{checked:>10}] matched {match_len}/{}: {:.40}...  nsec={}",
                prefix.len(),
                npub,
                &nsec_hex[..16],
            );
        }

        if npub.starts_with(prefix) {
            let nsec_hex = hex::encode(secret_key.secret_bytes());

            // Compute node_addr
            let hash: [u8; 32] = Sha256::digest(pubkey_bytes).into();
            let mut node_addr = [0u8; 16];
            node_addr.copy_from_slice(&hash[..16]);

            println!();
            println!("=== Found vanity npub! ===");
            println!();
            println!("  npub:      {npub}");
            println!("  nsec_hex:  {nsec_hex}");
            println!("  node_addr: {}", hex::encode(node_addr));
            println!();
            println!("  Use in config:");
            println!("    identity:");
            println!("      nsec: \"{nsec_hex}\"");
            println!();
            break;
        }

        if checked % 1_000_000 == 0 {
            println!("  ... {checked} keys checked");
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("show") => show_nodes(),
        Some("grind-root") => grind_root(),
        Some("grind-vanity") => {
            let prefix = args.get(2).map(|s| s.as_str()).unwrap_or("npub1mesh");
            grind_vanity(prefix);
        }
        _ => {
            eprintln!("Usage: keytool <command>");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  show                    Show current node keys");
            eprintln!("  grind-root              Grind for smallest node_addr (tree root)");
            eprintln!("  grind-vanity [prefix]   Grind for vanity npub (default: npub1mesh)");
        }
    }
}
