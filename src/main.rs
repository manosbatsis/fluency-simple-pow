use sha2::{Digest, Sha256};

/// Simple holder of calculation results
#[derive(Debug, PartialEq)]
struct HashAndPrefix {
    hash: String,
    prefix: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let input_string = &args[1];

    let r = pow(input_string).unwrap();

    println!("{}\n{}", r.hash, r.prefix);
}

/// Perform a brute force search from 0,0,0,0 to 255,255,255,255
fn pow(input_string: &String) -> Option<HashAndPrefix> {
    let input_as_bytes = &hex::decode(input_string).unwrap()[..];

    for b1 in 0..256 {
        for b2 in 0..256 {
            for b3 in 0..256 {
                for b4 in 0..256 {
                    let r = pow_with_prefix(
                        input_as_bytes,
                        &vec![b1 as u8, b2 as u8, b3 as u8, b4 as u8][..],
                    );
                    match r {
                        Some(_) => return r,
                        None => continue,
                    }
                }
            }
        }
    }

    None
}

/// Maybe get a HashAndPrefix matching the last two bytes
fn pow_with_prefix(input: &[u8], prefix: &[u8]) -> Option<HashAndPrefix> {
    let mut hasher = Sha256::new_with_prefix(prefix);
    hasher.update(input);

    let res = &hasher.finalize()[..];
    let second_last_byte = &res[&res.len() - 2];
    let last_byte = &res[&res.len() - 1];

    // ca = 202, fe = 254
    if *second_last_byte == 202 && *last_byte == 254 {
        return Some(HashAndPrefix {
            hash: hex::encode(res),
            prefix: hex::encode(prefix),
        });
    }

    None
}

#[cfg(test)]
mod test {
    use super::*;

    const INPUT_EXAMPLE: &str = "129df964b701d0b8e72fe7224cc71643cf8e000d122e72f742747708f5e3bb6294c619604e52dcd8f5446da7e9ff7459d1d3cefbcc231dd4c02730a22af9880c";
    const EXPECTED_HASH: &str = "6681edd1d36af256c615bf6dcfcda03c282c3e0871bd75564458d77c529dcafe";
    const EXPECTED_PREFIX: &str = "00003997";

    #[test]
    fn input_from_example() {
        let r = pow(&INPUT_EXAMPLE.to_string());
        let expected_result = HashAndPrefix {
            hash: EXPECTED_HASH.to_string(),
            prefix: EXPECTED_PREFIX.to_string(),
        };
        assert_eq!(r, Some(expected_result));
    }

    #[test]
    fn wrong_input() {
        let r = pow(&INPUT_EXAMPLE.replacen("1", "2", 1).to_string());
        let expected_result = HashAndPrefix {
            hash: EXPECTED_HASH.to_string(),
            prefix: EXPECTED_PREFIX.to_string(),
        };
        assert_ne!(r, Some(expected_result));
    }

    #[test]
    #[should_panic]
    fn incorrect_input_should_panic() {
        //changed second char from 2 to 1
        let r = pow(&"s".to_string());
        let expected_result = HashAndPrefix {
            hash: EXPECTED_HASH.to_string(),
            prefix: EXPECTED_PREFIX.to_string(),
        };
        assert_ne!(r, Some(expected_result));
    }
}
