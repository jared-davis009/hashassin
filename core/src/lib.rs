#![deny(clippy::unwrap_used, clippy::expect_used)]

use ::num::{Integer, ToPrimitive}; //LOOK INTO
use anyhow::Error;

use hex::encode;
use md5::{Digest, Md5};
use rand::prelude::*;

use std::collections::HashMap;

use std::{fs::OpenOptions, io::Write, num::NonZeroUsize};

use thiserror::Error;
use tracing::{error, trace};
/// Builder for password generator
#[derive(Default, Debug)]
pub struct PasswordGeneratorBuilder {
    /// Min chars for password
    min_char: Option<NonZeroUsize>,
    /// Max chars for password
    max_char: Option<NonZeroUsize>,
}

/// Implements builder for password generator
impl PasswordGeneratorBuilder {
    /// Set the minimum number of characters in the password
    pub fn with_min_char(self, min_char: Option<NonZeroUsize>) -> Self {
        trace!("With min char");
        Self {
            min_char,
            max_char: self.max_char,
        }
    }

    /// Set the maximum number of characters in the password
    pub fn with_max_char(self, max_char: Option<NonZeroUsize>) -> Self {
        trace!("With max char");
        Self {
            min_char: self.min_char,
            max_char,
        }
    }

    /// Build a PasswordGenerator
    pub fn build(self) -> std::result::Result<PasswordGenerator, PasswordGeneratorError> {
        trace!("Build");
        let password_generator = PasswordGenerator {
            min_char: match self.min_char {
                Some(min_char) => min_char.into(),
                None => PasswordGenerator::default().min_char,
            },

            max_char: match self.max_char {
                Some(max_char) => max_char.into(),
                None => PasswordGenerator::default().max_char,
            },
        };
        if self.min_char > self.max_char {
            error!("MinMax error");
            return Err(PasswordGeneratorError::MinMax {
                min: password_generator.min_char,
                max: password_generator.max_char,
            });
        }
        Ok(password_generator)
    }
}

/// Used to generate passwords
#[derive(Clone, Copy)]
pub struct PasswordGenerator {
    /// Min length of password
    min_char: usize,
    /// Max length of password
    max_char: usize,
}

/// Default for password generator
impl Default for PasswordGenerator {
    /// Min and max chars default to 4
    fn default() -> Self {
        Self {
            min_char: 4,
            max_char: 4,
        }
    }
}

/// Implement password generator
impl PasswordGenerator {
    /// Generates a password between min_char and max_char, containing valid ASCII (including punctation and spaces)
    pub fn generate(self) -> String {
        trace!("Generate");
        let mut rng = thread_rng();

        // Randomly generates the size of the password
        let length: usize = rng.gen_range(self.min_char..=self.max_char);

        // Creates the password as a vector
        // From 0..length generates a value between 32..=126 (all valid ASCII), converts it to a char, collects it into the vector
        let password_vec: Vec<char> = (0..length)
            .map(|_| rng.gen_range(32_u8..=126_u8) as char)
            .collect();

        // Converts password as a vector into a string
        password_vec.into_iter().collect()
    }
}

/// Errors for password generations
#[derive(Error, Debug)]
pub enum PasswordGeneratorError {
    #[error("Min length {min} must be less or equal to max length {max}")]
    MinMax { min: usize, max: usize },
}

/// Struct for my hash generator
pub struct HashGenerator {
    pub password: String,
    pub hash_algorithm: String,
}
/// implements hash generator
impl HashGenerator {
    pub fn new(password: String, hash_algorithm: String) -> Self {
        trace!("New hash generator");
        HashGenerator {
            password,
            hash_algorithm,
        }
    }

    /// function that hashes password with algorithms that have the digest and default trait
    fn simple_hash<T>(&self) -> Result<[u8; 16], HashErrors>
    where
        T: Digest + Default,
    {
        let pass = self.password.clone();

        let mut hasher = T::default();

        hasher.update(pass.as_bytes());

        let hash_bytes = hasher.finalize();
        let hash_bytes = hash_bytes.to_vec();

        let mut ret = [0_u8; 16];
        ret[..16].copy_from_slice(&hash_bytes[..16]);

        Ok(ret)
    }
    /// Function that pattern matches on the algorithm to call the right function
    /// Will return an error if the specified algorithm doesnt exist
    pub fn hash_password(&self) -> Result<[u8; 16], HashErrors> {
        trace!("Hash password");
        match self.hash_algorithm.as_str() {
            "Md5" => self.simple_hash::<Md5>(),
            /*
            "Sha2_256" => self.simple_hash::<sha2::Sha256>(),
            "Sha2_512" => self.simple_hash::<sha2::Sha512>(),
            "Sha1" => self.simple_hash::<Sha1>(),
            "Sha3_256" => self.simple_hash::<sha3::Sha3_256>(),
            "Sha3_224" => self.simple_hash::<sha3::Sha3_224>(),
            "Shabal256" => self.simple_hash::<shabal::Shabal256>(),
            "Shabal224" => self.simple_hash::<shabal::Shabal224>(),
            "Shabal192" => self.simple_hash::<shabal::Shabal192>(),
            "Shabal512" => self.simple_hash::<shabal::Shabal512>(),
            "Shabal384" => self.simple_hash::<shabal::Shabal384>(),
            "Ascon2" => self.simple_hash::<ascon_hash::AsconHash>(),
            "Sm3" => self.simple_hash::<sm3::Sm3>(),
            "Ripemd128" => self.simple_hash::<ripemd::Ripemd128>(),
            "Ripemd256" => self.simple_hash::<ripemd::Ripemd256>(),
            "Ripemd320" => self.simple_hash::<ripemd::Ripemd320>(),
            "Fsb160" => self.simple_hash::<fsb::Fsb160>(),
            "Fsb224" => self.simple_hash::<fsb::Fsb224>(),
            "Fsb256" => self.simple_hash::<fsb::Fsb256>(),
            "Fsb512" => self.simple_hash::<fsb::Fsb512>(),
            "Fsb384" => self.simple_hash::<fsb::Fsb384>(),
            "Jh224" => self.simple_hash::<jh::Jh224>(),
            "Jh256" => self.simple_hash::<jh::Jh256>(),
            "Jh384" => self.simple_hash::<jh::Jh384>(),
            "Jh512" => self.simple_hash::<jh::Jh512>(),
            "Tiger" => self.simple_hash::<tiger::Tiger>(),
            "Tiger2" => self.simple_hash::<tiger::Tiger2>(),
            "BeltHash" => self.simple_hash::<belt_hash::BeltHash>(),
            "Streebog256" => self.simple_hash::<streebog::Streebog256>(),
            "Streebog512" => self.simple_hash::<streebog::Streebog512>(),
            "Md4" => self.simple_hash::<md4::Md4>(),
            "Groestl224" => self.simple_hash::<groestl::Groestl224>(),
            "Groestl256" => self.simple_hash::<groestl::Groestl256>(),
            "Groestl384" => self.simple_hash::<groestl::Groestl384>(),
            "Groestl512" => self.simple_hash::<groestl::Groestl512>(),
            "Gost94" => self.simple_hash::<gost94::Gost94UA>(),
            */
            _ => {
                error!("Unsupported Algo");
                Err(HashErrors::UnsupportedAlgorithm)
            }
        }
    }
}

/// Errors for hash generation
#[derive(Error, Debug)]
pub enum HashErrors {
    #[error("Error with Argon2 Hashing")]
    Argon2Error,
    #[error("Unsupported hash algorithm")]
    UnsupportedAlgorithm,
    #[error("Hash not Present in Rainbow Table\n")]
    NotInRainbowTable,
}
// ----------------------------------------------------------------------------------
// Crack
// ----------------------------------------------------------------------------------
pub struct Crack {
    // Number of links in chain
    num_links: NonZeroUsize,
    // Length of each password
    password_length: NonZeroUsize,
    // Hashing algorithm
    algorithm: String,

    rainbow_table: HashMap<String, String>,
}
impl Crack {
    pub fn new(
        num_links: NonZeroUsize,
        password_length: NonZeroUsize,
        algorithm: String,
        rainbow_table: HashMap<String, String>,
    ) -> Self {
        Crack {
            num_links,
            password_length,
            algorithm,
            rainbow_table,
        }
    }

    pub fn helper(&self, final_link_number: usize, first_pass: String) -> Result<String, Error> {
        // num links = 2 (2 reductions): string h-> hash r-> string h-> hash r-> string
        let mut password = first_pass;
        let mut hash = [0_u8; 16];
        let radix: u8 = 126_u8 - 32_u8;
        let password_length: usize = self.password_length.into();
        //let final_link_number = final_link_number;
        for link_number in 0..final_link_number {
            trace!("{} hashing", link_number);
            let hash_generator = HashGenerator {
                password: password.clone(),
                hash_algorithm: self.algorithm.clone(),
            };
            hash = hash_generator.hash_password()?;

            trace!("{} reduce", link_number);
            password = reduction(&hash, link_number as u128, radix, password_length as u32);
        }

        Ok(password)
    }

    pub fn crack(&self, hash: &[u8; 16]) -> Result<String, Error> {
        //let mut hash_clone = hash.clone();
        let radix: u8 = 126 - 32;
        //let mut link_number: usize = 0;
        let password_length: usize = self.password_length.into();
        //let mut link_number_clone = link_number.clone();

        for link_number in 0..self.num_links.into() {
            let mut hash_clone = *hash;

            let mut link_number_clone = link_number;

            while link_number_clone < self.num_links.into() {
                let pass = reduction(
                    &hash_clone,
                    link_number_clone as u128,
                    radix,
                    password_length as u32,
                );
                if self.rainbow_table.contains_key(&pass) {
                    println!("test1");
                    let hashed_pass =
                        self.helper(link_number, self.rainbow_table[&pass].clone())?;
                    return Ok(format!("{}\t{}\n", encode(hash), hashed_pass));
                    //return Ok(format!("{}\t{}\n", encode(hash), self.rainbow_table[&pass]));
                } else {
                    let hash_generator = HashGenerator {
                        password: pass.clone(),
                        hash_algorithm: self.algorithm.clone(),
                    };
                    hash_clone = hash_generator.hash_password()?;
                }
                link_number_clone += 1;
            }
            //error!("Hash Not Present in RainbowTable");
        }
        Err(HashErrors::NotInRainbowTable.into())
        // Err(HashErrors::NotInRainbowTable)
    }
}

// ----------------------------------------------------------------------------------
// RAINBOW TABLE
// ----------------------------------------------------------------------------------

/// Struct to create rainbow table
#[derive(Clone)]
pub struct RainbowTable {
    // Number of links in chain
    num_links: NonZeroUsize,
    // Length of each password
    password_length: NonZeroUsize,
    // Hashing algorithm
    algorithm: String,
}

/// Struct for each rainbow table chain
pub struct Chain {
    // Beginning of chain
    first_pass: String,
    // End of chain
    last_pass: String,
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!("{0}\t{1}", self.first_pass, self.last_pass);
        write!(f, "{s}")
    }
}

impl Chain {
    pub fn new(first_pass: String, last_pass: String) -> Self {
        Chain {
            first_pass,
            last_pass,
        }
    }
}

/// Implements rainbow table
impl RainbowTable {
    pub fn new(num_links: NonZeroUsize, password_length: NonZeroUsize, algorithm: String) -> Self {
        RainbowTable {
            num_links,
            password_length,
            algorithm,
        }
    }

    /// Generate a chain for a rainbow table and return a vec of bytes
    pub fn generate_chain(self, mut password: String) -> Result<Chain, Error> {
        // num links = 2 (2 reductions): string h-> hash r-> string h-> hash r-> string
        let first_pass = password.clone();
        let mut hash = [0_u8; 16];
        let radix: u8 = 126_u8 - 32_u8;
        let password_length: usize = self.password_length.into();
        let mut chain_file = match OpenOptions::new()
            .write(true)
            .append(true)
            .open("data/chain_file.txt")
        {
            Ok(file) => file,
            Err(_) => todo!(),
        };
        write!(chain_file, "Chain: ")?;
        for link_number in 0..self.num_links.into() {
            write!(chain_file, "{password}")?;
            write!(chain_file, "|hash->")?;
            trace!("{} hashing", link_number);
            let hash_generator = HashGenerator {
                password: password.clone(),
                hash_algorithm: self.algorithm.clone(),
            };
            hash = hash_generator.hash_password()?;

            chain_file.write_all(&hash)?;
            write!(chain_file, "|reduce->")?;
            trace!("{} reduce", link_number);
            password = reduction(&hash, link_number as u128, radix, password_length as u32);
        }

        write!(chain_file, "{password}")?;
        writeln!(chain_file, "\n\n")?;

        //debug!("{full_chain}");

        Ok(Chain {
            first_pass,
            last_pass: password,
        })
    }
}

pub fn reduction(hash: &[u8; 16], link_number: u128, radix: u8, password_length: u32) -> String {
    // (h + k) mod (keyspace)
    // h = password hash as number
    // k = the number in the chain
    // keyspace is number of possible passwords
    let password_num: u128 = u128::from_ne_bytes(*hash);
    let password_num = password_num + link_number;

    trace!("pre ^");
    trace!("Radix: {radix} Password length: {password_length}");
    // Ex: 8 lowercase char = 26^8
    let radix = radix as u128;
    let keyspace = radix.pow(password_length);
    //let keyspace: u128 = radix.pow(password_length).into();
    //let keyspace: u128 = pow(radix.into(), password_length);

    trace!("pre %");
    // the reduced password
    let password_num = password_num % keyspace;

    // encode the numeric value to a valid password
    encoder(password_num, radix as u8)
    // = hash + link_number
}

fn encoder(mut num: u128, radix: u8) -> String {
    let mut ret = String::new();

    while num > 0 {
        let (div, rem) = num.div_rem(&radix.into());

        num = div;
        let rem_u8 = match rem.to_u8() {
            Some(rem) => rem,
            None => todo!(),
        };
        let c: char = (rem_u8 + 97_u8).into();
        ret.push(c);
    }
    ret
}
