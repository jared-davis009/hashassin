use anyhow::{anyhow, Result};
use clap::Args;
use hashassin_core::HashGenerator;
use std::{
    fs::File,
    io::{self, prelude::*, BufReader, Stdout, Write},
    num::NonZeroUsize,
    path::PathBuf,
    thread,
};
use tracing::{debug, info, trace};
enum Writer {
    /// Write to file
    File(File),
    /// Write to stdout
    Stdout(Stdout),
}

/// Options for hash generation
#[derive(Args, Debug)]
pub(crate) struct HashesOpts {
    /// This is the path to read the plaintext passwords

    #[clap(long)]
    pub in_path: String,

    /// This is the path to run output the hashes, will default to stdout

    #[clap(long)]
    out_path: Option<PathBuf>,

    /// This is the number of threads to use to generate the hashes

    #[clap(long, default_value = "1")]
    pub threads: NonZeroUsize,

    /// This is the algorithm to use to generate the hashes

    #[clap(long, default_value = "Md5")]
    pub algorithm: String,
}

/// This function calls hash functions from lib.rs
/// Will also distribute work as evenly as possible among threads
pub(crate) fn gen_hashes(opts: HashesOpts) -> Result<()> {
    trace!("Gen Hashes");
    let input_file = File::open(opts.in_path)?;

    let mut output_file: Writer = match opts.out_path {
        Some(out_path) => {
            let file = File::create(out_path)?;
            Writer::File(file)
        }
        None => Writer::Stdout(io::stdout()),
    };
    let reader = BufReader::new(input_file);
    let (tx_main, rx_main) = crossbeam_channel::unbounded();
    // used to print
    // multi producers (password_gen), single consumer (printer)
    let (tx_printer, rx_printer) = std::sync::mpsc::channel();

    let mut threads = vec![];

    // Main thread loops 0..num_to_gen, sending to generator threads
    for passwords in reader.lines() {
        tx_main.send(passwords)?;
    }
    debug!("Main thread done");
    drop(tx_main);

    for thread_number in 0..opts.threads.into() {
        let rx_main = rx_main.clone();
        let tx_printer = tx_printer.clone();
        let algorithm = opts.algorithm.clone();
        let thread = thread::spawn(move || -> Result<()> {
            // loop while main thread is still sending
            while let Ok(password) = rx_main.recv() {
                let hash_generator = HashGenerator::new(password?, algorithm.clone());
                let hashed_password = match hash_generator.hash_password() {
                    Ok(password) => password,
                    Err(error) => panic!("Error: {error}"),
                };
                print!("{:?}", hashed_password);

                tx_printer.send(hashed_password)?;
            }
            Ok(())
        });

        debug!("Thread {thread_number} done");

        threads.push(thread);
    }

    info!("Hashes done generating");

    drop(rx_main);
    drop(tx_printer);

    let printer_thread = thread::spawn(move || -> Result<()> {
        while let Ok(password_result) = rx_printer.recv() {
            match output_file {
                Writer::File(ref mut to_write) => {
                    //write!(to_write, "{:?}", &password);
                    //for element in &password {
                    //    write!(to_write, "{}", element)?
                    //}
                    //write!(to_write, "{}", password_result)?;
                    to_write.write_all(&password_result)?;
                }

                Writer::Stdout(ref mut _to_write) => {
                    // for element in &password {
                    //     write!(to_write, "{}", element)?
                    // }
                    //write!(to_write, "{}", password_result)?;
                }
            };
        }

        drop(rx_printer);

        Ok(())
    });

    debug!("Printer thread done");

    threads.push(printer_thread);

    for thread in threads {
        thread
            .join()
            .map_err(|_e| anyhow!("Failed to join a thread"))??;
    }

    debug!("All threads joined");

    Ok(())
}
