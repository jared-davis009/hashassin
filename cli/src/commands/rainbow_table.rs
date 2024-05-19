use anyhow::{anyhow, Result};
use clap::Args;
use hashassin_core::RainbowTable;

use std::{
    borrow::BorrowMut,
    fs::File,
    io::{self, BufRead, BufReader, Stdout, Write},
    num::NonZeroUsize,
    path::{PathBuf},
    thread,
};
use tracing::{debug, info, trace};



/// Options for password generation
#[derive(Args, Debug)]
pub(crate) struct RainbowOpts {
    // Number of links in each chain
    #[clap(long, default_value = "5")]
    num_links: NonZeroUsize,

    // Threads used to generate rainbow table
    #[clap(long)]
    threads: NonZeroUsize,

    // Output path for rainbow table
    #[clap(long)]
    out_path: Option<PathBuf>,

    // Length of passwords for rainbow table
    #[clap(long, default_value = "4")]
    password_length: NonZeroUsize,

    // Hashing algorithm used
    #[clap(long, default_value = "Md5")]
    algorithm: String,

    // Input path to passwords
    #[clap(long)]
    in_path: PathBuf,
}

/// Output destination
enum Writer {
    /// Write to file
    File(File),
    /// Write to stdout
    Stdout(Stdout),
}

pub(crate) fn do_rainbow(opts: RainbowOpts) -> Result<()> {
    let rainbow_table = RainbowTable::new(opts.num_links, opts.password_length, opts.algorithm);

    let mut out_file: Writer = match opts.out_path {
        Some(out_path) => {
            let file = File::create(out_path)?;
            Writer::File(file)
        }
        None => Writer::Stdout(io::stdout()),
    };

    let input_file = File::open(opts.in_path)?;
    let reader = BufReader::new(input_file);

    let _chain_file = File::create("data/chain_file.txt")?;

    // One prod, multi cons
    // Transmit passwords
    let (tx_main, rx_main) = crossbeam_channel::unbounded();

    // Send chain to print
    let (tx_printer, rx_printer) = std::sync::mpsc::channel();

    let mut threads = vec![];

    // Main tread loops throuhg input file, sending passwords
    for passwords in reader.lines() {
        tx_main.send(passwords)?;
    }
    trace!("Main thread done");
    drop(tx_main);

    //Start worker threads
    for thread_number in 0..opts.threads.into() {
        let rx_main = rx_main.clone();
        let tx_printer = tx_printer.clone();
        let rainbow_table = rainbow_table.clone();
        let thread = thread::spawn(move || -> Result<()> {
            while let Ok(password) = rx_main.recv() {
                let chain = rainbow_table.clone().generate_chain(password?);
                tx_printer.send(chain)?;
            }
            Ok(())
        });
        trace!("Thread {thread_number} done");
        threads.push(thread);
    }

    info!("All chains generated");

    drop(rx_main);
    drop(tx_printer);

    let printer_thread = thread::spawn(move || -> Result<()> {
        while let Ok(chain_result) = rx_printer.recv() {
            match chain_result {
                Ok(chain) => match out_file.borrow_mut() {
                    Writer::File(to_write) => writeln!(to_write, "{chain}")?,
                    Writer::Stdout(to_write) => writeln!(to_write, "{chain}")?,
                },
                Err(error) => panic!("Error: {error}"),
            };
        }

        drop(rx_printer);

        Ok(())
    });

    trace!("Printer thread done");

    threads.push(printer_thread);
    debug!("All threads joined");

    for thread in threads {
        thread
            .join()
            .map_err(|_e| anyhow!("Failed to join a thread"))??;
    }

    Ok(())
    // create rainbow table struct (num_links, pass_len, algo)
    // gen rainbow table
    // main thread gives lines to worker threads
    // worker thread gives line to printer thread
}
