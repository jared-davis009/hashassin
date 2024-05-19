use anyhow::{anyhow, Result};
use clap::Args;

use hashassin_core::PasswordGeneratorBuilder;
use std::{
    borrow::BorrowMut,
    fs::File,
    io::{self, Stdout, Write},
    num::NonZeroUsize,
    path::PathBuf,
    thread,
};
use tracing::{debug, info, trace};

/// Options for password generation
#[derive(Args, Debug)]
pub(crate) struct PasswordsOpts {
    /// This is the minimum number of characters for the password
    #[clap(long)]
    min_char: Option<NonZeroUsize>,

    /// This is the maximum number of characters for the password
    #[clap(long)]
    max_char: Option<NonZeroUsize>, //fix to enforce greater than min

    /// This the outpath of the file containing the passwords
    #[clap(long)]
    out_path: Option<PathBuf>,

    /// This is the number of threads used
    #[clap(long, default_value = "1")]
    threads: NonZeroUsize,

    /// This is the number of passwords to generate
    #[clap(long)]
    num_to_gen: NonZeroUsize,
}

/// Output destination
enum Writer {
    /// Write to file
    File(File),
    /// Write to stdout
    Stdout(Stdout),
}

/// This function calls password functions from lib.rs
/// Will also distribute work as evenly as possible among threads
pub(crate) fn do_passwords(opts: PasswordsOpts) -> Result<()> {
    trace!("Do passwords");
    // Ensure that maximum possible length >= minimum possible length
    let password_generator = PasswordGeneratorBuilder::default()
        .with_min_char(opts.min_char)
        .with_max_char(opts.max_char)
        .build();

    let password_generator = match password_generator {
        Ok(password_generator) => password_generator,
        Err(error) => panic!("Error: {error}"),
    };
    let _password = password_generator.generate();

    // This is standard functionallity
    let mut out_file: Writer = match opts.out_path {
        Some(out_path) => {
            let file = File::create(out_path)?;
            Writer::File(file)
        }
        None => Writer::Stdout(io::stdout()),
    };

    // (transmitter, receiver)
    // single producer, multi consumer
    let (tx_main, rx_main) = crossbeam_channel::unbounded();
    // used to print
    // multi producers (password_gen), single consumer (printer)
    let (tx_printer, rx_printer) = std::sync::mpsc::channel();

    let mut threads = vec![];

    // Main thread loops 0..num_to_gen, sending to generator threads
    for password_number in 0..opts.num_to_gen.into() {
        tx_main.send(password_number)?;
    }
    drop(tx_main);
    debug!("Main thread done");

    for thread_number in 0..opts.threads.into() {
        let rx_main = rx_main.clone();
        let tx_printer = tx_printer.clone();
        let thread = thread::spawn(move || -> Result<()> {
            // loop while main thread is still sending
            while let Ok(_password_number) = rx_main.recv() {
                tx_printer.send(password_generator.generate())?;
            }
            Ok(())
        });

        threads.push(thread);
        debug!("Thread: {thread_number} done");
    }
    info!("Done generating passwords");

    drop(rx_main);
    drop(tx_printer);
    let printer_thread = thread::spawn(move || -> Result<()> {
        while let Ok(password) = rx_printer.recv() {
            match out_file.borrow_mut() {
                Writer::File(to_write) => writeln!(to_write, "{password}")?,
                Writer::Stdout(to_write) => writeln!(to_write, "{password}")?,
            };
        }

        drop(rx_printer);
        debug!("Printer thread done");

        Ok(())
    });

    threads.push(printer_thread);

    for thread in threads {
        thread
            .join()
            .map_err(|_e| anyhow!("Failed to join a thread"))??;
    }

    debug! {"All threads joined"};

    Ok(())
}
