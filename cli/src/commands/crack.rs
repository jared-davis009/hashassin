use anyhow::{anyhow, Result};
use clap::Args;
use hashassin_core::Crack;

use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, BufReader, Read, Stdout, Write},
    num::NonZeroUsize,
    path::PathBuf,
    thread,
};
use tracing::{debug, info};

/// Options for password generation
#[derive(Args, Debug)]
pub(crate) struct CrackOpts {
    // Number of links in each chain
    #[clap(long, default_value = "5")]
    num_links: NonZeroUsize,

    // Threads used to generate rainbow table
    #[clap(long, default_value = "1")]
    threads: NonZeroUsize,

    // output path for rainbow table
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
    // Input path to rainbow table
    #[clap(long)]
    rainbow_path: PathBuf,
}
/// Output destination
enum Writer {
    /// Write to file
    File(File),
    /// Write to stdout
    Stdout(Stdout),
}

pub(crate) fn do_cracks(opts: CrackOpts) -> Result<()> {
    let mut rainbow_table = HashMap::new();
    let rainbow_file = File::open(opts.rainbow_path)?;
    let reader = BufReader::new(rainbow_file);
    for line in reader.lines() {
        match line {
            Ok(line) => {
                if let Some(tab_index) = line.find('\t') {
                    let (before_tab, after_tab) = line.split_at(tab_index);
                    let after_tab = &after_tab[1..];
                    rainbow_table.insert(after_tab.to_string(), before_tab.to_string());
                } else {
                    panic!("No tab character found in line: {}", line);
                }
            }
            Err(_err) => {
                panic!("Error reading line");
            }
        }
    }

    let mut input_file = File::open(opts.in_path)?;
    let mut first_line = Vec::new();
    let _ = input_file.read_to_end(&mut first_line);
    //let mut first_line = [0_u8; 16];
    //first_line[..16].copy_from_slice(&&first_line_step[..16]);
    println!("{:?}", first_line);
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

    // let mut first_line = String::new();
    for number in reader.lines() {
        let _number = number?;
    }
    let num_to_gen = first_line.len() / 16;
    // Main thread loops 0..num_to_gen, sending to generator threads
    // let i = 0;firs
    for i in 0..num_to_gen {
        let chunk = &first_line[i * 16..(i + 1) * 16];
        //let hashed_bytes = <[u8; 16]>::from_hex(chunk)?;
        let hashed_bytes: [u8; 16] = chunk.try_into()?;
        let _ = tx_main.send(hashed_bytes);
    }
    debug!("Main thread done");
    drop(tx_main);

    for thread_number in 0..opts.threads.into() {
        let rx_main = rx_main.clone();
        let tx_printer = tx_printer.clone();
        let algorithm = opts.algorithm.clone();
        let rainbow_table_clone = rainbow_table.clone();
        let thread = thread::spawn(move || -> Result<()> {
            // loop while main thread is still sending
            let cracker = Crack::new(
                opts.num_links,
                opts.password_length,
                algorithm,
                rainbow_table_clone,
            );
            while let Ok(password) = rx_main.recv() {
                let hashed = match cracker.crack(&password) {
                    Ok(password) => password,
                    Err(error) => error.to_string(),
                };

                tx_printer.send(hashed)?;
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
                    write!(to_write, "{}", password_result)?;
                }

                Writer::Stdout(ref mut to_write) => {
                    // for element in &password {
                    //     write!(to_write, "{}", element)?
                    // }
                    write!(to_write, "{}", password_result)?;
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
    // create rainbow table struct (num_links, pass_len, algo)
    // gen rainbow table
    // main thread gives lines to worker threads
    // worker thread gives line to printer thread
}
