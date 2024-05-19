use anyhow::Result;
use clap::Args;

use tokio::io::AsyncReadExt;

use tokio::net::TcpListener;
// use std::io::BufRead;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use hex;
use tokio::net::TcpStream;
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::Sender;
// use std::{io::BufReader};
use tracing::{debug, info};

#[derive(Args, Debug, Clone)]
pub(crate) struct ServerOpts {
    /// Port number
    #[clap(long, default_value = "4515")]
    port: u16, // check to see if we will error on port 0.

    /// The ip address to bind to
    #[clap(long, default_value = "127.0.0.1")]
    ip_address: std::net::IpAddr, // check this?
                                  // could have a protocol type too
    // Number of links in each chain
    #[clap(long, default_value = "5")]
    num_links: NonZeroUsize,
    
    // Threads used to generate rainbow table
    #[clap(long, default_value = "1")]
    threads: NonZeroUsize,
    
    // Length of passwords for rainbow table
    #[clap(long, default_value = "4")]
    password_length: NonZeroUsize,

    // Hashing algorithm used
    #[clap(long, default_value = "Md5")]
    algorithm: String,
    // Input path to rainbow table
    #[clap(long)]
    rainbow_path: PathBuf,

}

pub struct Server {
    listener: TcpListener, // we want to listen for connections from clients
    broadcast_sender: Sender<(SocketAddr, String)>, // how to send messages to all connectd clients
}

impl Server {
    pub async fn new(ip_address: IpAddr, port: u16) -> Self {
        // create a listener
        // let listener = TcpListener::bind((ip_address, port)).await.unwrap();

        let listener = match TcpListener::bind((ip_address, port)).await {
            Ok(listener) => listener,
            Err(err) => panic!("Error accepting connection: {:?}", err),
        };
        let (broadcast_sender, _broadcast_receiver) = tokio::sync::broadcast::channel(100);

        Self {
            listener,
            broadcast_sender,
        }
    }

    /// this method starts accepting connections to the server
    pub async fn listen(&self) {
        info!("listening on {:?}", self.listener.local_addr());

        // accept connections!
        loop {
            //let (stream, remote_addr) = self.listener.accept().await.unwrap();
            let (stream, remote_addr) = match self.listener.accept().await {
                Ok((stream, remote_addr)) => (stream, remote_addr),
                Err(err) => panic!("Error accepting connection: {:?}", err),
                //fake
            };

            // we want to wait for an incoming connection and then do something with it
            info!("connection established from {remote_addr}");
            let conn = Connection::new(
                stream,
                remote_addr,
                self.broadcast_sender.clone(),
                self.broadcast_sender.subscribe(),
            )
            .await;
            info!("connection2 established from {remote_addr}");
            tokio::task::spawn(async move {
                handle_connection(conn).await;
            });
        }
    }
}

struct Connection {
    stream: TcpStream,                     // the stream we are talking to client over
    addr: SocketAddr,                      // the remote connections address
    broadcast_sender: BroadcastSender,     // send to other connections
    broadcast_receiver: BroadcastReceiver, // receive from other connections
}

type BroadcastSender = Sender<(SocketAddr, String)>;
type BroadcastReceiver = Receiver<(SocketAddr, String)>;

impl Connection {
    async fn new(
        stream: TcpStream,
        addr: SocketAddr,
        broadcast_sender: BroadcastSender,
        broadcast_receiver: BroadcastReceiver,
    ) -> Connection {
        Self {
            stream,
            addr,
            broadcast_sender,
            broadcast_receiver,
        }
    }

    /// say something
    async fn say(&self, msg: &str) {
        // broadcast the msg.
        /*self.broadcast_sender
        .send((self.addr, msg.to_owned()))
        .unwrap();*/
        match self.broadcast_sender.send((self.addr, msg.to_owned())) {
            Ok(_) => print!("Message Sent Successfully"),
            Err(_) => panic!("Messsage Sent Unsucsessfully"),
        }
    }
}

async fn do_stuff_async() {
    //
}

async fn do_more_stuff() {
    // whatever
}

async fn test_stuff() {
    loop {
        tokio::select! {
            _x = do_stuff_async() => {
                println!("async stuff")
                
            }
            _y = do_more_stuff() => {
                println!("do more async stuff")
            }
        }
    }
}

/// Set up a socket and listen on it.
pub(crate) async fn server(opts: ServerOpts) -> Result<()> {
    debug!("I'm running server()");

    let server = Server::new(opts.ip_address, opts.port).await;
    info!("waiting for connection!");

    server.listen().await;
    Ok(())
}

/// Handles a connection
async fn handle_connection(mut connection: Connection) {
    debug!("Connection established from cumtown");
    // when someone connects, send out a "hello" msg;
    connection.say("hi i connected\n").await;

    let mut buf = vec![0_u8; 100];
    loop {
        tokio::select! {
            // listen for data coming in from our client
           n_read = connection.stream.read(&mut buf) => {
                // msg from our connected client
                // now we need to send it out to other clients
                //let x = &buf[0..n_read.unwrap()];
                //connection.broadcast_sender.send((connection.addr, String::from_utf8(x.to_vec()).unwrap())).unwrap();

                // Take in a message
                // Get hash
                // Run crack
                // TODO: CHANGE ALL PANICS PROBABLY
                let n_read = match n_read {
                    Ok(x) => x,
                    Err(x) => panic!("{x}"),
                };
                let message = &buf[0..n_read];

                let string_message = match String::from_utf8(message.to_vec()){
                    Ok(x) => x,
                    Err(x) => panic!("{x}"),
                };

                if let Some(_space_index) = string_message.find("crack ") {
                    let split_message = (string_message.split(' ')).collect::<Vec<&str>>();
                    
                    let hash = split_message[1].trim();
                    
                    let hash_len = format!("{}\n",hash.len());
                    connection.say(&hash_len).await;
                    connection.say("\n").await;
                    // connection.say(hash).await;
                    
                    match hex::decode(hash){
                        Ok(_x) => {
                            //connection.say("hello from jizztown3\n").await;
                            test_stuff().await;
                        },
                        Err(_x) => connection.say("Error {x}\n",).await,
                    };
                    // test_stuff().await;
                } else{
                    connection.say("ERRROR: Command must be in the format `crack <hash>`\n").await;

                }          


            }

            // or data coming in over the broadcast channel (i.e., from other clients)
            _msg = connection.broadcast_receiver.recv() => {
                // someone else sent a message.
                // send it back to our connected client.
                //let (sender, msg) = msg.unwrap();
                //let msg = format!("{sender} says {msg}");
                //connection.stream.write_all(msg.as_bytes()).await.unwrap();
            }

        }
    }
}
