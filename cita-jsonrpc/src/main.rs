#![feature(try_from)]
extern crate bytes;
extern crate clap;
extern crate cpuprofiler;
extern crate dotenv;
extern crate error;
extern crate futures;
extern crate http;
extern crate httparse;
extern crate hyper;
extern crate jsonrpc_types;
extern crate libproto;
#[macro_use]
extern crate log;
extern crate logger;
extern crate net2;
extern crate num_cpus;
extern crate protobuf;
extern crate pubsub;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate threadpool;
extern crate time;
extern crate tokio_core;
extern crate tokio_io;
extern crate toml;
extern crate unicase;
#[macro_use]
extern crate util;
extern crate uuid;
extern crate ws;

mod config;
mod helper;
mod ws_handler;
mod mq_handler;
mod http_server;
mod response;

use clap::App;
use config::{NewTxFlowConfig, ProfileConfig};
use cpuprofiler::PROFILER;
use http_server::Server;
use libproto::Message;
use libproto::request::{self as reqlib, BatchRequest};
use protobuf::RepeatedField;
use pubsub::start_pubsub;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Arc;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::{Duration, SystemTime};
use tokio_core::reactor::Core;
use util::{set_panic_handler, Mutex};
use uuid::Uuid;
use ws_handler::WsFactory;

pub const TOPIC_NEW_TX: &str = "jsonrpc.new_tx";
pub const TOPIC_NEW_TX_BATCH: &str = "jsonrpc.new_tx_batch";

fn main() {
    micro_service_init!("cita-jsonrpc", "CITA:jsonrpc");

    // todo load config
    let matches = App::new("JsonRpc")
        .version("0.1")
        .author("Cryptape")
        .about("CITA JSON-RPC by Rust")
        .args_from_usage("-c, --config=[FILE] 'Sets a custom config file'")
        .get_matches();

    let mut config_path = "./jsonrpc.toml";
    if let Some(c) = matches.value_of("config") {
        info!("Value for config: {}", c);
        config_path = c;
    }

    let config = config::Config::new(config_path);
    info!(
        "CITA:jsonrpc config \n {:?}",
        toml::to_string_pretty(&config).unwrap()
    );

    //enable HTTP or WebSocket server!
    if !config.ws_config.enable && !config.http_config.enable {
        error!("enable HTTP or WebSocket server!");
        std::process::exit(-1);
    }

    start_profile(&config.profile_config);

    // init pubsub
    let (tx_sub, rx_sub) = channel();
    let (tx_pub, rx_pub) = channel();
    //used for buffer message
    let (tx_relay, rx_relay) = channel();
    start_pubsub("jsonrpc", vec!["auth.rpc", "chain.rpc"], tx_sub, rx_pub);

    let backlog_capacity = config.backlog_capacity;

    let responses = Arc::new(Mutex::new(HashMap::with_capacity(backlog_capacity)));
    let http_responses = Arc::clone(&responses);
    let ws_responses = Arc::clone(&responses);
    let mut mq_handle = mq_handler::MqHandler::new(responses);

    //dispatch
    let tx_flow_config = config.new_tx_flow_config;
    thread::spawn(move || {
        let mut new_tx_request_buffer = Vec::new();
        let mut time_stamp = SystemTime::now();
        loop {
            if let Ok(res) = rx_relay.try_recv() {
                let (topic, req): (String, reqlib::Request) = res;
                forward_service(
                    topic,
                    req,
                    &mut new_tx_request_buffer,
                    &mut time_stamp,
                    &tx_pub,
                    &tx_flow_config,
                );
            } else {
                if !new_tx_request_buffer.is_empty() {
                    batch_forward_new_tx(&mut new_tx_request_buffer, &mut time_stamp, &tx_pub);
                }
                thread::sleep(Duration::new(0, tx_flow_config.buffer_duration));
            }
        }
    });

    //ws
    if config.ws_config.enable {
        let ws_config = config.ws_config.clone();
        let tx = tx_relay.clone();
        thread::spawn(move || {
            let url = ws_config.listen_ip.clone() + ":" + &ws_config.listen_port.clone().to_string();
            //let factory = WsFactory::new(ws_responses, tx_pub, 0);
            let factory = WsFactory::new(ws_responses, tx, 0);
            info!("WebSocket Listening on {}", url);
            let mut ws_build = ws::Builder::new();
            ws_build.with_settings(ws_config.into());
            let ws_server = ws_build.build(factory).unwrap();
            let _ = ws_server.listen(url);
        });
    }

    if config.http_config.enable {
        let http_config = config.http_config.clone();
        let addr = http_config.listen_ip.clone() + ":" + &http_config.listen_port.clone().to_string();
        info!("Http Listening on {}", &addr);

        let threads: usize = config
            .http_config
            .thread_number
            .unwrap_or_else(num_cpus::get);

        for i in 0..threads {
            let addr = addr.clone().parse().unwrap();
            let tx = tx_relay.clone();
            let timeout = http_config.timeout;
            let http_responses = Arc::clone(&http_responses);
            let allow_origin = http_config.allow_origin.clone();
            let _ = thread::Builder::new()
                .name(format!("worker{}", i))
                .spawn(move || {
                    let core = Core::new().unwrap();
                    let handle = core.handle();
                    let timeout = Duration::from_secs(timeout);
                    let listener = http_server::listener(&addr, &handle).unwrap();
                    Server::start(core, listener, tx, http_responses, timeout, &allow_origin);
                })
                .unwrap();
        }
    }

    loop {
        let (key, msg) = rx_sub.recv().unwrap();
        mq_handle.handle(&key, &msg);
    }
}

fn batch_forward_new_tx(
    new_tx_request_buffer: &mut Vec<reqlib::Request>,
    time_stamp: &mut SystemTime,
    tx_pub: &Sender<(String, Vec<u8>)>,
) {
    trace!(
        "Going to send new tx batch to auth with {} new tx and buffer time cost is {:?} ",
        new_tx_request_buffer.len(),
        time_stamp.elapsed().unwrap()
    );
    let mut batch_request = BatchRequest::new();
    batch_request.set_new_tx_requests(RepeatedField::from_slice(&new_tx_request_buffer[..]));

    let request_id = Uuid::new_v4().as_bytes().to_vec();
    let mut request = reqlib::Request::new();
    request.set_batch_req(batch_request);
    request.set_request_id(request_id);

    let data: Message = request.into();
    tx_pub
        .send((String::from(TOPIC_NEW_TX_BATCH), data.try_into().unwrap()))
        .unwrap();
    *time_stamp = SystemTime::now();
    new_tx_request_buffer.clear();
}

fn forward_service(
    topic: String,
    req: reqlib::Request,
    new_tx_request_buffer: &mut Vec<reqlib::Request>,
    time_stamp: &mut SystemTime,
    tx_pub: &Sender<(String, Vec<u8>)>,
    config: &NewTxFlowConfig,
) {
    if topic.as_str() != TOPIC_NEW_TX {
        let data: Message = req.into();
        tx_pub.send((topic, data.try_into().unwrap())).unwrap();
    } else {
        new_tx_request_buffer.push(req);
        trace!(
            "New tx is pushed and has {} new tx and buffer time cost is {:?}",
            new_tx_request_buffer.len(),
            time_stamp.elapsed().unwrap()
        );
        if new_tx_request_buffer.len() > config.count_per_batch
            || time_stamp.elapsed().unwrap().subsec_nanos() > config.buffer_duration
        {
            batch_forward_new_tx(new_tx_request_buffer, time_stamp, tx_pub);
        }
    }
}

fn start_profile(config: &ProfileConfig) {
    if config.enable && config.flag_prof_start != 0 && config.flag_prof_duration != 0 {
        let start = config.flag_prof_start;
        let duration = config.flag_prof_duration;
        thread::spawn(move || {
            thread::sleep(Duration::new(start, 0));
            PROFILER
                .lock()
                .unwrap()
                .start("./jsonrpc.profile")
                .expect("Couldn't start");
            thread::sleep(Duration::new(duration, 0));
            PROFILER.lock().unwrap().stop().unwrap();
        });
    }
}
