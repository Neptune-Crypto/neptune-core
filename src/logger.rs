use log::{Metadata, Record};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
extern crate chrono;
use chrono::offset::Local;
use chrono::DateTime;
use std::time::SystemTime;

#[derive(Debug)]
pub struct Logger {
    log_file_name: String,
    verbose: u8,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if !Path::new(&self.log_file_name).is_file() {
                match File::create(self.log_file_name.clone()) {
                    Ok(_) => (),
                    Err(err) => println!("Failed to create logging file. Error: {:?}", err),
                }
            }

            let mut log_file = OpenOptions::new()
                .write(true)
                .append(true)
                .open(self.log_file_name.clone())
                .unwrap_or_else(|_| panic!("failed to open log file: \"{}\"", self.log_file_name));
            let system_time = SystemTime::now();
            let datetime: DateTime<Local> = system_time.into();
            log_file
                .write_all(
                    format!(
                        "{} {}  {}: {}\n",
                        datetime.format("%Y-%m-%dT%TZ"),
                        record.target(),
                        record.level(),
                        record.args()
                    )
                    .as_bytes(),
                )
                .expect("Unable to write log file");
        }
    }

    fn flush(&self) {}
}

impl Logger {
    fn verbose_to_log_level(verbose: u8) -> log::LevelFilter {
        match verbose {
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        }
    }

    pub fn init(opt: crate::args::Args) {
        let logger: Logger = Logger {
            log_file_name: opt.log_file_name.clone(),
            verbose: opt.verbose,
        };
        log::set_boxed_logger(Box::new(logger))
            .map(|()| log::set_max_level(Logger::verbose_to_log_level(opt.verbose)))
            .expect("Unable to configure logger");
    }
}
