mod alertdetected;
use std::fs;
use serde_json::from_str;
use serde::Deserialize;
use std::io::{Write, BufRead, BufReader};
use chrono::{Timelike, Datelike, Local};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use tokio;

#[derive(Deserialize, Debug)]
struct AlertStruct {
    event_type: String,
    timestamp: String,
    alert: Option<AlertDetails>,
    src_ip: Option<String>,
    dest_ip: Option<String>,
}

#[derive(Deserialize, Debug)]
struct AlertDetails {
    severity: u8,
    signature: String,
    signature_id: u32,
    category: String,
    action: String,
}

//Do not need to write my own logic for filtering alerts. Can be done from Wazuh side. Just need to forward high severity alerts to Zeek for pcap analysis.
#[tokio::main]
async fn main() {
    let eveJson: &str = "/var/log/suricata/eve.json";
    let zeekBin: &str = "/opt/zeek/bin/zeek";
    let zeekLogDir: &str = "/opt/zeek/etc"; // Directory containing Zeek log files, need to iterate through and get each.

    let eveFile = fs::read_to_string(&eveJson).expect("Could not open eve.json file"); 
    let alertsReader = from_str::<Vec<AlertStruct>>(&eveFile).unwrap();

    for eve in alertsReader { 
        if eve.event_type == "alert" {
            //Safe borrow and unwrapping. Using .unwrap() moves ownership to sevCheck.
            if let Some(sevCheck) = &eve.alert {
                if sevCheck.severity <= 2 {
                    let now = Local::now();
                    let mins_now = now.minute() as i32;

                    //formats to match pcap file naming convention.
                    let timestamp = now.format("%Y%m%d_%H").to_string();
                    let final_formatted = String::from("hourly_") + "" + &timestamp + "" + &timestamp_adjust(mins_now) + "" + &String::from(".pcap");

                    //Creates hash from composite strings included in alerts.
                    let fingerprint = format!("P{} : {} : {} : {} : {} : {}",
                        &sevCheck.severity,
                        &eve.timestamp,
                        &eve.src_ip.unwrap(),
                        &eve.dest_ip.unwrap(),
                        &sevCheck.signature,
                        &sevCheck.signature_id
                    );
                    let hash_written = composite_fingerprint(&fingerprint).unwrap();
                    if hash_written {
                        alertdetected::execute_zeek(&final_formatted, &fingerprint).await;
                    }
                }
            }
        }
    }
}

//Merge Timestamp, Signature ID, Signature, src IP and dest IP to create a unique hash for an alert - store in a file and check against to avoid dupes
//Wipe daily to avoid file bloat.
fn composite_fingerprint(fingerprint: &String) -> Result<bool, std::io::Error> {
    let mut hasher = DefaultHasher::new();
    fingerprint.hash(&mut hasher);
    let alert_hash = hasher.finish();

    let mut hash_check_status = false;
    let hash_file = fs::File::open("hashfile.txt").expect("Could not open alert_hashes.txt file");
    let reader = BufReader::new(hash_file);
    for line in reader.lines() {
        if let Ok(line) = line {
            if line.trim() == alert_hash.to_string() {
                hash_check_status = true;
                break;
            } 
        }
    }
    if !hash_check_status {
        let mut write_file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open("hashfile.txt")
            .expect("Could not open alert_hashes.txt file");
        writeln!(write_file, "{}", alert_hash).expect("Could not write to alert_hashes.txt file");
        Ok(true)
    } else {
        Ok(false)
    }
}


fn timestamp_adjust(num: i32) -> String {
    //Rounds minutes down to nearest pcap run interval. Being 30 mins or 00 Mins (On the hour).
    if num > 30 {
        let thirty_more = num - (num % 30);
        thirty_more.to_string()
    } else if num == 30 {
        String::from("00")
    } else {
        String::from("00") // Add else if num = 0 case for later
    }
}

