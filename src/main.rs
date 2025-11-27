mod alertdetected;
use std::fs;
use serde_json::from_str;
use serde::Deserialize;
use std::io::{Write, BufRead, BufReader};
use chrono::{Timelike, Datelike, Local};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::time::Duration;
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

    let eveFile = fs::read_to_string("src/eve.json").expect("Could not open eve.json file"); 
    let alertsReader = eveFile
        .lines()
        .filter_map(|line| serde_json::from_str::<AlertStruct>(line).ok())
        .collect::<Vec<AlertStruct>>();


    for eve in alertsReader { 
        if eve.event_type == "alert" {
            //Safe borrow and unwrapping. Using .unwrap() moves ownership to sevCheck.
            if let Some(sevCheck) = &eve.alert {
                if sevCheck.severity <= 2 {
                    let final_formatted = timestamp_adjust();

                    //Creates hash from composite strings included in alerts.
                    let fingerprint = format!("P{} : {} : {} : {} : {} : {}",
                        &sevCheck.severity,
                        &eve.timestamp,
                        &eve.src_ip.unwrap(),
                        &eve.dest_ip.unwrap(),
                        &sevCheck.signature,
                        &sevCheck.signature_id
                    );
                    let hash_written = composite_fingerprint(&fingerprint);
                    if hash_written.contains("true") {
                        //alertdetected::execute_zeek(&final_formatted, &fingerprint).await;
                        println!("Test: {}, ", &final_formatted);
                        println!("{}", &hash_written);
                    }
                }
            }
        }
    }
}

//Merge Timestamp, Signature ID, Signature, src IP and dest IP to create a unique hash for an alert - store in a file and check against to avoid dupes
fn composite_fingerprint(fingerprint: &String) -> String {
    let mut hasher = DefaultHasher::new();
    fingerprint.hash(&mut hasher);
    let alert_hash = hasher.finish();
    //Creates hash based on alert composite string.

    //Flag checks against existing hashes in file.
    let mut hash_check_status = false;
    //If Zeek has already been called for this run, do not call again.
    let mut latest_run_flag = false;

    let hash_file = fs::File::open("src/hashfile.txt").expect("Could not open alert_hashes.txt file");
    let reader = BufReader::new(hash_file);
    for line in reader.lines() {
        if let Ok(line) = line {
            if let Some((stored_hash, flag)) = line.trim().split_once('-') {
                if stored_hash == alert_hash.to_string() {
                    println!("Hash: {}-{}", &stored_hash, &flag);
                    //Check flag. If 0, need to start a process that will fetch the pcap time and run zeek on it. Can call the timestamp_adjust function here as normal with mins.
                    if flag == "0" && !latest_run_flag {
                        latest_run_flag = true;
                    }
                    hash_check_status = true;
                    break;
                }
            }
        }
    }
    let mut write_file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("src/hashfile.txt")
        .expect("Could not open alert_hashes.txt file");
    if !hash_check_status{
        writeln!(write_file, "{}-0", alert_hash).expect("Could not write to alert_hashes.txt file");
        String::from("true")
    } else if latest_run_flag {
        //Update flag to 1 for all hashes with 0 flag.
            let contents = fs::read_to_string("src/hashfile.txt").expect("Could not read hashfile.txt");
            let updated_contents: String = contents
                .lines()
                .map(|line| {
                    if line.ends_with("-0") {
                        line.replace("-0", "-1")
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<String>>()
                .join("\n");
            fs::write("src/hashfile.txt", updated_contents).expect("Could not write updated contents to hashfile.txt");
            String::from("true-BitAmended") 
    } else {
        String::from("false")
    }
}


fn timestamp_adjust() -> String {
    //Rounds minutes down to nearest pcap run interval. Being 30 mins or 00 Mins (On the hour).
    let now = Local::now();
    // Determine previous rotation point
    let (prev_hour, prev_min) = if now.minute() >= 30 {
        (now.hour(), 0)
    } else {
        // Before 30 → previous file ended at :30 of previous hour
        let hour = if now.hour() == 0 { 23 } else { now.hour() - 1 };
        (hour, 30)
    };

    format!(
        "hourly_{:04}{:02}{:02}_{:02}{:02}.pcap",
        now.year(),
        now.month(),
        now.day(),
        prev_hour,
        prev_min
    )
}

