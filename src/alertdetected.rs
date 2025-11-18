use std::process::Command;
use dotenv::dotenv;
use std::env;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_lambda::{Client, Error};
use serde_json::json;
use aws_sdk_lambda::primitives::Blob;
use tokio;


//Implement zeek run here and webhook alerts.
pub async fn execute_zeek(hourly_pcap_file: &str, alert: &str) {
    let pcapDir: &str = "/usr/local/bin/hourlypcap";
    let full_pcap_path = format!("{}/{}", pcapDir, hourly_pcap_file);
    let status = Command::new("zeek")
        .args(["-r", &full_pcap_path])
        .status();

    match status {
        Ok(exit) if exit.success() => println!("Zeek executed successfully."),
        Ok(exit) => eprintln!("Zeek exited with status: {}", exit),
        Err(e) => eprintln!("Failed to execute Zeek: {}", e),
    }
    println!("Executing Zeek on pcap file... {}", full_pcap_path);
    webhook_alert(&hourly_pcap_file, &alert).await.unwrap();
}


async fn webhook_alert(hourly_pcap_file: &str, alert: &str) -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let region_provider = RegionProviderChain::default_provider().or_else("eu-north-1");
    let config = aws_config::from_env().region(region_provider).load().await;
    let client = Client::new(&config);

    let payload = json!({
        "message": format!("**Alert:** {} | **PCAP Capture:** {}", alert, hourly_pcap_file)
    });

    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let resp = client
        .invoke()
        .function_name("SuricataAlert")
        .payload(Blob::new(payload_bytes))
        .send()
        .await?;

    if let Some(bytes) = resp.payload {
        println!("Response from Lambda: {}", String::from_utf8_lossy(&bytes.as_ref()));
    }
    Ok(())
}