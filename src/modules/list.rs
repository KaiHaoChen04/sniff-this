use std::process::Command;

pub fn list_local() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("arp").arg("-a").output()?;

    if !output.status.success() {
        eprint!("Command failed");
        return Ok("".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
}
