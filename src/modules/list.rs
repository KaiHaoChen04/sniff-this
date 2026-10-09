use std::process::Command;

pub fn list_local() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let output = Command::new("arp").arg("-a").output()?;

    if !output.status.success() {
        eprint!("Command failed");
        return Err(format!("arp exited with status {}", output.status).into());
    }

    let term_output = String::from_utf8_lossy(&output.stdout);

    let ip_list = term_output
        .lines()
        .filter_map(|l| l.split('(').nth(1)?.split(')').next())
        .map(String::from)
        .collect();

    Ok(ip_list)
}
