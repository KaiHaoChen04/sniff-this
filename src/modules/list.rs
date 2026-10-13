use std::process::Command;

fn is_private_ipv4(ip: &str) -> bool {
    let mut parts = ip.split('.');
    let first: u8 = match parts.next().and_then(|p| p.parse().ok()) {
        Some(n) => n,
        None => return false,
    };
    let second: u8 = match parts.next().and_then(|p| p.parse().ok()) {
        Some(n) => n,
        None => return false,
    };
    // Require exactly 4 octets.
    if parts.count() != 2 {
        return false;
    }
    match first {
        10 => true,
        172 if (16..=31).contains(&second) => true,
        192 if second == 168 => true,
        _ => false,
    }
}

pub fn list_local() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let output = Command::new("arp").arg("-a").output()?;

    if !output.status.success() {
        eprintln!("Command failed");
        return Err(format!("arp exited with status {}", output.status).into());
    }

    let term_output = String::from_utf8_lossy(&output.stdout);

    let mut ip_list: Vec<String> = term_output
        .lines()
        .filter_map(|l| l.split('(').nth(1)?.split(')').next())
        .filter(|ip| is_private_ipv4(ip))
        .map(String::from)
        .collect();

    ip_list.sort();
    ip_list.dedup();

    Ok(ip_list)
}
