Sure, here's a `README.md` file for your script:

```markdown
# Nmap Post-Processing Script

This script processes the output of an Nmap scan to perform various security checks. It uses Metasploit, Hydra, and other tools to scan for vulnerabilities and gather information about the scanned hosts.

## Usage

```sh
./script.sh <nmap_output_file> --check <all|ports|eternalblue|anonymous|bluekeep|rdp|defaultcreds|httpmethods|kyocera|sslscan|cisco>
```

### Examples

- Run all checks:
  ```sh
  ./script.sh nmap_output.txt --check all
  ```

- Run only the Eternal Blue check:
  ```sh
  ./script.sh nmap_output.txt --check eternalblue
  ```

## Checks

The script can perform the following checks based on the value provided to the `--check` parameter:

- `all`: Run all checks
- `ports`: Extract hosts for specified ports from the Nmap output
- `eternalblue`: Check for Eternal Blue vulnerability using Metasploit
- `anonymous`: Check for anonymous FTP login using Metasploit
- `bluekeep`: Check for BlueKeep vulnerability using Metasploit
- `rdp`: Check for RDP NLA using Metasploit
- `defaultcreds`: Check for default RDP credentials using Hydra
- `httpmethods`: Check HTTP and HTTPS methods using Metasploit
- `kyocera`: Run Kyocera printer exploit
- `sslscan`: Perform SSL scan using sslscan
- `cisco`: Run Cisco Smart Install exploit

## Prerequisites

Ensure you have the following tools installed and properly configured:

- `nmap`
- `msfconsole` (Metasploit)
- `hydra`
- `sslscan`
- `python3`
- Python libraries: `requests`, `xmltodict`, `tftpy`

## Script Details

### Port Extraction

For the specified ports, extract the host IP addresses from the Nmap output and save them to corresponding files (`port_<port>.txt`).

### Eternal Blue Check

Run the Eternal Blue (MS17-010) check using Metasploit and save the vulnerable hosts to `eternal_blue`.

### Anonymous Login Check

Run the anonymous FTP login check using Metasploit and save the hosts with anonymous read access to `anonymous_login`.

### BlueKeep Check

Run the BlueKeep (CVE-2019-0708) check using Metasploit and save the vulnerable hosts to `blue_keep`.

### RDP NLA Check

Run the RDP NLA check using Metasploit and save the hosts that do not require NLA to `nla`.

### Default RDP Credentials Check

Use Hydra to check for default RDP credentials and save the results to `rdp_default_credentials.txt`.

### HTTP/HTTPS Methods Check

Check for allowed HTTP and HTTPS methods using Metasploit and save the results to `http_methods` and `https_methods`.

### Kyocera Credential Leakage Check

Run the Kyocera printer exploit to extract sensitive data and save the results to corresponding files.

### SSL Scan

Perform an SSL scan using `sslscan` and save the results to `port_443_ssl_report.txt` and `sort_ssl_ips`.

### Cisco Smart Install Check

Run the Cisco Smart Install exploit and save the results to corresponding files.

## Error Handling

The script checks for errors after each critical step and exits with an appropriate error message if a step fails.

## License

This script is provided "as-is" without any warranty. Use it at your own risk.

---

Feel free to customize the script and the README as per your requirements. For any issues or contributions, please create a pull request or open an issue on the repository.
```

Save the above content in a file named `README.md` in the same directory as your script. This will provide users with detailed information on how to use the script, what each check does, and any prerequisites they need to have in place.
