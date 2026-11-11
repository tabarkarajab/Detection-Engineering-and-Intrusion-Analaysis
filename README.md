# Detection Engineering and Intrusion Analysis (DEIA)

This repository contains the setup scripts and Infrastructure as Code (IaC) configuration to deploy the DEIA Lab 1 environment. 

##  Lab Architecture
The lab environment consists of two local Ubuntu Server Virtual Machines:
* **Splunk SIEM (VM 1):** Runs Splunk Enterprise, listens on port 9997, and stores telemetry in the `linux` index.
* **Victim Web Server (VM 2):** Runs Apache/PHP with an intentional web shell (`cmd.php`) and a Splunk Universal Forwarder to send logs to the SIEM.

## Repository Files
* `setup_lab.yml`: The Ansible playbook containing the automated setup instructions for both machines.
* `inventory.ini`: The target map containing the IP addresses of the virtual machines.

## How to Deploy (Automated via Ansible)

1. Ensure Ansible is installed on your control machine (`sudo apt install ansible`).
2. Update `inventory.ini` with the correct IP addresses for your `[splunk]` and `[webserver]` VMs.
3. Run the playbook:
   ```bash
   ansible-playbook -i inventory.ini setup_lab.yml --ask-become-pass


## Lab Operational History & Manual Access

To manually verify or log into the Victim Web Server for debugging and telemetry inspection:

### Useful Administrative & Diagnostic Commands
* **Check Web Server IP:** `ip a`
* **Check SSH Status:** `sudo systemctl status ssh`
* **Verify Audit Logging:** `sudo auditctl -l`
* **Tail Laurel Audit Logs:** `tail -f /var/log/laurel/audit.log`

* <img width="1920" height="535" alt="Screenshot from 2026-11-11 12-51-48" src="https://github.com/user-attachments/assets/a1b050a3-9798-4e00-90fe-9b96cdae7e9b" />
