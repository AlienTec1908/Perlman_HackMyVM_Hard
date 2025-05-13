# Perlman - HackMyVM (Hard)

![Perlman.png](Perlman.png)

## Übersicht

*   **VM:** Perlman
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Perlman)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 6. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Perlman_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Perlman" zu erlangen. Der Weg dorthin umfasste mehrere komplexe Eskalationsstufen: Zuerst wurde ein exponiertes `.git`-Verzeichnis auf dem Webserver entdeckt, das in seiner Historie einen phpass-Hash für den Benutzer `webmaster` enthielt. Nach dem Knacken des Hashes (`cookie`) wurde Zugriff auf das POP3-Postfach des Benutzers `rita` (mit demselben Passwort) erlangt. Eine E-Mail enthüllte den VHost `itzhak.perlman.hmv`, auf dem eine WordPress-Instanz lief. Eine bekannte Schwachstelle im "TheCartPress"-Plugin ermöglichte das Erstellen eines Admin-Accounts und den Upload einer Meterpreter-Shell als `www-data`. Von dort aus wurde zu `rita` eskaliert (Passwort-Wiederverwendung), dann zu `milou` durch Ausnutzung eines unsicheren Cronjobs (Path Hijacking mit `find`), weiter zu `ze_perlman` durch Command Injection in einer CSV-Datei, die von einem Skript verarbeitet wurde, und schließlich zu `root` durch Ausnutzung einer unsicheren `sudo`-Regel, die das Ausführen eines Backup-Skripts erlaubte, welches den privaten SSH-Schlüssel von `root` kopierte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` / `nano`
*   `nmap`
*   `gobuster`
*   `nc` (netcat)
*   `curl`
*   `gitdumper.sh`
*   `git`
*   `hashcat`
*   `wpscan`
*   `searchsploit`
*   Python (für Exploit-Skript)
*   `msfconsole` (Metasploit Framework)
*   `meterpreter`
*   Standard Linux-Befehle (`cat`, `echo`, `ls`, `cd`, `watch`, `chmod`, `ssh`, `cp`, `sudo`, `bash`, `pwd`, `touch`, `id`, `su`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Perlman" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Git/Mail Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.122) mit `arp-scan` identifiziert. Hostname `perlman.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH), 25 (SMTP), 80 (HTTP, Apache mit `.git`-Leak), 110 (POP3), 119 (NNTP), 995 (POP3S).
    *   NNTP-Enumeration (`nc ... list`, `group`, `article`) fand Benutzer `rita`.
    *   Mittels `gitdumper.sh` wurde das `.git`-Verzeichnis von `http://perlman.hmv/.git/` heruntergeladen.
    *   Analyse der Git-Historie (`git diff`) enthüllte einen phpass-Hash (`$P$BCaM...`) für den Benutzer `webmaster`.
    *   Der Hash wurde mit `hashcat` und `rockyou.txt` geknackt: Passwort `cookie`.
    *   Login auf POP3 (Port 110) als `rita` mit dem Passwort `cookie`. Eine E-Mail von `MAILER-DAEMON@itzhak.perlman.hmv` wurde gefunden, was den VHost `itzhak.perlman.hmv` enthüllte.

2.  **WordPress Exploitation & Initial Access (Meterpreter als `www-data`):**
    *   Der VHost `itzhak.perlman.hmv` wurde in `/etc/hosts` eingetragen. Es wurde eine WordPress-Instanz identifiziert.
    *   `wpscan` fand das Plugin "TheCartPress <= 1.5.3.6" mit einer "Unauthenticated Arbitrary Admin Account Creation"-Schwachstelle (EDB-ID 50378).
    *   Der Python-Exploit `50378.py` wurde ausgeführt, um einen Admin-Account (`admin_02:admin1234`) zu erstellen.
    *   Mittels Metasploit (`exploit/unix/webapp/wp_admin_shell_upload`) und den neuen Admin-Credentials wurde eine PHP-Meterpreter-Reverse-Shell als `www-data` auf dem Zielsystem etabliert und stabilisiert.

3.  **Privilege Escalation (Lateral Movement zu `rita`, `milou`, `ze_perlman`):**
    *   Von `www-data` wurde mit `su rita` und dem Passwort `cookie` zu `rita` gewechselt.
    *   Als `rita` wurde ein unsicherer Cronjob ausgenutzt (Path Hijacking): Ein Skript `/tmp/find` (das `cp /home/milou/.ssh/id_rsa /tmp/milou && chmod 777 /tmp/milou` enthielt) wurde erstellt und ausführbar gemacht. Ein Cronjob, der `find` unsicher aufrief, führte dieses Skript aus und kopierte Milous privaten SSH-Schlüssel.
    *   SSH-Login als `milou` mit dem extrahierten Schlüssel.
    *   Als `milou` wurde eine CSV-Datei (`perl_store.csv`) gefunden, die von einem Skript verarbeitet wurde und anfällig für Command Injection war. Durch Einfügen von `x[$(cp /home/ze_perlman/.ssh/id_rsa /dev/shm>&2 ; chmod 777 /dev/shm/id_rsa>&2)]` in die CSV wurde der private SSH-Schlüssel von `ze_perlman` nach `/dev/shm/id_rsa` kopiert.
    *   SSH-Login als `ze_perlman` mit dessen extrahiertem Schlüssel.
    *   Die User-Flag (`7efd84255146266f3ca02579eb71a36f`) wurde in `/home/ze_perlman/user.txt` gefunden.

4.  **Privilege Escalation (von `ze_perlman` zu `root` via `sudo` Script Exploit):**
    *   Als `ze_perlman` zeigte `sudo -l`, dass das Skript `/bin/bash /opt/backup/bk *` als `root` ohne Passwort ausgeführt werden durfte.
    *   Das Skript `/opt/backup/bk` kopierte bei Ausführung mit dem Argument `desired-root-2022` (abgeleitet aus `/opt/vfy.txt`) den privaten SSH-Schlüssel von `root` (`~/.ssh/id_rsa`) in das Verzeichnis `/opt/backup/`.
    *   Das Skript wurde mit `sudo /bin/bash /opt/backup/bk desired-root-2022` ausgeführt. Der Root-SSH-Schlüssel wurde nach `/opt/backup/id_rsa` kopiert.
    *   Der Schlüssel wurde nach `/dev/shm/root` kopiert, die Berechtigungen auf `600` gesetzt.
    *   Erfolgreicher lokaler SSH-Login als `root` mit dem Schlüssel (`ssh -i /dev/shm/root root@localhost`).
    *   Die Root-Flag (`0ca2710be21eabe7ddbf0240557bd210`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Exponiertes `.git`-Verzeichnis:** Ermöglichte das Herunterladen des Quellcodes und der Git-Historie, was zur Aufdeckung eines Passwort-Hashes führte.
*   **Passwort-Wiederverwendung:** Das für `webmaster` geknackte Passwort `cookie` funktionierte auch für `rita`s POP3-Account.
*   **WordPress Plugin Schwachstelle (TheCartPress):** Eine bekannte Schwachstelle erlaubte die Erstellung eines unautorisierten Admin-Accounts.
*   **Unsicherer Cronjob (Path Hijacking):** Ein Cronjob führte `find` unsicher aus, was das Einschleusen von Befehlen durch Erstellen eines bösartigen `find`-Skripts in einem durchsuchten Pfad ermöglichte.
*   **Command Injection in CSV-Verarbeitung:** Ein Skript verarbeitete eine CSV-Datei unsicher, was Command Injection über manipulierte CSV-Einträge erlaubte.
*   **Unsichere `sudo`-Regel (Skriptausführung):** Ein Benutzer durfte ein Backup-Skript als `root` ausführen, das sensible Dateien (Root-SSH-Key) an einen zugänglichen Ort kopierte.
*   **Informationslecks:** Passwort-Hash in Git-Historie, VHost-Name in E-Mail-Header, NNTP-Benutzername.

## Flags

*   **User Flag (`/home/ze_perlman/user.txt`):** `7efd84255146266f3ca02579eb71a36f`
*   **Root Flag (`/root/root.txt`):** `0ca2710be21eabe7ddbf0240557bd210`

## Tags

`HackMyVM`, `Perlman`, `Hard`, `Git Dumper`, `Password Cracking`, `phpass`, `POP3`, `WordPress Exploit`, `TheCartPress`, `Metasploit`, `Cronjob Exploit`, `Path Hijacking`, `CSV Command Injection`, `sudo Exploit`, `SSH Key Leak`, `Linux`, `Web`, `Privilege Escalation`, `Apache`, `ProFTPD`, `Postfix`, `Dovecot`, `INN`
