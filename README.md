Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/jaredriskus1/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "jaredcs" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-04-01T03:40:57.5599033Z`. These events began at `2026-04-01T03:04:04.2485795Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName contains "Jared-Windows"  
| where InitiatingProcessAccountName == "jaredcs"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-04-01T03:40:57.5599033Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1449" height="427" alt="image" src="https://github.com/user-attachments/assets/7e093b5a-5c49-477e-9c8a-31f829e5d374" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched through the DeviceProcessEvents table looking for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.8.exe”. Based on the logs that were returned, at 2026-04-01T03:07:30.104611Z, an employee on the “Jared-Windows-1”device ran the file tor-browser-windows-x86_64-portable-15.0.8.exe from their Downloads folder, using a command that triggered a silent installation. 

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName contains "Jared-Windows"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.8.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1487" height="112" alt="image" src="https://github.com/user-attachments/assets/15840868-aab3-4c3e-9d2d-d9b2c7e56055" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Conducted a search through the DeviceProcessEvents table looking for any indication that the user “jaredcs” actually opened the “tor” browser. There was evidence that the user opened the browser at 2026-04-01T03:08:26.3536809Z. Several other instances of firefox.exe (Tor) as well as tor.exe were spawned afterwards. 

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName contains "Jared-Windows"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication that the “tor” browser was used to establish a connection using any of the known “tor” ports. 

At 2026-04-01T03:08:48.3241576Z, an employee on the “Jared-Windows-1” device successfully established a connection to the remote IP address 159.69.138.31 on port 9001. The connection was initiated by the process tor.exe, located in the folder c:\users\jaredcs\desktop\tor browser\browser\torbrowser\tor\tor.exe. There were a couple other connections over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName contains "Jared-Windows"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer
- **Timestamp:** `2026-04-01T03:04:04.2485795Z`
- **Event:** The user "jaredcs" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\jaredcs\Downloads\tor-browser-windows-x86_64-portable-15.0.8.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-04-01T03:07:30.104611Z`
- **Event:** The user "jaredcs" executed the file `tor-browser-windows-x86_64-portable-15.0.8.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.8.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.8.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-04-01T03:08:26.3536809Z`
- **Event:** User "jaredcs" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\jaredcs\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-04-01T03:08:48.3241576Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "jaredcs" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\jaredcs\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-04-01T03:09:17.8093124Z` - Connected to `64.65.63.33` on port `443`.
  - `2026-04-01T03:08:59.9004649Z ` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "jaredcs" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-04-01T03:40:57.4933276Z`
- **Event:** The user "jaredcs" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\jaredcs\Desktop\tor-shopping-list.txt`

---

## Summary

The user "jaredcs" on the "Jared-Windows-1" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `Jared-Windows-1` by the user `jaredcs`. The device was isolated, and the user's direct manager was notified.

---
