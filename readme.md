# SPAMSI - Remote AMSI Patch Tool

  

**SPAMSI** is a post-exploitation tool for disabling AMSI (Antimalware Scan Interface) in remote PowerShell processes. It supports both **one-time patching** and **continuous monitoring** via a watchdog service (hence the name... "spam"si... it spams your PS processes with a patch)

  
**Note:** Requires Administrator privileges to function properly, as it accesses and modifies memory of other processes. This is why SPAMSI is designed as a post-exploitation tool.
 
---

## Features

  

### One-Time Patch (`--patch`)

SPAMSI scans all currently running processes for `powershell.exe` or `pwsh.exe`, then remotely injects a patch to neutralize AMSI functionality. This bypasses script content scanning by AV/EDR solutions.

  

- Automatically finds PowerShell processes

- Resolves `amsi.dll` base and `AmsiScanBuffer` offset

- Applies a small in-memory patch to disable AMSI
  

---

  

### AutoPatch / Watchdog Mode (`--autopatch`)

A persistent **monitoring loop** that continuously looks for newly spawned PowerShell processes, and patches them on detection.

  

- Runs in a loop

- Tracks already-patched PIDs to avoid duplicates

- Optionally could be converted into a Windows Service for stealth and persistence

  

---

  

## AMSI Patch Details

  

The patch is the traditional AMSI patch, applied to the `AmsiScanBuffer` function in `amsi.dll` via:

- Memory protection change (`VirtualProtectEx`)

- Remote memory write (`WriteProcessMemory`)

- Uses an obfuscated byte sequence (with `+1` delta) to slightly evade static detection

Eventually I'd like to see if it's possible to monkeypatch, similar to [GitHub - cybersectroll/TrollAMSI](https://github.com/cybersectroll/TrollAMSI)
  

```cpp

unsigned  char  patch[6] = { 0xB9, 0x58, 0x01, 0x08, 0x81, 0xC4 };

// Deobfuscated in runtime by subtracting 1 from each byte

````

  

This effectively changes the behavior of AMSI to always return a success or bypass status.

  

---

  

## Detection Behavior

| Detection Type | Status |
| -------------- | --------------------------------------------------------------------------------------------------- |
| Static | None seen |
| Dynamic | Flagged by AVs (e.g., Defender) |
| Defender Note | `Behavior:Win32/Gracing.IQ` behavior-based detection, but **still lets it run** in most cases |

  

---

  

## Usage

  

### Command-Line Arguments

  

```bash

spamsi.exe --patch

spamsi.exe --autopatch

```

  

### Options

| Flag | Description |
| ------------- | ------------------------------------------------------------------------ |
| `--patch` | One-time AMSI patching of all active PowerShell processes |
| `--autopatch` | Watchdog mode — continuously scan for new PowerShell processes and patch |
| `--help` | Show usage instructions |


---

  

## Todo

* [ ] Convert watchdog into a persistent Windows service

* [ ] Add support for patching other AMSI-using binaries

* [ ] Track & remove exited PIDs from the patch list (watchdog mode)

* [ ] Additional patch obfuscation techniques (e.g., runtime stub encryption)

  

---

  

## Legal Disclaimer

  

This tool is intended for educational and authorized penetration testing purposes only.

**Do not use on systems you do not own or have explicit permission to test.**

  

---
