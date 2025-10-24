# SSHPot

A highly configurable SSH honeypot built with Python's asyncio framework for capturing and analyzing SSH-based attacks. SSHPot simulates a interactive SSH server without executing attacker commands, providing  forensic logging and file upload quarantine.

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


## Overview

SSHPot is a defensive security tool designed to detect, monitor, and analyze network intrusion attempts. The system provides forensically accurate simulation of network services based purely on static configuration files and dynamic per-attacker state tracking.

### Core Principles

- **No Code Execution**: The system never executes any attacker commands
- **Stateful Simulation**: Virtual filesystem changes (touch, rm, echo) are tracked per-attacker session
- **Forensic Accuracy**: Comprehensive logging of every interaction for security analysis


## Quick Start

### Prerequisites

- Python 3.10 or higher
- Paramiko (for SSH protocol implementation)

Install dependencies:
```bash
pip install paramiko
```

### Installation

```bash
git clone https://github.com/RaikyHH/SSHPot.git
cd SSHPot

# Generate SSH host key (required on first run)
python generate_host_key.py

# Start the honeypot
python main.py
```

On first run, the system will automatically generate sample configuration files:
- `config_commands.json` - Command behavior definitions (130+ commands)
- `config_files.json` - Virtual filesystem structure
- `config_connection.json` - Network service configuration

The honeypot will start listening on **port 22 (SSH)** by default and display a real-time monitoring console.

>

### Example Session

Connect to the honeypot using SSH:
```bash
ssh root@localhost -p 22
# Password: toor (configurable in config_connection.json)
```

The honeypot will simulate a fully interactive shell:
```bash
root@debian:/root$ whoami
root
root@debian:/root$ uptime
 14:23:45 up 5 days, 03:21,  1 user,  load average: 0.08, 0.12, 0.21
root@debian:/root$ touch /tmp/test.txt
root@debian:/root$ ls /tmp
test.txt
root@debian:/root$ echo "malware" > /tmp/malware.sh
root@debian:/root$ cat /tmp/malware.sh
malware
root@debian:/root$ ls -la
drwxr-xr-x 1 root root  4096 Jan 15 12:00 .
drwxr-xr-x 1 root root  4096 Jan 15 12:00 ..
-rw-r--r-- 1 root root  3106 Jan 15 12:00 .bashrc
-rw-r--r-- 1 root root  4096 Jan 15 12:00 .bash_history
```

Upload files via SCP (automatically quarantined):
```bash
scp malware.sh root@localhost:/tmp/
# File stored in quarantine/files/{sha256}.bin with forensic metadata
```


## Architecture

### System Architecture Diagram

```
                                  SSHPot Honeypot System
                            ================================

                          ┌─────────────────────────────────┐
                          │     Attacker Connections        │
                          │  (SSH port 22 / Custom Port)    │
                          └──────────────┬──────────────────┘
                                         │
                                         ▼
                          ┌──────────────────────────────────┐
                          │     Network Handler              │
                          │  (network_handler.py)            │
                          │  - Async TCP dispatcher          │
                          │  - Connection rate limiting      │
                          │  - Protocol routing              │
                          └──────────────┬───────────────────┘
                                         │
                 ┌───────────────────────┴────────────────────────┐
                 │                                                 │
                 ▼                                                 ▼
    ┌────────────────────────┐                        ┌────────────────────────┐
    │  SSH Protocol Handler  │                        │  Future Protocol       │
    │ (ssh_server_paramiko)  │                        │  Handlers (FTP, etc.)  │
    │  - SSH-2.0 handshake   │                        │  - Extensible design   │
    │  - Authentication      │                        │  - BaseProtocolHandler │
    │  - PTY/shell session   │                        └────────────────────────┘
    └──────────┬─────────────┘
               │
               ├─────────────┬──────────────┬──────────────────┐
               │             │              │                  │
               ▼             ▼              ▼                  ▼
    ┌─────────────────┐ ┌──────────┐ ┌───────────────┐ ┌──────────────┐
    │ Command         │ │   SCP    │ │ File          │ │  Dynamic     │
    │ Processor       │ │ Handler  │ │ Operations    │ │  Values      │
    │ (command_       │ │ (scp_    │ │ (file_        │ │ (dynamic_    │
    │  processor.py)  │ │  handler)│ │  operations)  │ │  values.py)  │
    │                 │ │          │ │               │ │              │
    │ • Parse cmds    │ │• File    │ │• touch/rm/    │ │• {{random}}  │
    │ • Lookup config │ │  upload  │ │  mkdir/cat    │ │• {{uptime}}  │
    │ • Simulate      │ │• SHA256  │ │• echo > >>    │ │• {{counter}} │
    │   latency       │ │  hash    │ │• cp/mv        │ │• {{datetime}}│
    │ • Generate      │ │• Metadata│ │• Validation   │ │• Nested calc │
    │   output        │ │• Quarant │ │• State track  │ │• Per-session │
    └────────┬────────┘ └────┬─────┘ └───────┬───────┘ └──────┬───────┘
             │               │               │                │
             └───────────────┴───────────────┴────────────────┘
                                     │
                                     ▼
              ┌─────────────────────────────────────────────────┐
              │         Core Infrastructure Layer               │
              └─────────────────────────────────────────────────┘
                         │                    │
            ┌────────────┴──────────┐    ┌────┴──────────────┐
            ▼                       ▼    ▼                   ▼
  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
  │  Config Engine   │   │  State Manager   │   │ Forensic Logger  │
  │ (config_engine)  │   │ (state_manager)  │   │ (forensic_       │
  │                  │   │                  │   │  logger.py)      │
  │ • Singleton      │   │ • SQLite DB      │   │                  │
  │ • Load configs:  │   │ • Session track  │   │ • JSON-Lines     │
  │   - commands.json│   │ • Per-attacker   │   │ • Event types:   │
  │   - files.json   │   │   filesystem     │   │   - CONNECTION   │
  │   - connection   │   │   state          │   │   - COMMAND_EXEC │
  │ • Validation     │   │ • File changes   │   │   - STATE_CHANGE │
  │ • Thread-safe    │   │   (create/delete)│   │   - SCP_UPLOAD   │
  └──────────────────┘   │ • DoS limits     │   │ • Sanitization   │
                         │   (10k ops/sess) │   │ • 64KB limit     │
                         └──────────────────┘   └──────────────────┘
                                 │                       │
                                 ▼                       ▼
                    ┌──────────────────────┐  ┌──────────────────┐
                    │   honeypot_state.db  │  │ honeypot_        │
                    │   ================   │  │ forensics.log    │
                    │                      │  │ ================│
                    │   Tables:            │  │                  │
                    │   • sessions         │  │ JSON-Lines format│
                    │     - id, ip, start  │  │ Real-time append │
                    │     - end, status    │  │ Log rotation     │
                    │   • file_changes     │  └──────────────────┘
                    │     - session_id     │
                    │     - path, action   │
                    │     - content, ts    │
                    └──────────────────────┘

              ┌─────────────────────────────────────────────────┐
              │            Quarantine Storage                   │
              │         (SCP Uploaded Files)                    │
              └─────────────────────────────────────────────────┘
                         │                        │
                         ▼                        ▼
              ┌────────────────────┐   ┌──────────────────────┐
              │  quarantine/files/ │   │ quarantine/metadata/ │
              │  {sha256}.bin      │   │ {session}_{ts}_      │
              │  (deduplicated)    │   │ {hash}.json          │
              │  - Binary storage  │   │ - IP, timestamp      │
              │  - No execution    │   │ - SHA256, MD5        │
              │  - 100MB limit     │   │ - Permissions        │
              └────────────────────┘   └──────────────────────┘

              ┌─────────────────────────────────────────────────┐
              │          Console Monitoring                     │
              │         (monitoring.py)                         │
              │  - Real-time ANSI dashboard                     │
              │  - Active sessions count                        │
              │  - Last 20 commands across all sessions         │
              │  - System status display                        │
              │  - Auto-refresh every 2 seconds                 │
              └─────────────────────────────────────────────────┘

```

### Data Flow Sequence

```
1. CONNECT    → NetworkHandler receives TCP connection on port 22
                ├─> Rate limit check (10/min per IP)
                └─> Protocol dispatch (SSH)

2. HANDSHAKE  → SSHServerParamiko performs SSH-2.0 handshake
                ├─> Key exchange (KEX)
                ├─> Authentication (password check)
                └─> PTY allocation for shell session

3. SESSION    → StateManager.create_session(ip, fingerprint)
                └─> New entry in sessions table

4. COMMAND    → CommandProcessor.process_command(session_id, cmd_line)
                ├─> Parse command and arguments
                ├─> ConfigEngine.get_command_config(cmd_name)
                ├─> DynamicValueProcessor.process(output_template)
                ├─> FileOperationHandler.process_command() [if applicable]
                │   ├─> Validate against filesystem state
                │   └─> StateManager.track_file_change()
                ├─> asyncio.sleep(latency_ms)  # Simulate real latency
                └─> Return sanitized output

5. SCP UPLOAD → SCPProtocolHandler.handle_file_reception()
                ├─> Receive file data
                ├─> Calculate SHA256 and MD5 hashes
                ├─> Store in quarantine/files/{sha256}.bin
                ├─> Generate metadata JSON
                └─> ForensicLogger.log_scp_upload()

6. LOGGING    → ForensicLogger.log_command(session_id, cmd, output)
                ├─> Sanitize all inputs (remove control chars)
                ├─> Escape newlines (prevent log injection)
                └─> Append JSON-Lines to honeypot_forensics.log

7. DISCONNECT → StateManager.close_session(session_id)
                ├─> Update end_time in sessions table
                └─> ForensicLogger.log_disconnect(session_id)
```

The system is organized into four modular components:

### Module 1: Core Architecture 
**Files**: `config_engine.py`, `state_manager_interface.py`

- Singleton configuration manager loading and validating JSON configs
- Abstract interface (IStateManager) defining the state management contract

### Module 2: Network Handler 

**Files**: `network_handler.py`, `base_handler.py`

- Asynchronous TCP dispatcher routing connections to protocol handlers
- Base class for all protocol emulators providing common functionality

### Module 3: SSH Simulator 

**Files**: `ssh_server_paramiko.py`, `command_processor.py`, `file_operations.py`, `dynamic_values.py`, `scp_handler.py`

- Full SSH-2.0 protocol implementation using Paramiko
- Password authentication with configurable credentials
- Interactive shell session with command processing
- Declarative file operations system (touch, rm, mkdir, cat, etc.)
- Dynamic value placeholders for realistic, time-varying outputs
- SCP file reception for capturing attacker uploads

### Module 4: Database & Logger 

**Files**: `state_manager.py`, `forensic_logger.py`, `monitoring.py`

- SQLite-based attacker session and filesystem state tracking
- JSON-Lines forensic logging of all events
- Real-time console monitoring with ANSI colors

## Configuration

The honeypot's behavior is defined by three JSON configuration files:

### config_commands.json

Defines the behavior of each emulated shell command with three powerful systems:

**1. Static Output Commands:**
```json
{
  "whoami": {
    "output": "root",
    "latency_ms": [50, 150]
  }
}
```

**2. File Operations (Declarative):**
```json
{
  "touch": {
    "output": "",
    "latency_ms": [30, 80],
    "file_operations": {
      "type": "create",
      "requires_args": true,
      "arg_mapping": {"target": 0},
      "effect": {
        "action": "create",
        "content": "",
        "update_mtime": true
      }
    }
  }
}
```

**3. Dynamic Values (Placeholders):**
```json
{
  "uptime": {
    "output": "{{datetime:%H:%M:%S}} up {{uptime_days}}, 1 user, load average: {{random:0.00:0.15:2}}, {{random:0.01:0.20:2}}, {{random:0.05:0.30:2}}",
    "latency_ms": [40, 100],
    "dynamic_values": true
  }
}
```

**Supported Dynamic Placeholders:**
- `{{random:min:max}}` - Random integer/float values
- `{{uptime}}`, `{{uptime_days}}` - Increasing uptime counter
- `{{datetime:%format}}` - Current time formatting
- `{{counter:name:start:increment}}` - Global incrementing counters
- `{{session_counter:name:start:inc}}` - Per-session counters
- `{{calc:expression}}` - Mathematical calculations (supports nested placeholders)
- `{{random_choice:a|b|c}}` - Random selection from options


### config_files.json

Defines the static virtual filesystem:

```json
{
  "/etc/passwd": {
    "type": "file",
    "content": "root:x:0:0:root:/root:/bin/bash\n",
    "perms": "rw-r--r--"
  },
  "/tmp": {
    "type": "dir",
    "perms": "rwxrwxrwt"
  }
}
```

### config_connection.json

Defines network services and authentication:

```json
{
  "ssh": {
    "port": 22,
    "banner": "SSH-2.0-OpenSSH_7.6p1",
    "users": {
      "root": "toor",
      "admin": "admin123"
    }
  }
}
```

## How It Works

### Data Flow

1. **Connection** - NetworkHandler receives incoming TCP connection
2. **Rate Limiting** - IP checked against connection rate limits
3. **Protocol Dispatch** - Port-based lookup routes to appropriate protocol handler
4. **Session Creation** - StateManager creates unique attacker session
5. **Emulation** - Protocol handler processes attacker interactions
6. **Command Processing** - Commands are parsed, sanitized, and simulated
7. **State Tracking** - Filesystem changes are recorded per-session
8. **Logging** - All events are written to sanitized forensic logs

### State Management

The `StateManager` maintains two SQLite tables:

**sessions** - Tracks attacker connections
- Session ID, IP address, fingerprint, timestamps, status

**file_changes** - Per-session filesystem modifications
- Session ID, file path, action (create/delete/modify), content, timestamp
- Limited to 10,000 changes per session (DoS protection)
- Content limited to 1 MB per file

The `resolve_file_state()` method merges static configuration with dynamic changes to provide an accurate view of the filesystem for each attacker.

## SCP File Reception

The honeypot includes comprehensive support for capturing files uploaded by attackers via SCP:

### Features
- **Automatic File Capture**: Accepts files uploaded via `scp` command
- **Secure Quarantine**: All files stored in isolated `quarantine/` directory
- **Deduplication**: Files stored by SHA256 hash (duplicates not re-stored)
- **Never Executed**: Files are ONLY stored, never opened or executed
- **Forensic Metadata**: Complete tracking of source, timestamps, hashes, permissions

### File Storage Structure
```
quarantine/
├── files/
│   └── {sha256_hash}.bin           # Actual file content (deduplicated)
└── metadata/
    └── {session_id}_{timestamp}_{sha256_prefix}.json  # Forensic metadata
```

### Metadata Captured
Each uploaded file generates comprehensive forensic metadata:
- Session ID and client IP address
- Original filename and target path
- Upload timestamp (Unix + ISO8601 format)
- File size in bytes
- SHA256 and MD5 hashes
- Unix file permissions (octal)
- Deduplication status

### Usage Example
```bash
# Attacker uploads a file
scp malware.sh root@honeypot:/tmp/

# Honeypot automatically:
# 1. Accepts the file transfer
# 2. Stores file as quarantine/files/{sha256}.bin
# 3. Creates metadata JSON with forensic details
# 4. Logs SCP_FILE_UPLOAD event
# 5. Displays console notification
```

### Security Considerations
- Files are stored in quarantine and **NEVER EXECUTED**
- Use hash-based filenames to prevent path traversal
- Analyze files only in isolated VM/sandbox environments
- SHA256 deduplication prevents storage exhaustion attacks
- File size limited to 100 MB per upload (configurable)

## Forensic Logging

All events are logged to `honeypot_forensics.log` in JSON-Lines format with proper sanitization:

```json
{"timestamp_ms": 1234567890, "type": "CONNECTION_START", "session_id": "192.168.1.100_1234567890", "data": {"ip": "192.168.1.100", "port": 54321, "protocol": "SSH"}}
{"timestamp_ms": 1234567891, "type": "COMMAND_EXEC", "session_id": "192.168.1.100_1234567890", "data": {"command_input": "whoami", "status": "SUCCESS", "output_length": 5, "latency_ms": 87}}
{"timestamp_ms": 1234567892, "type": "SCP_FILE_UPLOAD", "session_id": "192.168.1.100_1234567890", "data": {"filename": "malware.sh", "size_bytes": 1024, "sha256": "abc123...", "target_path": "/tmp/"}}
```

**Log Security Features:**
- Newlines escaped to prevent log injection
- Null bytes and control characters removed
- Entry size limited to 64 KB
- UTF-8 encoding with proper escaping

## Console Monitoring

The system provides a real-time ANSI-colored console display showing:

- Active session count
- Last 20 commands executed across all sessions
- System status and log file location

The console refreshes every 2 seconds to provide live visibility into honeypot activity.

## Extending the System

### Adding a New Protocol Handler

1. Create a class inheriting from `BaseProtocolHandler`
2. Implement `async def run_emulation(self)`
3. Register in `PROTOCOL_HANDLERS` dict
4. Add configuration to `config_connection.json`

Example:

```python
from base_handler import BaseProtocolHandler
from network_handler import PROTOCOL_HANDLERS

class FTPSimulator(BaseProtocolHandler):
    async def run_emulation(self):
        await self._start_session("FTP")
        # Protocol emulation logic here
        await self._close_connection()

PROTOCOL_HANDLERS['ftp'] = FTPSimulator
```




## Security & Legal Notice

**This is a defensive security tool.**

SSHPot is designed for:
- Research on attacker behavior and tactics
- Early warning system for network intrusions
- Security training and education
- Threat intelligence gathering

**Important:**
- The system is intentionally designed to NEVER execute attacker commands
- Deploy only on networks you own or have explicit permission to monitor
- Ensure compliance with local laws regarding network monitoring
- Review logs regularly as they may contain sensitive information
- All uploaded files are stored in quarantine and should be analyzed in isolated environments





---

**Warning**: This is a honeypot system. It will attract and log malicious activity. Deploy responsibly.
