# igris

**Security scanner for AI agent workflows.**

Find vulnerabilities in LangChain, CrewAI, OpenAI Agents SDK, and other AI agent frameworks before attackers do.

[![PyPI](https://img.shields.io/pypi/v/igris.svg)](https://pypi.org/project/igris/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What It Does

igris connects to running AI agents and tests them for security vulnerabilities:

- **Prompt Injection** — Can attackers override the agent's instructions?
- **System Prompt Extraction** — Can attackers leak the agent's configuration?
- **Jailbreaks** — Can attackers bypass safety guardrails?
- **Tool Abuse** — Can attackers make the agent misuse its tools?
- **Multi-Turn Escalation** — Can attackers manipulate the agent over conversation?

## Quick Start

```bash
# Install
pip install igris

# Scan an agent
igris scan --http http://localhost:8000/chat

# Map agent capabilities
igris map --http http://localhost:8000/chat
```

## Example Output

```
🔒 Scan Starting
Target: http://localhost:8000/chat
✓ Connected successfully

Discovering agent capabilities...
File Access:      ✓
Code Execution:   ✓
Web Access:       ✗
Memory:           ✓

Running security scans...

🚨 Found 4 Vulnerabilities
Critical: 1  High: 2  Medium: 1  Low: 0

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Severity ┃ Title                    ┃ Category         ┃ Confidence ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ CRITICAL │ Dangerous Tool Execution │ tool_abuse       │ confirmed  │
│ HIGH     │ System Prompt Extraction │ prompt_injection │ likely     │
│ HIGH     │ Multi-Turn Escalation    │ multi_turn       │ confirmed  │
│ MEDIUM   │ Potential Override       │ prompt_injection │ possible   │
└──────────┴──────────────────────────┴──────────────────┴────────────┘
```

## Installation

```bash
pip install igris
```

Or with AI-powered analysis:

```bash
pip install igris[ai]
```

## Usage

### Scan an Agent

```bash
# Basic scan
igris scan --http http://localhost:8000/chat

# With authentication
igris scan --http https://api.example.com/agent --auth "Bearer sk-xxx"

# Save report
igris scan --http http://localhost:8000/chat --output report.json

# Verbose output
igris scan --http http://localhost:8000/chat --verbose
```

### Map Agent Architecture

```bash
# Discover what the agent can do
igris map --http http://localhost:8000/chat
```

## Supported Frameworks

igris works with any AI agent that exposes an HTTP endpoint:

- ✅ LangChain / LangGraph
- ✅ CrewAI
- ✅ OpenAI Agents SDK
- ✅ AutoGen
- ✅ Custom agents

## Why igris?

Traditional security tools test **code**. igris tests **behavior**.

AI agents make decisions at runtime. They interpret instructions, choose tools, and act on user input. Static analysis can't find these bugs — you need to actually **talk to the agent** and see what it does.

igris does exactly that: sends adversarial inputs, observes agent behavior, and reports when the agent does something dangerous.

## From the Creator of mcpsec

igris is built by the creator of [mcpsec](https://github.com/manthanghasadiya/mcpsec), which has reported 12+ vulnerabilities ranging from Medium to Critical severity in popular MCP implementations.

Same approach, one layer up: mcpsec tests MCP servers (the transport layer), igris tests agent workflows (the orchestration layer).

## License

MIT

## Author

**Manthan Ghasadiya**
- GitHub: [@manthanghasadiya](https://github.com/manthanghasadiya)
- LinkedIn: [linkedin.com/in/man-ghasadiya](https://linkedin.com/in/man-ghasadiya)
