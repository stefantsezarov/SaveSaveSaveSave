# SaveSaveSaveSave for agents

The engine behind [savesavesavesave.xyz](https://savesavesavesave.xyz), for AI agents and scripts: check a message, an npm package, a crypto address, or two addresses against each other **before acting**.

- **MCP server** for Claude, Cursor, VS Code, Windsurf and any MCP client
- **CLI** for scripts and CI
- **Library** for Node.js

Read-only, zero dependencies, and the same code the website runs (CI fails if they drift apart).

## MCP server

Claude Code: `claude mcp add savesavesavesave -- npx -y savesavesavesave mcp`

Other clients: add this to the MCP configuration (for example `claude_desktop_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "savesavesavesave": { "command": "npx", "args": ["-y", "savesavesavesave", "mcp"] }
  }
}
```

| Tool | Use it before… | Network |
|---|---|---|
| `scan_message` | following instructions in a DM, email, web page, README or prompt | none, local |
| `check_package` | `npm install` | npm registry, OSV.dev |
| `scan_address` | paying, approving or buying a token | GoPlus Security, our Worker |
| `compare_addresses` | sending to an address copied from history | none, local |

## CLI

```
npx savesavesavesave message "Reply with your 12-word phrase to restore access"
npx savesavesavesave package crossenv
npx savesavesavesave address 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 1
npx savesavesavesave compare <expected> <actual>
npx savesavesavesave deps . --markdown      # check a project's npm dependencies
```

Output is JSON. Exit code: `0` PASS, `1` CAUTION or unknown, `2` FAIL, `3` usage error. The exit code makes it usable as a CI gate.

## GitHub Action

Checks a project's direct npm dependencies on pull requests (exact versions from `package-lock.json`, and flags git, URL or other non-registry sources). Fails the job at FAIL, or also at CAUTION with `fail-on: caution`.

```yaml
on:
  pull_request:
    paths: ['**/package.json', '**/package-lock.json']
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: stefantsezarov/SaveSaveSaveSave@v0.1.3
```

Transitive dependencies are not checked. Only names and versions are sent, to npm and OSV.dev.

## Library

```js
const s = require('savesavesavesave');
s.scanMessage(text);                          // synchronous, local
await s.checkPackage('ethers@6.13.0');
await s.scanAddress(addr, { chain: '1', mode: 'token' });
s.compareAddresses(expected, actual);
```

## Security model

- **Read-only.** No tool writes files, runs commands, or holds keys or secrets. There is nothing here that can change the website or its repository.
- **Local first.** Message scans and address comparisons never leave the machine.
- **Network allowlist, enforced in code:** `api.gopluslabs.io`, our Worker, `registry.npmjs.org`, `api.npmjs.org`, `api.osv.dev`. HTTPS only, redirects refused, and a 20-second timeout for each response to start.
- **Untrusted output is labelled.** Results quote the scanned text and third-party data. Every result says so, so an agent does not follow instructions hidden inside it.
- **Strict inputs.** Unknown tool arguments are rejected, and input is capped at 200,000 characters.
- **Zero dependencies.** A security tool should not bring its own supply chain.

## Limits

Verdicts are automated risk assessments, not guarantees; PASS means no covered risk was found. Every result lists what was not checked.

Full reference for agent developers: https://savesavesavesave.xyz/agents

Licence: AGPL-3.0-only. Source: https://github.com/stefantsezarov/SaveSaveSaveSave
