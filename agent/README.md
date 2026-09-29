# SaveSaveSaveSave for agents

The engine behind [savesavesavesave.xyz](https://savesavesavesave.xyz), for AI agents and scripts: check a message, an npm package, a crypto address, or two addresses against each other **before acting**.

- **MCP server** for Claude, Cursor, VS Code, Windsurf and any MCP client
- **CLI** for scripts and CI
- **Library** for Node.js

Read-only, zero dependencies, and the same code the website runs (CI fails if they drift apart).

## MCP server

Add this to your client's MCP configuration (for example `claude_desktop_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "savesavesavesave": { "command": "npx", "args": ["-y", "savesavesavesave", "mcp"] }
  }
}
```

Before the npm release, run it from a clone of the repository instead:

```json
{ "mcpServers": { "savesavesavesave": { "command": "node", "args": ["/path/to/SaveSaveSaveSave/agent/mcp-server.js"] } } }
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
```

Output is JSON. Exit code: `0` PASS, `1` CAUTION or unknown, `2` FAIL, `3` usage error. The exit code makes it usable as a CI gate.

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
- **Network allowlist, enforced in code:** `api.gopluslabs.io`, our Worker, `registry.npmjs.org`, `api.npmjs.org`, `api.osv.dev`. HTTPS only, redirects refused, 20-second timeout.
- **Untrusted output is labelled.** Results quote the scanned text and third-party data. Every result says so, so an agent does not follow instructions hidden inside it.
- **Strict inputs.** Unknown tool arguments are rejected, and input is capped at 200,000 characters.
- **Zero dependencies.** A security tool should not bring its own supply chain.

## Limits

Verdicts are automated risk assessments, not guarantees; PASS means no covered risk was found. Every result lists what was not checked.

Licence: AGPL-3.0-only. Source: https://github.com/stefantsezarov/SaveSaveSaveSave
