'use strict';
// Host adapters for the pre-install guard.
//
// claudeCodePreToolUse: a Claude Code PreToolUse hook for the Bash tool.
// Register it in .claude/settings.json (see README, "Pre-install guard").
// It reads the hook event JSON on stdin and returns the hook output object,
// or null to stay silent.
//
// It never returns "allow". A clean result must not let a command skip the
// person's own permission prompt: the guard can only add friction ("ask")
// or block ("deny"), never remove it.
//
// VERIFY BEFORE RELYING ON IT: written against the PreToolUse format as
// documented when this was built (tool_name, tool_input.command in;
// hookSpecificOutput.permissionDecision out). Check the current Claude Code
// hooks documentation, and run the scenario in demo/ against a real session.
const G = require('./guard.js');

async function claudeCodePreToolUse(stdinText, argvMode, env, opts) {
  let mode;
  try { mode = G.modeFrom(argvMode, env); } catch (e) { return out('deny', 'SaveSaveSaveSave guard is misconfigured: ' + e.message); }
  let ev;
  try { ev = JSON.parse(stdinText || '{}'); } catch (_) {
    return mode === 'observe' ? null : out(mode === 'strict' ? 'deny' : 'ask', 'SaveSaveSaveSave guard could not read the hook event.');
  }
  if (!ev || ev.tool_name !== 'Bash') return null;
  const command = ev.tool_input && typeof ev.tool_input.command === 'string' ? ev.tool_input.command : '';
  if (!G.parseInstalls(command).length) return null;
  let res;
  try {
    res = await G.guardCommand(command, mode, Object.assign({ cwd: ev.cwd || undefined }, opts || {}));
  } catch (e) {
    if (mode === 'observe') return null;
    return out(mode === 'strict' ? 'deny' : 'ask', 'SaveSaveSaveSave guard could not complete its check (' + String((e && e.message) || e).slice(0, 200) + ').');
  }
  if (res.decision === 'deny') return out('deny', G.explain(res));
  if (res.decision === 'review') return out('ask', G.explain(res));
  return null;   // allow: say nothing, the normal permission flow applies
}

function out(permissionDecision, reason) {
  return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision, permissionDecisionReason: reason } };
}

module.exports = { claudeCodePreToolUse };
