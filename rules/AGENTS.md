# Agent Guidelines for agy-auto

When `agy-auto` is active, tool calls are gated by an intelligent multi-layer security policy.

## Handling Denied Commands

If a tool call is denied, the response will contain `tool call denied by pre-tool hook: [agy-auto/<layer>] ...`:

1. **Do not retry identical or trivial variations** of a blocked command. Retrying triggers escalation counters.
2. **Explain clearly to the user**:
   - What command or action was blocked.
   - Why you intended to run it and what step of the task it fulfills.
3. **Conversational Approval**:
   - For commands blocked under grey-area policies (such as package installs or build scripts), the user can approve the action simply by replying in the chat (e.g., `> i approve` or `> yes, proceed`).
   - Once approved, rerun the command.
4. **Hard-Deny Boundaries**:
   - Actions touching credentials (`~/.ssh`, `.env`, OAuth tokens), system disks/partitions, `sudo`, or destructive deletes outside the workspace cannot be approved conversationally and must be executed by the user directly in their terminal if required.
