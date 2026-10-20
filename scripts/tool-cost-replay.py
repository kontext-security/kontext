"""Replay a two-prompt Claude Code session through the real kontext hook binary.

Used by `scripts/tool-cost-local.sh probe-replay` when no signed-in agent is at
hand. Writes transcript rows in Claude Code's format with real-time timestamps
and invokes `kontext hook <alias>` on the isolated collector socket in Claude
Code's order: a prompt row is written, then its UserPromptSubmit hook fires
(measured: the hook follows the row by about 20 ms). The session has a turn from
before the install (no hooks), a prompt running one Bash call, and a prompt
running a subagent whose sidechain transcript is its own file, registered at
SubagentStop as Claude Code does. Prints the session ID.
"""
import datetime
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

state = Path(sys.argv[1])
socket = (state / 'socket-path').read_text().strip()
kontext = state / 'kontext'
session = str(uuid.uuid4())
replay = state / 'replay'
transcript = replay / (session + '.jsonl')
agent_file = replay / session / 'subagents' / 'agent-a1.jsonl'
agent_file.parent.mkdir(parents=True, exist_ok=True)
cwd = str(state / 'project')


def ts(offset=0.0):
    at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=offset)
    return at.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def append(path, row):
    with open(path, 'a') as f:
        f.write(json.dumps(row) + '\n')


def hook(alias, payload):
    payload = {'session_id': session, 'transcript_path': str(transcript), 'cwd': cwd,
               'permission_mode': 'default', **payload}
    subprocess.run([str(kontext), 'hook', alias, '--agent', 'claude', '--mode', 'observe', '--socket', socket],
                   input=json.dumps(payload), text=True, capture_output=True, check=True)


def user(text, at=None, sidechain=False):
    return {'type': 'user', 'sessionId': session, 'timestamp': at or ts(), 'isSidechain': sidechain,
            'message': {'role': 'user', 'content': text}}


def result(tool, at=None, sidechain=False):
    return {'type': 'user', 'sessionId': session, 'timestamp': at or ts(), 'isSidechain': sidechain,
            'message': {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': tool, 'content': 'ok'}]}}


def assistant(message, content, at=None, sidechain=False):
    return {'type': 'assistant', 'sessionId': session, 'requestId': 'req_' + message, 'timestamp': at or ts(),
            'isSidechain': sidechain,
            'message': {'id': message, 'model': 'claude-fable-5-1', 'type': 'message', 'role': 'assistant',
                        'content': content,
                        'usage': {'input_tokens': 3, 'cache_creation_input_tokens': 1200, 'cache_read_input_tokens': 30000,
                                  'output_tokens': 40, 'service_tier': 'standard',
                                  'cache_creation': {'ephemeral_1h_input_tokens': 1200, 'ephemeral_5m_input_tokens': 0}}}}


def tool_use(tool, name, tool_input):
    return [{'type': 'tool_use', 'id': tool, 'name': name, 'input': tool_input}]


# A turn from before the install: no hooks fired for it.
append(transcript, user('what does the cost summary endpoint return?', ts(-3600)))
append(transcript, assistant('msg_prefix_1', tool_use('toolu_prefix', 'Read', {'file_path': 'README.md'}), ts(-3599)))
append(transcript, result('toolu_prefix', ts(-3598)))
append(transcript, assistant('msg_prefix_2', [{'type': 'text', 'text': 'It sums usage.'}], ts(-3597)))

hook('session-start', {'hook_event_name': 'SessionStart', 'source': 'resume'})

# Prompt 1: one Bash call.
first = 'Use Bash exactly once to execute: printf kontext-cost-local-probe. Do not read files or run other commands. After seeing the output, reply only OK.'
append(transcript, user(first))
hook('user-prompt-submit', {'hook_event_name': 'UserPromptSubmit', 'prompt': first})
command = {'command': 'printf kontext-cost-local-probe', 'description': 'Print the probe marker'}
append(transcript, assistant('msg_1', tool_use('toolu_1', 'Bash', command)))
hook('pre-tool-use', {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash', 'tool_input': command, 'tool_use_id': 'toolu_1'})
append(transcript, result('toolu_1'))
hook('post-tool-use', {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash', 'tool_input': command, 'tool_use_id': 'toolu_1',
                       'tool_response': {'stdout': 'kontext-cost-local-probe', 'stderr': '', 'interrupted': False}})
append(transcript, assistant('msg_2', [{'type': 'text', 'text': 'OK'}]))
hook('stop', {'hook_event_name': 'Stop', 'stop_hook_active': False})

time.sleep(2)

# Prompt 2: a subagent with its own sidechain transcript.
second = 'Use a subagent to search the repository for TODO comments in the cost summary code, then explain in one sentence what the first output meant.'
append(transcript, user(second))
hook('user-prompt-submit', {'hook_event_name': 'UserPromptSubmit', 'prompt': second})
task = {'description': 'Find TODOs', 'prompt': 'Search for TODO comments in the cost summary code and report them.', 'subagent_type': 'Explore'}
append(transcript, assistant('msg_3', tool_use('toolu_3', 'Task', task)))
hook('pre-tool-use', {'hook_event_name': 'PreToolUse', 'tool_name': 'Task', 'tool_input': task, 'tool_use_id': 'toolu_3'})
grep = {'pattern': 'TODO', 'path': '.'}
append(agent_file, user(task['prompt'], sidechain=True))
append(agent_file, assistant('msg_3s', tool_use('toolu_3s', 'Grep', grep), sidechain=True))
hook('pre-tool-use', {'hook_event_name': 'PreToolUse', 'tool_name': 'Grep', 'tool_input': grep, 'tool_use_id': 'toolu_3s', 'agent_id': 'a1', 'agent_type': 'Explore'})
append(agent_file, result('toolu_3s', sidechain=True))
hook('post-tool-use', {'hook_event_name': 'PostToolUse', 'tool_name': 'Grep', 'tool_input': grep, 'tool_use_id': 'toolu_3s', 'agent_id': 'a1', 'agent_type': 'Explore',
                       'tool_response': {'numFiles': 0}})
append(agent_file, assistant('msg_3s2', [{'type': 'text', 'text': 'No TODO comments.'}], sidechain=True))
hook('subagent-stop', {'hook_event_name': 'SubagentStop', 'agent_id': 'a1', 'agent_type': 'Explore', 'agent_transcript_path': str(agent_file), 'stop_hook_active': False})
append(transcript, result('toolu_3'))
hook('post-tool-use', {'hook_event_name': 'PostToolUse', 'tool_name': 'Task', 'tool_input': task, 'tool_use_id': 'toolu_3',
                       'tool_response': {'content': [{'type': 'text', 'text': 'No TODO comments.'}]}})
append(transcript, assistant('msg_4', [{'type': 'text', 'text': 'There are no TODOs; the first output was the probe marker.'}]))
hook('stop', {'hook_event_name': 'Stop', 'stop_hook_active': False})
hook('session-end', {'hook_event_name': 'SessionEnd', 'reason': 'other'})
print(session)
