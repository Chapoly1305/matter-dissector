#!/usr/bin/env python3
import pathlib
import re
from datetime import datetime, timezone

ROOT = pathlib.Path('/workspaces/matterproxy/matter-dissector_ws4.6.3')
INC = ROOT / 'im_name_tables.inc'
OUT = ROOT / 'docs' / 'CLUSTER_TODO.md'

CLUSTER_LINE_RE = re.compile(r'\{\s*0x([0-9A-Fa-f]{8})\s*,\s*"([^"]+)"\s*\},')
SCOPED_LINE_RE = re.compile(r'\{\s*0x([0-9A-Fa-f]{8})\s*,\s*0x([0-9A-Fa-f]{8})\s*,\s*"([^"]+)"\s*\},')
FIELD_LINE_RE = re.compile(r'\{\s*0x([0-9A-Fa-f]{8})\s*,\s*0x([0-9A-Fa-f]{8})\s*,\s*(\d+)\s*,\s*"([^"]+)"\s*\},')
COMMAND_FIELD_LINE_RE = re.compile(
    r'\{\s*0x([0-9A-Fa-f]{8})\s*,\s*0x([0-9A-Fa-f]{8})\s*,\s*(\d+)\s*,\s*(true|false)\s*,\s*"([^"]+)"\s*\},'
)

# These are already done globally in current branch.
GLOBAL_DONE = {
    'path_name_mapping': True,
    # IM attribute payload parser supports primitive typed values globally.
    'attribute_payload_generic_decode': True,
    # IM command payload parser supports field-name decode where command field tables exist.
    'command_payload_generic_decode': True,
    # IM event payload parser supports field-name decode where event field tables exist.
    'event_payload_generic_decode': True,
}

CLUSTER_SEED = {}


def parse_table_entries(text: str, table_header: str, line_re: re.Pattern):
    entries = []
    in_table = False
    for line in text.splitlines():
        if line.strip().startswith(table_header):
            in_table = True
            continue
        if in_table and line.strip() == '};':
            break
        if in_table:
            m = line_re.search(line)
            if m:
                entries.append(m.groups())
    return entries


def parse_state():
    text = INC.read_text(encoding='utf-8')

    cluster_entries = parse_table_entries(text, 'static const ClusterNameEntry kClusterNameTable[]', CLUSTER_LINE_RE)
    attribute_name_entries = parse_table_entries(text, 'static const ScopedNameEntry kAttributeNameTable[]', SCOPED_LINE_RE)
    command_name_entries = parse_table_entries(text, 'static const ScopedNameEntry kCommandNameTable[]', SCOPED_LINE_RE)
    command_field_entries = parse_table_entries(
        text, 'static const CommandFieldNameEntry kCommandFieldNameTable[]', COMMAND_FIELD_LINE_RE
    )
    event_name_entries = parse_table_entries(text, 'static const ScopedNameEntry kEventNameTable[]', SCOPED_LINE_RE)
    event_field_entries = parse_table_entries(text, 'static const EventFieldNameEntry kEventFieldNameTable[]', FIELD_LINE_RE)
    attribute_struct_field_entries = parse_table_entries(
        text, 'static const AttributeStructFieldNameEntry kAttributeStructFieldNameTable[]', FIELD_LINE_RE
    )
    attribute_enum_value_entries = parse_table_entries(
        text, 'static const AttributeEnumValueNameEntry kAttributeEnumValueNameTable[]',
        re.compile(r'\{\s*0x([0-9A-Fa-f]{8})\s*,\s*0x([0-9A-Fa-f]{8})\s*,\s*(\d+)\s*,\s*"([^"]+)"\s*\},')
    )

    clusters = [(int(cid, 16), name) for cid, name in cluster_entries]
    clusters.sort(key=lambda x: x[0])

    clusters_with_attributes = {int(cid, 16) for cid, _attrid, _name in attribute_name_entries}
    clusters_with_commands = {int(cid, 16) for cid, _cmdid, _name in command_name_entries}
    clusters_with_events = {int(cid, 16) for cid, _evid, _name in event_name_entries}
    clusters_with_command_fields = {int(cid, 16) for cid, _cmdid, _tag, _is_req, _name in command_field_entries}
    clusters_with_event_fields = {int(cid, 16) for cid, _evid, _tag, _name in event_field_entries}
    clusters_with_attribute_struct_fields = {int(cid, 16) for cid, _attrid, _tag, _name in attribute_struct_field_entries}
    clusters_with_attribute_enum_values = {int(cid, 16) for cid, _attrid, _value, _name in attribute_enum_value_entries}

    return {
        'clusters': clusters,
        'clusters_with_attributes': clusters_with_attributes,
        'clusters_with_commands': clusters_with_commands,
        'clusters_with_events': clusters_with_events,
        'clusters_with_command_fields': clusters_with_command_fields,
        'clusters_with_event_fields': clusters_with_event_fields,
        'clusters_with_attribute_struct_fields': clusters_with_attribute_struct_fields,
        'clusters_with_attribute_enum_values': clusters_with_attribute_enum_values,
    }


def checkbox(v: bool) -> str:
    return '[x]' if v else '[ ]'


def main():
    state = parse_state()
    clusters = state['clusters']
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    lines = []
    lines.append('# Cluster Completion TODO (Matter v1.5)')
    lines.append('')
    lines.append(f'Generated at: `{now}`')
    lines.append('')
    lines.append('## Scope')
    lines.append('- Source baseline: `connectedhomeip v1.5-branch`')
    lines.append('- Tracking target: `ws-4.6.3` full IM/cluster parsing completion')
    lines.append('')
    lines.append('## Global Status')
    lines.append(f'- {checkbox(GLOBAL_DONE["path_name_mapping"])} Full cluster/attribute/command/event ID-to-name mapping in IM paths')
    lines.append(f'- {checkbox(GLOBAL_DONE["attribute_payload_generic_decode"])} Generic IM attribute payload decode (primitive typed values)')
    lines.append(f'- {checkbox(GLOBAL_DONE["command_payload_generic_decode"])} Generic IM command payload decode with field-name mapping')
    lines.append(f'- {checkbox(GLOBAL_DONE["event_payload_generic_decode"])} Generic IM event payload decode with field-name mapping')
    lines.append('')
    lines.append('## Per-Cluster Checklist')
    lines.append('Legend:')
    lines.append('- `Path decode`: Cluster/Attribute/Command/Event path IDs decoded to names')
    lines.append('- `Attribute payload`: Attribute data/status payload fields decoded structurally')
    lines.append('- `Command payload`: Command request/response payload fields decoded structurally')
    lines.append('- `Event payload`: Event payload fields decoded structurally')
    lines.append('')

    for cid, name in clusters:
        seed = CLUSTER_SEED.get(name, {})
        path_decode = seed.get('path_decode', True)

        if 'attribute_payload_decode' in seed:
            attr_decode = seed['attribute_payload_decode']
        else:
            # If no attributes exist, treat as N/A complete.
            attr_decode = (cid not in state['clusters_with_attributes']) or GLOBAL_DONE['attribute_payload_generic_decode']

        if 'command_payload_decode' in seed:
            cmd_decode = seed['command_payload_decode']
        else:
            # If commands exist, generic command payload decode applies; command-field names are available where table entries exist.
            cmd_decode = (cid not in state['clusters_with_commands']) or GLOBAL_DONE['command_payload_generic_decode']

        if 'event_payload_decode' in seed:
            evt_decode = seed['event_payload_decode']
        else:
            # If events exist, generic event payload decode applies; event-field names are available where table entries exist.
            evt_decode = (cid not in state['clusters_with_events']) or GLOBAL_DONE['event_payload_generic_decode']

        lines.append(f'### {name} (`0x{cid:08X}`)')
        lines.append(f'- {checkbox(path_decode)} Path decode')
        lines.append(f'- {checkbox(attr_decode)} Attribute payload')
        lines.append(f'- {checkbox(cmd_decode)} Command payload')
        lines.append(f'- {checkbox(evt_decode)} Event payload')
        lines.append('')

    OUT.write_text('\n'.join(lines), encoding='utf-8')


if __name__ == '__main__':
    main()
