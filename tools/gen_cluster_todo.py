#!/usr/bin/env python3
import pathlib
import re
from datetime import datetime, timezone

ROOT = pathlib.Path('/workspaces/matterproxy/matter-dissector_ws4.6.3')
INC = ROOT / 'im_name_tables.inc'
OUT = ROOT / 'docs' / 'CLUSTER_TODO.md'

CLUSTER_LINE_RE = re.compile(r'\{\s*0x([0-9A-Fa-f]{8})\s*,\s*"([^"]+)"\s*\},')

# These are already done globally in current branch.
GLOBAL_DONE = {
    'path_name_mapping': True,
}

# Seed known cluster-specific state.
# Keep conservative: only mark payload-level work done when fully implemented.
CLUSTER_SEED = {
    'OnOff': {
        'path_decode': True,
        'attribute_payload_decode': False,
        'command_payload_decode': False,
        'event_payload_decode': False,
    },
}


def parse_clusters():
    clusters = []
    text = INC.read_text(encoding='utf-8')
    in_cluster_table = False
    for line in text.splitlines():
        if line.strip().startswith('static const ClusterNameEntry kClusterNameTable[]'):  # begin
            in_cluster_table = True
            continue
        if in_cluster_table and line.strip() == '};':
            break
        if in_cluster_table:
            m = CLUSTER_LINE_RE.search(line)
            if m:
                cid = int(m.group(1), 16)
                name = m.group(2)
                clusters.append((cid, name))
    return clusters


def checkbox(v: bool) -> str:
    return '[x]' if v else '[ ]'


def main():
    clusters = parse_clusters()
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
        attr_decode = seed.get('attribute_payload_decode', False)
        cmd_decode = seed.get('command_payload_decode', False)
        evt_decode = seed.get('event_payload_decode', False)

        lines.append(f'### {name} (`0x{cid:08X}`)')
        lines.append(f'- {checkbox(path_decode)} Path decode')
        lines.append(f'- {checkbox(attr_decode)} Attribute payload')
        lines.append(f'- {checkbox(cmd_decode)} Command payload')
        lines.append(f'- {checkbox(evt_decode)} Event payload')
        lines.append('')

    OUT.write_text('\n'.join(lines), encoding='utf-8')


if __name__ == '__main__':
    main()
