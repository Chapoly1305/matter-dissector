#!/usr/bin/env python3
import pathlib
import re

CHIP_CLUSTERS_DIR = pathlib.Path('/workspaces/matterproxy/connectedhomeip/zzz_generated/app-common/clusters')
OUT_FILE = pathlib.Path('/workspaces/matterproxy/matter-dissector_ws4.6.3/im_name_tables.inc')

CLUSTER_ID_RE = re.compile(r"inline\s+constexpr\s+ClusterId\s+Id\s*=\s*(0x[0-9A-Fa-f]+)\s*;")
ITEM_RE_TEMPLATE = r"namespace\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{{\s*inline\s+constexpr\s+{kind}\s+Id\s*=\s*(0x[0-9A-Fa-f]+)\s*;"
FIELDS_BLOCK_RE = re.compile(
    r"namespace\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{[^{}]*?enum\s+class\s+Fields\s*:\s*uint8_t\s*\{(.*?)\};",
    re.MULTILINE | re.DOTALL,
)
FIELD_ENTRY_RE = re.compile(r"\bk([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9A-Fa-f]+|\d+)")
ACCEPTED_COMMAND_RE = re.compile(
    r"namespace\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{\s*inline\s+constexpr\s+DataModel::AcceptedCommandEntry",
    re.MULTILINE,
)
ATTR_TYPEINFO_BLOCK_RE = re.compile(
    r"namespace\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{\s*struct\s+TypeInfo\s*\{(.*?)\};\s*\}\s*//\s*namespace\s+[A-Za-z_][A-Za-z0-9_]*",
    re.MULTILINE | re.DOTALL,
)
STRUCT_TYPE_IN_BLOCK_RE = re.compile(
    r"using\s+Type\s*=\s*chip::app::Clusters::[A-Za-z0-9_]+::Structs::([A-Za-z_][A-Za-z0-9_]*)::Type\s*;",
    re.MULTILINE,
)
ATTR_ENUM_TYPE_IN_BLOCK_RE = re.compile(
    r"using\s+Type\s*=\s*chip::app::Clusters::[A-Za-z0-9_]+::([A-Za-z_][A-Za-z0-9_]*)\s*;",
    re.MULTILINE,
)
ATTR_NULLABLE_ENUM_TYPE_IN_BLOCK_RE = re.compile(
    r"using\s+Type\s*=\s*chip::app::DataModel::Nullable<\s*chip::app::Clusters::[A-Za-z0-9_]+::([A-Za-z_][A-Za-z0-9_]*)\s*>\s*;",
    re.MULTILINE,
)
ENUM_BLOCK_RE = re.compile(
    r"enum\s+class\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[A-Za-z0-9_:<>]+\s*\{(.*?)\};",
    re.MULTILINE | re.DOTALL,
)
ENUM_ENTRY_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,")

ATTR_RE = re.compile(ITEM_RE_TEMPLATE.format(kind='AttributeId'), re.MULTILINE)
CMD_RE = re.compile(ITEM_RE_TEMPLATE.format(kind='CommandId'), re.MULTILINE)
EVT_RE = re.compile(ITEM_RE_TEMPLATE.format(kind='EventId'), re.MULTILINE)


def parse_cluster(cluster_dir: pathlib.Path):
    cluster_id_h = cluster_dir / 'ClusterId.h'
    m = CLUSTER_ID_RE.search(cluster_id_h.read_text(encoding='utf-8', errors='ignore'))
    if not m:
        return None

    cluster_id = int(m.group(1), 16)
    cluster_name = cluster_dir.name

    attrs = []
    cmds = []
    evts = []
    cmd_fields = []
    evt_fields = []
    attr_struct_fields = []
    attr_enum_values = []

    attr_h = cluster_dir / 'AttributeIds.h'
    attr_name_to_id = {}
    if attr_h.exists():
        text = attr_h.read_text(encoding='utf-8', errors='ignore')
        for name, hexid in ATTR_RE.findall(text):
            attr_id = int(hexid, 16)
            attrs.append((attr_id, name))
            attr_name_to_id[name] = attr_id

    attributes_h = cluster_dir / 'Attributes.h'
    attr_struct_name_by_id = {}
    attr_enum_name_by_id = {}
    if attributes_h.exists() and attr_name_to_id:
        text = attributes_h.read_text(encoding='utf-8', errors='ignore')
        for attr_name, block in ATTR_TYPEINFO_BLOCK_RE.findall(text):
            attr_id = attr_name_to_id.get(attr_name)
            if attr_id is None:
                continue

            m_struct = STRUCT_TYPE_IN_BLOCK_RE.search(block)
            if m_struct:
                struct_name = m_struct.group(1)
                attr_struct_name_by_id[attr_id] = struct_name

            m_enum = ATTR_ENUM_TYPE_IN_BLOCK_RE.search(block)
            if m_enum:
                attr_enum_name_by_id[attr_id] = m_enum.group(1)
                continue

            m_nullable_enum = ATTR_NULLABLE_ENUM_TYPE_IN_BLOCK_RE.search(block)
            if m_nullable_enum:
                attr_enum_name_by_id[attr_id] = m_nullable_enum.group(1)

    structs_h = cluster_dir / 'Structs.h'
    if structs_h.exists() and attr_struct_name_by_id:
        text = structs_h.read_text(encoding='utf-8', errors='ignore')
        struct_fields = {}
        for struct_name, fields_block in FIELDS_BLOCK_RE.findall(text):
            if struct_name not in struct_fields:
                struct_fields[struct_name] = []
            for field_name, field_tag_raw in FIELD_ENTRY_RE.findall(fields_block):
                field_tag = int(field_tag_raw, 0)
                struct_fields[struct_name].append((field_tag, field_name))

        for attr_id, struct_name in attr_struct_name_by_id.items():
            for field_tag, field_name in struct_fields.get(struct_name, []):
                attr_struct_fields.append((attr_id, field_tag, field_name))

    enums_h = cluster_dir / 'Enums.h'
    if enums_h.exists() and attr_enum_name_by_id:
        text = enums_h.read_text(encoding='utf-8', errors='ignore')
        enum_values_by_name = {}
        for enum_name, enum_block in ENUM_BLOCK_RE.findall(text):
            values = []
            for entry_name, entry_value_raw in ENUM_ENTRY_RE.findall(enum_block):
                values.append((int(entry_value_raw, 0), entry_name))
            if values:
                enum_values_by_name[enum_name] = values

        for attr_id, enum_name in attr_enum_name_by_id.items():
            for enum_value, enum_entry_name in enum_values_by_name.get(enum_name, []):
                label = enum_entry_name[1:] if enum_entry_name.startswith('k') and len(enum_entry_name) > 1 else enum_entry_name
                attr_enum_values.append((attr_id, enum_value, label))

    cmd_h = cluster_dir / 'CommandIds.h'
    cmd_name_to_id = {}
    if cmd_h.exists():
        text = cmd_h.read_text(encoding='utf-8', errors='ignore')
        for name, hexid in CMD_RE.findall(text):
            cmd_id = int(hexid, 16)
            cmds.append((cmd_id, name))
            cmd_name_to_id[name] = cmd_id

    accepted_commands = set()
    metadata_h = cluster_dir / 'Metadata.h'
    if metadata_h.exists():
        metadata_text = metadata_h.read_text(encoding='utf-8', errors='ignore')
        accepted_commands = set(ACCEPTED_COMMAND_RE.findall(metadata_text))

    commands_h = cluster_dir / 'Commands.h'
    if commands_h.exists() and cmd_name_to_id:
        text = commands_h.read_text(encoding='utf-8', errors='ignore')
        for cmd_name, fields_block in FIELDS_BLOCK_RE.findall(text):
            cmd_id = cmd_name_to_id.get(cmd_name)
            if cmd_id is None:
                continue
            is_request = True
            if accepted_commands:
                is_request = cmd_name in accepted_commands
            elif cmd_name.endswith('Response'):
                is_request = False
            for field_name, field_tag_raw in FIELD_ENTRY_RE.findall(fields_block):
                field_tag = int(field_tag_raw, 0)
                cmd_fields.append((cmd_id, field_tag, field_name, is_request))

    evt_h = cluster_dir / 'EventIds.h'
    evt_name_to_id = {}
    if evt_h.exists():
        text = evt_h.read_text(encoding='utf-8', errors='ignore')
        for name, hexid in EVT_RE.findall(text):
            evt_id = int(hexid, 16)
            evts.append((evt_id, name))
            evt_name_to_id[name] = evt_id

    events_h = cluster_dir / 'Events.h'
    if events_h.exists() and evt_name_to_id:
        text = events_h.read_text(encoding='utf-8', errors='ignore')
        for evt_name, fields_block in FIELDS_BLOCK_RE.findall(text):
            evt_id = evt_name_to_id.get(evt_name)
            if evt_id is None:
                continue
            for field_name, field_tag_raw in FIELD_ENTRY_RE.findall(fields_block):
                field_tag = int(field_tag_raw, 0)
                evt_fields.append((evt_id, field_tag, field_name))

    return {
        'id': cluster_id,
        'name': cluster_name,
        'attrs': sorted(set(attrs)),
        'cmds': sorted(set(cmds)),
        'evts': sorted(set(evts)),
        'cmd_fields': sorted(set(cmd_fields)),
        'evt_fields': sorted(set(evt_fields)),
        'attr_struct_fields': sorted(set(attr_struct_fields)),
        'attr_enum_values': sorted(set(attr_enum_values)),
    }


def emit():
    clusters = []
    for p in sorted(CHIP_CLUSTERS_DIR.iterdir()):
        if not p.is_dir():
            continue
        try:
            info = parse_cluster(p)
        except Exception:
            continue
        if info is not None:
            clusters.append(info)

    clusters.sort(key=lambda x: x['id'])

    lines = []
    lines.append('// Auto-generated by tools/gen_im_name_tables.py from connectedhomeip v1.5 branch')
    lines.append('// Do not edit manually.')
    lines.append('')

    lines.append('static const ClusterNameEntry kClusterNameTable[] = {')
    for c in clusters:
        lines.append(f'    {{ 0x{c["id"]:08X}, "{c["name"]}" }},')
    lines.append('};')
    lines.append('')

    lines.append('static const ScopedNameEntry kAttributeNameTable[] = {')
    for c in clusters:
        for aid, aname in c['attrs']:
            lines.append(f'    {{ 0x{c["id"]:08X}, 0x{aid:08X}, "{aname}" }},')
    lines.append('};')
    lines.append('')

    lines.append('static const ScopedNameEntry kCommandNameTable[] = {')
    for c in clusters:
        for cid, cname in c['cmds']:
            lines.append(f'    {{ 0x{c["id"]:08X}, 0x{cid:08X}, "{cname}" }},')
    lines.append('};')
    lines.append('')

    lines.append('static const ScopedNameEntry kEventNameTable[] = {')
    for c in clusters:
        for eid, ename in c['evts']:
            lines.append(f'    {{ 0x{c["id"]:08X}, 0x{eid:08X}, "{ename}" }},')
    lines.append('};')
    lines.append('')

    lines.append('static const CommandFieldNameEntry kCommandFieldNameTable[] = {')
    for c in clusters:
        for cmd_id, field_tag, field_name, is_request in c['cmd_fields']:
            lines.append(f'    {{ 0x{c["id"]:08X}, 0x{cmd_id:08X}, {field_tag}, {"true" if is_request else "false"}, "{field_name}" }},')
    lines.append('};')
    lines.append('')

    lines.append('static const EventFieldNameEntry kEventFieldNameTable[] = {')
    for c in clusters:
        for evt_id, field_tag, field_name in c['evt_fields']:
            lines.append(f'    {{ 0x{c["id"]:08X}, 0x{evt_id:08X}, {field_tag}, "{field_name}" }},')
    lines.append('};')
    lines.append('')

    lines.append('static const AttributeStructFieldNameEntry kAttributeStructFieldNameTable[] = {')
    for c in clusters:
        for attr_id, field_tag, field_name in c['attr_struct_fields']:
            lines.append(f'    {{ 0x{c["id"]:08X}, 0x{attr_id:08X}, {field_tag}, "{field_name}" }},')
    lines.append('};')
    lines.append('')

    lines.append('static const AttributeEnumValueNameEntry kAttributeEnumValueNameTable[] = {')
    for c in clusters:
        for attr_id, enum_value, enum_name in c['attr_enum_values']:
            lines.append(f'    {{ 0x{c["id"]:08X}, 0x{attr_id:08X}, {enum_value}, "{enum_name}" }},')
    lines.append('};')
    lines.append('')

    OUT_FILE.write_text('\n'.join(lines), encoding='utf-8')


if __name__ == '__main__':
    emit()
