from typing import Dict, Iterable, List, Optional, Tuple

from .models import TraceRecord


def split_top_level_csv(text: str) -> List[str]:
    items: List[str] = []
    cur: List[str] = []
    depth_brace = 0
    depth_bracket = 0
    for ch in text:
        if ch == "{" and depth_bracket >= 0:
            depth_brace += 1
        elif ch == "}" and depth_brace > 0:
            depth_brace -= 1
        elif ch == "[" and depth_brace >= 0:
            depth_bracket += 1
        elif ch == "]" and depth_bracket > 0:
            depth_bracket -= 1

        if ch == "," and depth_brace == 0 and depth_bracket == 0:
            item = "".join(cur).strip()
            if item:
                items.append(item)
            cur = []
            continue
        cur.append(ch)

    tail = "".join(cur).strip()
    if tail:
        items.append(tail)
    return items


def parse_payload(payload_text: str) -> Tuple[Optional[str], Dict[str, str]]:
    payload = payload_text.strip()
    role: Optional[str] = None

    if ":" in payload:
        prefix, rest = payload.split(":", 1)
        prefix_clean = prefix.strip()
        # In lines like "fetch req:" or "execute ... core-rsp:", keep this as role.
        if prefix_clean and "=" not in prefix_clean:
            role = prefix_clean
            payload = rest.strip()

    fields: Dict[str, str] = {}
    for token in split_top_level_csv(payload):
        if "=" in token:
            key, value = token.split("=", 1)
            fields[key.strip()] = value.strip()
        else:
            # Preserve standalone tokens so context is not lost.
            if token:
                fields[token.strip()] = ""
    return role, fields


def parse_optional_int(text: Optional[str]) -> Optional[int]:
    if text is None:
        return None
    value = text.strip()
    if not value:
        return None
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        return int(value, 10)
    return None


def summarise_data_fields(fields: Dict[str, str]) -> str:
    if not fields:
        return ""

    primary_keys = [
        "ex",
        "op",
        "instr",
        "rd",
        "wb",
        "sop",
        "eop",
        "addr",
        "tag",
        "pid",
        "ibuf_idx",
        "batch_idx",
        "valid",
        "pmask",
        "offset",
        "byteen",
        "flags",
        "data",
        "rs1_data",
        "rs2_data",
        "rs3_data",
    ]

    out: List[str] = []
    skip_keys = {"wid", "pc", "tmask", "sid"}
    for key in primary_keys:
        if key in fields and key not in skip_keys:
            out.append(f"{key}={fields[key]}")

    for key in sorted(fields.keys()):
        if key in skip_keys:
            continue
        if key not in primary_keys:
            value = fields[key]
            if value:
                out.append(f"{key}={value}")
            else:
                out.append(key)

    return ", ".join(out)


def find_first_available_int(
    records: Iterable[TraceRecord], field_name: str
) -> Optional[int]:
    for record in records:
        value = parse_optional_int(record.fields.get(field_name))
        if value is not None:
            return value
    return None
