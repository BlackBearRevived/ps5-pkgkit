"""Byte-preserving edits to ``sce_sys/param.json``.

The packaged copy is a rewrite of the source, never the source itself: the DRM
value becomes ``standard``, launch-only fields are cleared, the content id and
title id are made to match the package, an optional firmware minimum is set and
the size class is declared. Every function changes only the bytes of the value
it names, so the file's formatting survives.
"""

from __future__ import annotations

import json

STANDARD_DRM = "standard"


def parse(data: bytes):
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeError, ValueError, RecursionError):
        return None


def string_value_span(text: str, key: str) -> tuple[int, int] | None:
    at = text.find(key)
    if at < 0:
        return None
    rest = text[at + len(key):]
    colon = rest.find(":")
    if colon < 0:
        return None
    after = rest[colon + 1:]
    opening = after.find('"')
    if opening < 0:
        return None
    start = at + len(key) + colon + 1 + opening + 1
    closing = text.find('"', start)
    if closing < 0:
        return None
    return start, closing


def set_string_value(data: bytes, key: str, value: str) -> bytes | None:
    text = data.decode("utf-8", "replace")
    span = string_value_span(text, key)
    if span is None:
        return None
    start, end = span
    raw = text.encode("utf-8")
    return raw[:start] + value.encode("utf-8") + raw[end:]


def insert_raw_field(data: bytes, name: str, raw: str) -> bytes | None:
    text = data.decode("utf-8", "replace")
    opening = text.find("{")
    if opening < 0:
        return None
    at = opening + 1
    if text[at:].startswith("\r\n"):
        newline = "\r\n"
    elif text[at:].startswith("\n"):
        newline = "\n"
    else:
        newline = ""
    tail = text[at:]
    pad = ""
    if "\n" in tail:
        pad = "".join(
            char for char in _take_while_whitespace(tail.split("\n", 1)[1])
        )
    separator = ":" if newline == "" else ": "
    inserted = f'{newline}{pad}"{name}"{separator}{raw},'
    raw_text = text.encode("utf-8")
    return raw_text[:at] + inserted.encode("utf-8") + raw_text[at:]


def _take_while_whitespace(text: str) -> str:
    out = []
    for char in text:
        if not char.isspace():
            break
        out.append(char)
    return "".join(out)


def insert_field(data: bytes, name: str, value: str) -> bytes | None:
    return insert_raw_field(data, name, f'"{value}"')


def drm_rewrite(data: bytes) -> bytes | None:
    text = data.decode("utf-8", "replace")
    span = string_value_span(text, '"applicationDrmType"')
    if span is None:
        return None
    start, end = span
    if text[start:end].lower() == STANDARD_DRM:
        return None
    return set_string_value(data, '"applicationDrmType"', STANDARD_DRM)


def launch_rewrite(data: bytes) -> bytes | None:
    output = data
    changed = False
    text = output.decode("utf-8", "replace")
    span = string_value_span(text, '"versionFileUri"')
    if span is not None and span[0] < span[1]:
        rewritten = set_string_value(output, '"versionFileUri"', "")
        if rewritten is not None:
            output = rewritten
            changed = True
    for key in ('"originContentVersion"', '"targetContentVersion"'):
        rewritten = remove_string_field(output, key)
        if rewritten is not None:
            output = rewritten
            changed = True
    rewritten = blank_string_array(output, '"serviceIdForSharing"')
    if rewritten is not None:
        output = rewritten
        changed = True
    return output if changed else None


def remove_string_field(data: bytes, key: str) -> bytes | None:
    text = data.decode("utf-8", "replace")
    key_at = text.find(key)
    if key_at < 0:
        return None
    span = string_value_span(text, key)
    if span is None:
        return None
    _, value_end = span
    end = value_end + 1
    after = text[end:]
    comma = after.find(",")
    if comma >= 0 and after[:comma].strip() == "":
        end += comma + 1
        rest = text[end:]
        end += len(rest) - len(rest.lstrip())
        before = text[:key_at]
        start = key_at - (len(before) - len(before.rstrip(" \t")))
        indent = text[start:key_at]
        raw = text.encode("utf-8")
        return raw[:start] + indent.encode("utf-8") + raw[end:]
    before = text[:key_at]
    comma = before.rfind(",")
    if comma < 0 or before[comma + 1:].strip():
        return None
    raw = text.encode("utf-8")
    return raw[:comma] + raw[end:]


def blank_string_array(data: bytes, key: str) -> bytes | None:
    text = data.decode("utf-8", "replace")
    at = text.find(key)
    if at < 0:
        return None
    at += len(key)
    relative_open = text[at:].find("[")
    if relative_open < 0:
        return None
    opening = at + relative_open
    relative_close = text[opening:].find("]")
    if relative_close < 0:
        return None
    closing = opening + relative_close
    out = bytearray(text.encode("utf-8"))
    changed = False
    in_string = False
    for index in range(opening + 1, closing):
        byte = out[index]
        if byte == ord('"'):
            in_string = not in_string
        elif byte == ord(" "):
            pass
        elif in_string:
            out[index] = ord(" ")
            changed = True
    return bytes(out) if changed else None


def title_id_from_content_id(content_id: str) -> str | None:
    if "-" not in content_id:
        return None
    rest = content_id.split("-", 1)[1]
    if "_" not in rest:
        return None
    return rest.split("_", 1)[0] or None


def content_id_rewrite(data: bytes, content_id: str) -> bytes | None:
    parsed = parse(data)
    if parsed is None:
        return None
    title_id = title_id_from_content_id(content_id)
    if title_id is None:
        return None
    output = data
    for name, value in (("contentId", content_id), ("titleId", title_id)):
        current = parsed.get(name)
        if current == value:
            continue
        key = f'"{name}"'
        rewritten = (set_string_value(output, key, value) if isinstance(current, str)
                     else insert_field(output, name, value))
        if rewritten is None:
            return None
        output = rewritten
    return output


def firmware_word(version: str) -> str | None:
    value = version.strip()
    if value[:2].lower() == "0x":
        hex_part = value[2:]
        if len(hex_part) == 16 and all(char in "0123456789abcdefABCDEF" for char in hex_part):
            return "0x" + hex_part.upper()
        return None
    if "." not in value:
        return None
    major, minor = value.split(".", 1)
    if not major or not minor or len(major) > 2 or len(minor) > 2:
        return None
    if not major.isdigit() or not minor.isdigit():
        return None
    minor = minor + "0" if len(minor) == 1 else minor
    try:
        word = (int(major, 16) << 56) | (int(minor, 16) << 48)
    except ValueError:
        return None
    return f"0x{word:016X}"


def firmware_rewrite(data: bytes, version: str) -> bytes | None:
    return set_string_value(data, '"requiredSystemSoftwareVersion"', version)


def content_version_word(data: bytes) -> int | None:
    parsed = parse(data)
    if parsed is None:
        return None
    version = parsed.get("contentVersion")
    if not isinstance(version, str):
        return None
    digits = [int(char) for char in version if char.isdigit()]
    if len(digits) != 8:
        return None
    packed = 0
    for digit in digits:
        packed = (packed << 4) | digit
    return packed
