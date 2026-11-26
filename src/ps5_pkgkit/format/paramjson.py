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
    """Decode UTF-8 JSON, allowing a leading byte order mark.

    Args:
        data: JSON document bytes.

    Returns:
        The decoded value, or None if decoding or parsing fails.
    """
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeError, ValueError, RecursionError):
        return None


def string_value_span(text: str, key: str) -> tuple[int, int] | None:
    """Locate the contents of a quoted metadata field.

    Args:
        text: Decoded metadata text.
        key: Field name including its double quotes.

    Returns:
        Character offsets from just after the opening quote to the closing
        quote, or None if the field cannot be located.
    """
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
    """Replace the contents of a quoted metadata field.

    Args:
        data: UTF-8 metadata bytes.
        key: Field name including its double quotes.
        value: Replacement text with any required JSON escaping already applied.

    Returns:
        Updated bytes, or None if no value span can be located.
    """
    text = data.decode("utf-8", "replace")
    span = string_value_span(text, key)
    if span is None:
        return None
    start, end = span
    raw = text.encode("utf-8")
    return raw[:start] + value.encode("utf-8") + raw[end:]


def insert_raw_field(data: bytes, name: str, raw: str) -> bytes | None:
    """Insert a raw field before the existing members of a JSON object.

    Args:
        data: UTF-8 metadata bytes for a nonempty object.
        name: Field name without surrounding quotes.
        raw: Encoded JSON value to write verbatim.

    Returns:
        Updated metadata using the object's newline and indentation style, or
        None if no opening brace is present.
    """
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
    """Return the leading whitespace from a string."""
    out = []
    for char in text:
        if not char.isspace():
            break
        out.append(char)
    return "".join(out)


def insert_field(data: bytes, name: str, value: str) -> bytes | None:
    """Insert a quoted string field into the metadata object.

    Args:
        data: UTF-8 metadata bytes for a nonempty object.
        name: Field name without surrounding quotes.
        value: String contents with any required JSON escaping already applied.

    Returns:
        Updated metadata, or None if no opening brace is present.
    """
    return insert_raw_field(data, name, f'"{value}"')


def drm_rewrite(data: bytes) -> bytes | None:
    """Normalize the packaged metadata's DRM type to standard.

    Args:
        data: UTF-8 title metadata.

    Returns:
        Updated bytes, or None if the field is absent or already standard.
    """
    text = data.decode("utf-8", "replace")
    span = string_value_span(text, '"applicationDrmType"')
    if span is None:
        return None
    start, end = span
    if text[start:end].lower() == STANDARD_DRM:
        return None
    return set_string_value(data, '"applicationDrmType"', STANDARD_DRM)


def launch_rewrite(data: bytes) -> bytes | None:
    """Clear launch-specific fields from the packaged metadata.

    Args:
        data: UTF-8 title metadata.

    Returns:
        Updated bytes, or None if no field could be changed.
    """
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
    """Remove a quoted field and its adjacent separator.

    Args:
        data: UTF-8 metadata bytes.
        key: Field name including its double quotes.

    Returns:
        Updated bytes, or None if the field and a usable comma cannot be
        located.
    """
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
    """Replace string contents in a metadata array with spaces.

    Args:
        data: UTF-8 metadata bytes.
        key: Array field name including its double quotes.

    Returns:
        Updated bytes with the original array widths, or None if the array is
        absent or already blank.
    """
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
    """Extract the title ID segment from a content ID.

    Args:
        content_id: Identifier with the title segment between a dash and an
            underscore.

    Returns:
        The title segment, or None if it is empty or the separators are absent.
    """
    if "-" not in content_id:
        return None
    rest = content_id.split("-", 1)[1]
    if "_" not in rest:
        return None
    return rest.split("_", 1)[0] or None


def content_id_rewrite(data: bytes, content_id: str) -> bytes | None:
    """Set the content ID and matching title ID in packaged metadata.

    Args:
        data: UTF-8 metadata for a JSON object.
        content_id: Content identifier to write.

    Returns:
        Updated bytes, or None if the input cannot be parsed or rewritten.
    """
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
    """Convert a firmware version to the package's hexadecimal word.

    Args:
        version: Dotted major and minor version, or an existing 16-digit hex
            word.

    Returns:
        A 0x-prefixed word with uppercase digits, or None for invalid input.
    """
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
    """Replace the required system software version.

    Args:
        data: UTF-8 title metadata.
        version: Encoded firmware word, as returned by firmware_word.

    Returns:
        Updated bytes, or None if the target string cannot be located.
    """
    return set_string_value(data, '"requiredSystemSoftwareVersion"', version)


def content_version_word(data: bytes) -> int | None:
    """Pack the eight content-version digits into a BCD integer.

    Args:
        data: UTF-8 metadata for a JSON object.

    Returns:
        The packed version, or None when the version is missing or does not
        contain eight digits.
    """
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
