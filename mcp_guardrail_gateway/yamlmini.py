"""A tiny, dependency-free YAML *subset* loader.

This is deliberately not a full YAML implementation. It covers exactly the
shapes this project's policy files use:

- nested block mappings (indentation based)
- block sequences ("- item") of scalars and of mappings
- inline flow sequences ([a, b, c])
- scalars: quoted/unquoted strings, ints, floats, booleans, null
- "#" comments and blank lines

If PyYAML is installed, callers may prefer it; this loader exists so the tool
runs with the standard library alone. Both load paths are tested.
"""

from __future__ import annotations

from typing import Any, List, Tuple


class YamlMiniError(ValueError):
    """Raised when the input is outside the supported subset or malformed."""


def load(text: str) -> Any:
    lines = _tokenize(text)
    if not lines:
        return {}
    value, idx = _parse_block(lines, 0, lines[0][0])
    if idx != len(lines):
        raise YamlMiniError("could not parse entire document (indentation?)")
    return value


def _tokenize(text: str) -> List[Tuple[int, str]]:
    out: List[Tuple[int, str]] = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw)
        if stripped.strip() == "":
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        out.append((indent, stripped.strip()))
    return out


def _strip_comment(line: str) -> str:
    # Remove a trailing "#..." comment that is not inside quotes.
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            # Only treat as a comment if preceded by whitespace or line start.
            if i == 0 or line[i - 1] == " ":
                return line[:i]
    return line


def _parse_block(lines, index, indent):
    if lines[index][1].startswith("- "):
        return _parse_sequence(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _parse_mapping(lines, index, indent):
    result = {}
    while index < len(lines):
        cur_indent, content = lines[index]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise YamlMiniError("unexpected indentation in mapping: %r" % content)
        if content.startswith("- "):
            break
        key, sep, rest = content.partition(":")
        if not sep:
            raise YamlMiniError("expected 'key: value' but got: %r" % content)
        key = _scalar(key.strip())
        rest = rest.strip()
        if rest == "":
            # Nested block follows (mapping or sequence), or empty value.
            if index + 1 < len(lines) and lines[index + 1][0] > indent:
                child, index = _parse_block(lines, index + 1, lines[index + 1][0])
                result[key] = child
                continue
            # Could be a sequence at the same indent (block seq under a key).
            if index + 1 < len(lines) and lines[index + 1][0] == indent \
                    and lines[index + 1][1].startswith("- "):
                child, index = _parse_sequence(lines, index + 1, indent)
                result[key] = child
                continue
            result[key] = None
            index += 1
        else:
            result[key] = _parse_flow_or_scalar(rest)
            index += 1
    return result, index


def _parse_sequence(lines, index, indent):
    result = []
    while index < len(lines):
        cur_indent, content = lines[index]
        if cur_indent < indent or not content.startswith("- "):
            break
        if cur_indent > indent:
            raise YamlMiniError("unexpected indentation in sequence: %r" % content)
        item = content[2:].strip()
        if ":" in item and not _looks_like_flow(item):
            # Inline mapping start on the "- " line; reparse as a mapping whose
            # first line is this key/value, dedented to a virtual block.
            sub = [(cur_indent + 2, item)]
            j = index + 1
            while j < len(lines) and lines[j][0] > indent and not lines[j][1].startswith("- "):
                sub.append(lines[j])
                j += 1
            value, _ = _parse_mapping(sub, 0, cur_indent + 2)
            result.append(value)
            index = j
        else:
            result.append(_parse_flow_or_scalar(item))
            index += 1
    return result, index


def _looks_like_flow(item: str) -> bool:
    return item.startswith("[") or item.startswith("{") or item.startswith(('"', "'"))


def _parse_flow_or_scalar(text: str) -> Any:
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if inner == "":
            return []
        return [_scalar(p.strip()) for p in _split_flow(inner)]
    return _scalar(text)


def _split_flow(inner: str) -> List[str]:
    parts = []
    depth = 0
    cur = []
    in_single = in_double = False
    for ch in inner:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        if ch in "[{" and not in_single and not in_double:
            depth += 1
        elif ch in "]}" and not in_single and not in_double:
            depth -= 1
        if ch == "," and depth == 0 and not in_single and not in_double:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def _scalar(text: str) -> Any:
    if text == "":
        return None
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        body = text[1:-1]
        if text[0] == '"':
            body = body.replace('\\"', '"').replace("\\\\", "\\")
        return body
    low = text.lower()
    if low in ("null", "~"):
        return None
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text
