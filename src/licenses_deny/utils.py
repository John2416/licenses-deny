import re

from .loader import load_license_mapping, multi_word_license_keys


def normalize_license(raw: str) -> str:
    if not raw or raw == 'Unknown':
        return raw
    normalized = re.sub(r'\s+', ' ', raw.strip()).lower()
    mapping = load_license_mapping()
    if normalized in mapping:
        return mapping[normalized]
    if 'apache' in normalized and ('2.0' in normalized or '2' in normalized):
        return 'Apache-2.0'
    if 'mit' in normalized:
        return 'MIT'
    if 'bsd' in normalized and ('3' in normalized or 'three' in normalized or 'new' in normalized):
        return 'BSD-3-Clause'
    if 'lgpl' in normalized:
        if '2.1' in normalized:
            return 'LGPL-2.1'
        if '3' in normalized:
            return 'LGPL-3.0'
    if 'agpl' in normalized and '3' in normalized:
        return 'AGPL-3.0'
    if 'gpl' in normalized:
        if '3' in normalized:
            return 'GPL-3.0'
        if '2' in normalized:
            return 'GPL-2.0'
    if 'psf' in normalized or 'python software foundation' in normalized:
        return 'PSF-2.0'
    if 'public domain' in normalized:
        return 'CC0-1.0'
    return raw.strip()


def summarize_license(value: str, max_len: int = 64) -> str:
    collapsed = re.sub(r'\s+', ' ', value or '').strip()
    if len(collapsed) > max_len:
        return collapsed[: max_len - 3] + '...'
    return collapsed


def split_license_expression(expr: str, strict: bool) -> list[str]:
    if not expr or expr == 'Unknown':
        return [expr]
    sep_operator = ' AND ' if strict else ' OR '
    cleaned = re.sub(r'[()]', ' ', expr)
    cleaned = re.sub(r'[\\/;,\\+]', sep_operator, cleaned)
    if re.search(r'\b(and|or)\b', cleaned, flags=re.IGNORECASE):
        parts = re.split(r'\s+(?:and|or)\s+', cleaned, flags=re.IGNORECASE)
        return [p.strip() for p in parts if p.strip()]
    return [part.strip() for part in cleaned.split(sep_operator) if part.strip()]


def tokenize_license_expression(expr: str, strict: bool) -> list[str]:
    if not expr or expr == 'Unknown':
        return []

    operator_token = 'AND' if strict else 'OR'
    cleaned = re.sub(r'[\\/;,\\+]', f' {operator_token} ', expr)
    cleaned = re.sub(r'\s+', ' ', cleaned.strip())

    tokens: list[str] = []
    i = 0
    n = len(cleaned)

    and_or_pattern = re.compile(r'\b(and|or)\b', re.IGNORECASE)
    multi_word = multi_word_license_keys()

    while i < n:
        char = cleaned[i]
        if char in ' \t\n\r':
            i += 1
            continue
        if char in '()':
            tokens.append(char)
            i += 1
            continue

        matched = False
        substr = cleaned[i:].lower()
        for phrase in multi_word:
            if substr.startswith(phrase):
                tokens.append(cleaned[i : i + len(phrase)])
                i += len(phrase)
                matched = True
                break

        if matched:
            continue

        j = i
        while j < n and cleaned[j] not in ' \t\n\r()':
            j += 1
        word = cleaned[i:j]
        i = j

        if and_or_pattern.fullmatch(word):
            tokens.append('AND' if strict else 'OR')
        else:
            tokens.append(word)

    return tokens


def to_postfix(tokens: list[str]) -> list[str]:
    output: list[str] = []
    stack: list[str] = []
    precedence = {'AND': 2, 'OR': 1}
    for tok in tokens:
        if tok in precedence:
            while stack and stack[-1] in precedence and precedence[stack[-1]] >= precedence[tok]:
                output.append(stack.pop())
            stack.append(tok)
        elif tok == '(':
            stack.append(tok)
        elif tok == ')':
            while stack and stack[-1] != '(':
                output.append(stack.pop())
            if not stack:
                raise ValueError('Mismatched parenthesis in license expression')
            stack.pop()
        else:
            output.append(tok)
    while stack:
        if stack[-1] in ('(', ')'):
            raise ValueError('Mismatched parenthesis in license expression')
        output.append(stack.pop())
    return output


def evaluate_license_postfix(postfix: list[str], allowed_set: set[str], strict: bool) -> bool:
    if not postfix:
        return False
    stack: list[bool] = []
    for tok in postfix:
        if tok in ('AND', 'OR'):
            if len(stack) < 2:
                raise ValueError('Invalid license expression')
            right = stack.pop()
            left = stack.pop()
            if tok == 'AND' or (strict and tok == 'OR'):
                stack.append(left and right)
            else:
                stack.append(left or right)
        else:
            normalized = normalize_license(tok)
            stack.append(normalized in allowed_set)
    if len(stack) != 1:
        return all(stack) if strict else any(stack)
    return bool(stack[0])


def is_license_compliant(raw_license: str, allowed_set: set[str], strict: bool) -> bool:
    if raw_license == 'Unknown' or not raw_license:
        return False
    try:
        tokens = tokenize_license_expression(raw_license, strict)
        if not any(tok in ('AND', 'OR') for tok in tokens):
            return normalize_license(raw_license) in allowed_set
        postfix = to_postfix(tokens)
        return evaluate_license_postfix(postfix, allowed_set, strict)
    except Exception:
        parts = split_license_expression(raw_license, strict)
        normalized = [normalize_license(part) for part in parts]
        if not normalized:
            return False
        if strict:
            return all(part in allowed_set for part in normalized)
        return any(part in allowed_set for part in normalized)


def normalized_license_parts(expr: str) -> set[str]:
    tokens = tokenize_license_expression(expr, strict=False)
    parts = {normalize_license(tok) for tok in tokens if tok not in {'AND', 'OR', '(', ')'}}
    return {p for p in parts if p}


def is_copyleft(license_name: str) -> bool:
    normalized = license_name.lower()
    return 'gpl' in normalized or 'agpl' in normalized or 'lgpl' in normalized
