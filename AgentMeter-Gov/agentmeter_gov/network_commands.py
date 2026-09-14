"""Conservative classification of literal, single network commands.

This is an exemption parser, not a shell interpreter. Unknown options, expansion,
wrappers and compound syntax cannot qualify for the network-command exemption.
"""
from __future__ import annotations

import ipaddress
import ntpath
import re
from urllib.parse import urlsplit


def _tokens(command: str) -> list[str] | None:
    if not command or len(command) > 32768 or any(c in command for c in '\r\n\x00'):
        return None
    tokens, current = [], []
    quote = ''
    started = False
    for char in command:
        if quote:
            if char == quote:
                if quote == '"' and current and current[-1] == '\\':
                    return None
                quote = ''
            elif quote == '"' and char in '$`':
                return None
            else:
                current.append(char)
        elif char in "'\"":
            # Escaped quotes differ across cmd, PowerShell and POSIX shells.
            if current and current[-1] == '\\':
                return None
            quote = char
            started = True
        elif char.isspace():
            if started:
                tokens.append(''.join(current))
                current, started = [], False
        elif char in ';|&<>`$(){}':
            return None
        else:
            current.append(char)
            started = True
    if quote:
        return None
    if started:
        tokens.append(''.join(current))
    if any(re.search(r'%[A-Za-z_][A-Za-z0-9_]*%', t) for t in tokens):
        return None
    return tokens


def _url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ''
        _ = parsed.port
        if parsed.scheme not in {'http', 'https'} or not host or parsed.username or parsed.password:
            return False
        if re.search(r'[\s\\\x00-\x1f]', value):
            return False
        if parsed.scheme == 'http' and host != 'localhost':
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            pass
        return bool(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', host))
    except ValueError:
        return False


def _output(value: str) -> bool:
    if value == '-':
        return True
    parts = value.replace('\\', '/').lower().split('/')
    protected = {'.env', 'memory.md', 'openclaw.json', 'audit.log', 'access.log',
                 'error.log', 'config', 'logs', 'memory', 'credentials', 'security'}
    return bool(value) and not ntpath.isabs(value) and not ntpath.splitdrive(value)[0] and not any(
        p in protected or p in {'', '..'} or p.startswith(('.', '~')) for p in parts
    )


def classify_network_command(command: str) -> dict[str, object] | None:
    tokens = _tokens(command)
    if not tokens:
        return None
    program = tokens.pop(0).lower().removesuffix('.exe')
    if program not in {'curl', 'wget', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod'}:
        return None
    method, data, output = 'GET', False, None
    urls = []
    if program == 'curl':
        flags = {'--silent', '--show-error', '--fail', '--location', '--compressed',
                 '--no-progress-meter', '--ipv4', '--ipv6', '--include', '--head', '--get'}
        values = {'--request': 'method', '--url': 'url', '--output': 'output',
                  '--max-time': 'number', '--connect-timeout': 'number', '--retry': 'number',
                  '--data': 'data', '--data-raw': 'data', '--data-binary': 'data',
                  '--data-urlencode': 'data', '--json': 'data', '--form': 'data',
                  '--form-string': 'data', '--upload-file': 'upload'}
        short_flags = set('sSfL46iIG')
        short_values = {'X': 'method', 'o': 'output', 'm': 'number', 'd': 'data', 'F': 'data', 'T': 'upload'}
    elif program == 'wget':
        flags = {'--quiet', '--no-verbose', '--server-response'}
        values = {'--output-document': 'output', '--timeout': 'number', '--tries': 'number',
                  '--method': 'method', '--post-data': 'data', '--post-file': 'data',
                  '--body-data': 'data', '--body-file': 'data'}
        short_flags, short_values = set('qS'), {'O': 'output', 'T': 'number', 't': 'number'}
    else:
        flags = {'-usebasicparsing'}
        values = {'-uri': 'url', '-method': 'method', '-body': 'data', '-infile': 'upload',
                  '-outfile': 'output', '-timeoutsec': 'number', '-maximumredirection': 'number'}
        short_flags, short_values = set(), {}
    index, end_options = 0, False
    seen = set()
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if token == '--' and program in {'curl', 'wget'} and not end_options:
            end_options = True
            continue
        if not token.startswith('-') or end_options:
            if not _url(token):
                return None
            urls.append(token)
            continue
        option, equal, attached = token.partition('=')
        if program not in {'curl', 'wget'}:
            option = option.lower()
        kind, value = None, attached if equal else None
        if option in flags:
            if equal:
                return None
            if option == '--head' and 'method' not in seen:
                method = 'HEAD'
            if option == '--get' and 'method' not in seen:
                method = 'GET'
            continue
        if option in values:
            kind = values[option]
        elif program in {'curl', 'wget'} and not token.startswith('--'):
            cluster = token[1:]
            while cluster:
                flag, cluster = cluster[0], cluster[1:]
                if flag in short_flags:
                    if flag == 'I' and 'method' not in seen:
                        method = 'HEAD'
                    elif flag == 'G' and 'method' not in seen:
                        method = 'GET'
                    continue
                if flag not in short_values:
                    return None
                kind, value = short_values[flag], cluster or None
                break
            if kind is None:
                continue
        else:
            return None
        if value is None:
            if index == len(tokens):
                return None
            value = tokens[index]
            index += 1
        if kind in {'method', 'output'}:
            if kind in seen:
                return None
            seen.add(kind)
        if kind == 'method':
            method = value.upper()
            if method not in {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}:
                return None
        elif kind == 'url':
            if not _url(value):
                return None
            urls.append(value)
        elif kind == 'output':
            if not _output(value):
                return None
            output = value
        elif kind == 'number':
            if not re.fullmatch(r'\d+(?:\.\d+)?', value):
                return None
        else:
            data = True
            if method == 'GET':
                method = 'PUT' if kind == 'upload' else 'POST'
    if len(urls) != 1:
        return None
    return {'kind': 'read' if method in {'GET', 'HEAD'} and not data else 'mutation',
            'method': method, 'url': urls[0], 'has_data': data, 'output': output}


def user_authorizes_network_mutation(goal: str, request: dict[str, object]) -> bool:
    """Approval eligibility only; this never grants permission to execute."""
    goal = goal.strip()
    negative = (
        r'(?:不|勿|禁止|不得|避免|无需|不要|不能|不许)(?:需要|允许|进行|实际|直接|擅自|再|去|做)*'
        r'(?:发送|群发|外发|上传|提交|发布|删除|修改|写入|更新)'
        r'|\b(?:do\s+not|don[’\']t|never|must\s+not|without)\s+(?:actually\s+)?'
        r'(?:send|upload|post|submit|delete|modify|write|update)\b'
        r'|(?:只|仅)(?:需|要)?(?:生成|准备|编写).{0,20}草稿'
        r'|\b(?:draft\s+only|only\s+(?:prepare|create|write)\s+(?:a\s+)?draft)\b'
    )
    if re.search(negative, goal, re.I):
        return False
    # Match the complete endpoint, not just a domain or prefix. Paths are case
    # sensitive and a different query may select a different record or action.
    targets = re.findall(r'https?://[^\s<>"\'，。；！？）]+', goal)
    if str(request['url']) not in targets:
        return False
    return bool(re.search(
        r'发送|群发|外发|上传|提交|发布|上报|删除|修改|写入|更新'
        r'|\b(?:post|put|patch|delete|send|upload|submit|publish|update)\b', goal, re.I
    ))
