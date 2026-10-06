# 公开发布仓库门禁；只输出分类错误，不输出命中的秘密或私人路径。
import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

REPOSITORY = 'kickTiger/coffee-disk-space-clean-releases'
ALLOWED = {'README.md', '.github/ISSUE_TEMPLATE/bug_report.yml', '.github/ISSUE_TEMPLATE/config.yml',
           '.github/ISSUE_TEMPLATE/feature_request.yml', '.github/ISSUE_TEMPLATE/upgrade_failure.yml',
           '.github/scripts/public_guard.py', '.github/workflows/public-safety.yml',
           '.githooks/pre-commit', '.githooks/pre-push'}
LIMIT = 1024 * 1024
SECRET = re.compile(r'-{5}BEGIN (?:[A-Z ]*PRIVATE KEY)-{5}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|(?:AKIA|ASIA)[A-Z0-9]{16}')
PRIVATE_PATH = re.compile('/' + r'Users/[^\s/]+|/' + r'home/[^\s/]+|[A-Za-z]:[\\/]' + r'Users[\\/][^\s\\/]+')
MINISIGN = ' '.join(['minisign', 'secret', 'key'])

class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, '公开发布门禁拒绝：参数无效。\n')

def secret_content(text):
    return bool(SECRET.search(text) or MINISIGN in text.lower())

def check_files(files):
    issues = set()
    if 'README.md' not in files:
        issues.add('missing_readme')
    for name, (mode, data) in files.items():
        if name not in ALLOWED:
            issues.add('forbidden_path')
            continue
        if mode not in ('100644', '100755'):
            issues.add('file_type')
            continue
        if len(data) > LIMIT:
            issues.add('file_size')
            continue
        try:
            text = data.decode('utf8')
        except UnicodeError:
            issues.add('invalid_text')
            continue
        if '\x00' in text:
            issues.add('invalid_text')
        if secret_content(text):
            issues.add('secret')
        if PRIVATE_PATH.search(text):
            issues.add('private_path')
        # 检查 Tauri 私钥常见的外层 base64；不把普通公钥误判为私钥。
        for value in re.findall(r'[A-Za-z0-9+/]{32,}={0,2}', text):
            try:
                decoded = base64.b64decode(value, validate=True).decode('utf8')
                if secret_content(decoded):
                    issues.add('encoded_secret')
            except (ValueError, UnicodeError):
                pass
    return sorted(issues)

def tree_files(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('file_type')
    files = {}
    for directory, dirs, names, fd in os.fwalk(root, follow_symlinks=False):
        relative = Path(directory).relative_to(root)
        if relative == Path('.'):
            dirs[:] = [d for d in dirs if d != '.git']
            names = [n for n in names if n != '.git']
        for name in dirs:
            prefix = (relative / name).as_posix() + '/'
            if stat.S_ISLNK(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode):
                raise ValueError('file_type')
            if not any(p.startswith(prefix) for p in ALLOWED):
                raise ValueError('forbidden_path')
        for name in names:
            item = (relative / name).as_posix()
            if item not in ALLOWED:
                raise ValueError('forbidden_path')
            metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError('file_type')
            if metadata.st_size > LIMIT:
                raise ValueError('file_size')
            handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            with os.fdopen(handle, 'rb') as stream:
                before = os.fstat(stream.fileno())
                data = stream.read(LIMIT + 1)
                after = os.fstat(stream.fileno())
                if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                    raise ValueError('input_changed')
            files[item] = ('100755' if metadata.st_mode & 0o111 else '100644', data)
    return files

def git(*args):
    return subprocess.check_output(['git', *args], stderr=subprocess.PIPE, timeout=30)

def git_files(commit=None):
    files = {}
    listing = git('ls-tree', '-rz', commit) if commit else git('ls-files', '--stage', '-z')
    for entry in listing.split(b'\0'):
        if not entry:
            continue
        header, name = entry.split(b'\t', 1)
        mode, kind, oid = header.split() if commit else (header.split()[0], b'blob', header.split()[1])
        if not commit and header.split()[2] != b'0':
            raise ValueError('unmerged_index')
        name = name.decode('utf8')
        if name not in ALLOWED:
            raise ValueError('forbidden_path')
        if kind != b'blob' or mode not in (b'100644', b'100755'):
            raise ValueError('file_type')
        if int(git('cat-file', '-s', oid.decode())) > LIMIT:
            raise ValueError('file_size')
        files[name] = (mode.decode(), git('cat-file', 'blob', oid.decode()))
    return files

def main():
    parser = QuietParser(description='公开发布仓库文件与隐私门禁')
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--tree')
    modes.add_argument('--index', action='store_true')
    modes.add_argument('--history', action='store_true')
    modes.add_argument('--json', action='store_true')
    args = parser.parse_args()
    try:
        if os.environ.get('GITHUB_REPOSITORY', REPOSITORY).lower() != REPOSITORY.lower():
            raise ValueError('wrong_repository')
        if args.history:
            commits = git('rev-list', '--all').decode().splitlines()
            if not commits or len(commits) > 10000:
                raise ValueError('history_limit')
            issues = sorted(set(issue for commit in commits for issue in check_files(git_files(commit))))
        elif args.json:
            raw = sys.stdin.buffer.read(12 * LIMIT + 1)
            if len(raw) > 12 * LIMIT:
                raise ValueError('input_limit')
            entries = json.loads(raw)
            files = {}
            for item in entries:
                if item['path'] in files:
                    raise ValueError('duplicate_path')
                files[item['path']] = (item['mode'], base64.b64decode(item['content'], validate=True))
            issues = check_files(files)
        else:
            issues = check_files(tree_files(args.tree) if args.tree else git_files())
        if issues:
            print('公开发布门禁拒绝：' + ', '.join(issues), file=sys.stderr)
            return 1
        print('公开发布门禁通过。')
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('公开发布门禁拒绝：输入、仓库、文件类型或 Git 读取无效。', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
