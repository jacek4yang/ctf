#!/usr/bin/env bash
set -euo pipefail
export PATH="$(cd "${1:-target/release}" && pwd):$PATH"
smoke_root=$(mktemp -d)
smoke_root=$(cd "$smoke_root" && pwd)
[[ "$smoke_root" == /* && "$smoke_root" != / ]]
trap 'cd /; rm -rf -- "$smoke_root"' EXIT
export CTF_HOME="$smoke_root/workspace with spaces"
unset CTF_LIMIT CTF_CD_FILE
eval "$(ctf init bash)"

ctf contest new "BUUCTF"
ctf contest new "研究生网络安全创新大赛"
ctf contest list
[[ $(ctf contest list 研究生) == $'2\t研究生网络安全创新大赛' ]]
ctf use 1
[[ "$PWD" == "$CTF_HOME/BUUCTF" ]]
ctf new "签到题"
[[ "$PWD" == "$CTF_HOME/BUUCTF/签到题" ]]
ctf new "easyRSA"
ctf new "[极客大挑战 2019]EasySQL"
ctf new "RSA签到"
ctf list
[[ $(ctf list rsa | wc -l) -eq 2 ]]
[[ $(ctf list rsa easy) == $'2\teasyRSA' ]]
[[ $(ctf list 极客 sql) == $'3\t[极客大挑战 2019]EasySQL' ]]
ctf go 2
[[ "$PWD" == "$CTF_HOME/BUUCTF/easyRSA" ]]
ctf info
if ctf go rsa 2> "$smoke_root/ambiguous"; then
    printf '%s\n' 'Ambiguous navigation unexpectedly succeeded' >&2
    exit 1
fi
[[ "$PWD" == "$CTF_HOME/BUUCTF/easyRSA" ]]
grep -q 'ambiguous' "$smoke_root/ambiguous"
ctf go '极客 sql'
[[ "$PWD" == "$CTF_HOME/BUUCTF/[极客大挑战 2019]EasySQL" ]]
ctf go 2
ctf target 'nc "host" 2333; $(touch NEVER_EXECUTE)'
[[ ! -e NEVER_EXECUTE ]]

mkdir "$smoke_root/fixtures"
printf 'literal: aGVsbG8=\r\n' > "$smoke_root/fixtures/附件.txt"
ctf import "$smoke_root/fixtures/附件.txt"
ctf import "$smoke_root/fixtures/附件.txt"
[[ -f '附件.txt' && -f '附件-2.txt' ]]
cmp '附件.txt' "$smoke_root/fixtures/附件.txt"
mapfile -t originals < <(find .ctf/archive -type f)
[[ ${#originals[@]} -eq 2 ]]
printf 'edited\n' > '附件.txt'
cmp "${originals[0]}" "$smoke_root/fixtures/附件.txt"
tar -czf "$smoke_root/challenge.tar.gz" -C "$smoke_root/fixtures" '附件.txt'
ctf import "$smoke_root/challenge.tar.gz"
ctf extract
mapfile -t extracted < <(find . -maxdepth 1 -type d -name 'extracted-*')
[[ ${#extracted[@]} -eq 1 ]]
cmp "${extracted[0]}/附件.txt" "$smoke_root/fixtures/附件.txt"
ctf target 'nc example.com 1337'
[[ $(ctf info) == *'nc example.com 1337'* ]]

COMP_WORDS=(ctf go '[极')
COMP_CWORD=2
_ctf_complete
[[ ${COMPREPLY[0]} == '[极客大挑战 2019]EasySQL' ]]
ctf new '$(touch PWNED)'
[[ "$PWD" == "$CTF_HOME/BUUCTF/\$(touch PWNED)" ]]
ctf go 2
[[ ! -e PWNED ]]
ctf go '$(touch PWNED)'
[[ "$PWD" == "$CTF_HOME/BUUCTF/\$(touch PWNED)" ]]
ctf use 研究生
[[ "$PWD" == "$CTF_HOME/研究生网络安全创新大赛" ]]
ctf info
ctf use 1
ctf go 2
ctf rename 2 'easy RSA [中文]'
[[ "$PWD" == "$CTF_HOME/BUUCTF/easy RSA [中文]" ]]
ctf contest rename 1 'BUU renamed'
[[ "$PWD" == "$CTF_HOME/BUU renamed/easy RSA [中文]" ]]
ctf go 2
[[ "$PWD" == "$CTF_HOME/BUU renamed/easy RSA [中文]" ]]
ctf use 1
mkdir 'adopt 中文'
ctf adopt 'adopt 中文'
ctf go 6
[[ "$PWD" == "$CTF_HOME/BUU renamed/adopt 中文" ]]
ctf doctor
mkdir -p .ctf/staging/interrupted
printf 'partial\n' > .ctf/staging/interrupted/partial
if ctf doctor > "$smoke_root/doctor.txt"; then exit 1; fi
ctf doctor --fix
[[ ! -e .ctf/staging/interrupted ]]
ctf doctor
for name in "single'quote" 'double"quote' '$dollar' 'back\slash' '-leading'; do
    ctf new -- "$name"
    [[ "$PWD" == "$CTF_HOME/BUU renamed/$name" ]]
    ctf go -- "$name"
    [[ "$PWD" == "$CTF_HOME/BUU renamed/$name" ]]
done
COMP_WORDS=(ctf rename 'back')
COMP_CWORD=2
_ctf_complete
[[ ${COMPREPLY[0]} == 'back\slash' ]]
ctf doctor
printf '%s\n' 'Linux/Bash smoke test passed.'
