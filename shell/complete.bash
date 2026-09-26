_ctf_complete() {
    local candidate
    COMPREPLY=()
    while IFS= read -r candidate; do
        COMPREPLY+=("$candidate")
    done < <(command ctf __complete "${COMP_WORDS[@]:1:COMP_CWORD}" 2>/dev/null)
    if [[ ${COMP_WORDS[1]} == import || ${COMP_WORDS[1]} == extract || ${COMP_WORDS[1]} == adopt || ( ${COMP_WORDS[1]} == contest && ${COMP_WORDS[2]-} == adopt ) ]]; then
        compopt -o default
    else
        # Let Readline quote spaces, brackets, and shell metacharacters in names.
        compopt -o filenames 2>/dev/null || true
    fi
}
complete -F _ctf_complete ctf
