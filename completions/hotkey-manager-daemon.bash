# Bash completion for hotkey-manager-daemon
_hotkey_manager_daemon()
{
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    case "${prev}" in
        set)
            local fields="deviceFile socketPath passwordHash keyBinding"
            COMPREPLY=( $(compgen -W "${fields}" -- "${cur}") )
            return 0
            ;;
        deviceFile|socketPath)
            compopt -o filenames 2>/dev/null
            COMPREPLY=( $(compgen -f -- "${cur}") )
            return 0
            ;;
        -h|--help)
            COMPREPLY=()
            return 0
            ;;
    esac

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        local subcmds="hash keynames set -h --help"
        COMPREPLY=( $(compgen -W "${subcmds}" -- "${cur}") )
        return 0
    fi

    return 0
}

complete -F _hotkey_manager_daemon hotkey-manager-daemon
