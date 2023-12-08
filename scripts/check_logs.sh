#!/bin/bash

# Colors for terminal
if test -t 1; then
    # check if it supports colors
    ncolors=$(tput colors)
    if test -n "$ncolors" && test $ncolors -ge 8; then
        NC="$(tput sgr0)"       # no color
        RED="$(tput setaf 1)"   # red
        WHITE="$(tput setaf 7)" # white
    fi
fi

exception="(HTTP|OpenID|OAuth|TLS|API|ID)"

# the "nolint: check-logs" comment should be places on the last line that the linter matches
exclude_linter="(?!.*//nolint: check-logs)"

function lintLogContainingUpperCase {
    word_char="[\.-0-9a-z ]"
    capital_word="([a-z]*[A-Z][a-zA-Z]*)"

    grep --with-filename -n -P "Msg[f]?\(\"(($word_char|$exception)*)(?!$exception)($capital_word)($exclude_linter)" $1
}

# lintLogStartingWithUpperCase searched for log messages that start with an upper case letter
function lintLogStartingWithUpperCase {
    grep --with-filename -n "Msg[f]\?(\"[A-Z]" $1 | grep -v -P "Msg[f]?\(\"$exception($exclude_linter)"
}

# lintLogStartingWithComponent searches for log messages that starts with a component "component:"
function lintLogStartingWithComponent {
    # We'll check for different functions that can generate errors or logs. If they start with 
    # a number words followed by ":", it's considered as starting with a component.
    # Examples: '.Msgf("component:")', '.Errorf("com ponent:")', '.Msg("com-ponent:")'
    grep --with-filename -n -E "(Errorf|errors.New|Msg[f]?)\(\"[a-zA-Z-]+( [a-zA-Z-]+){0,1}:($exclude_linter)" $1
}

# lintErrorLogsBeggining searches for log messages that don't start with "failed to"
function lintErrorLogsBeggining {
    grep --with-filename -n -P "Error\(\)(?:.*)\n?.(?:.*)Msg[f]?\(\"(?!(failed to|failed due|invalid|unexpected|unsupported))($exclude_linter)" $1
}

function printLintError {
    errReason=$1
    errPathAndContent=$2

    IFS=':' read -r errPath errLine errLineContent <<< "$errPathAndContent"
    errLocation="$errPath:$errLine"

    if test -t 1; then
        echo -e "${WHITE}$errLocation${NC}: ${RED}$errReason${NC}\n\t$errLineContent"
    else
        echo "$errLocation: $errReason: $errLineContent"
    fi
}

files=$(find . -name '*.go' | grep -v '_test.go')

found_linting_error=false

for file in $files
do
    lintOutput=$(lintLogStartingWithUpperCase "$file")
    if [ $? -eq 0 ]; then
        found_linting_error=true
        while IFS= read -r line; do
            printLintError "Log message should not start with a CAPITAL letter" "$(echo $line | tr -s [:space:])"
        done <<< "$lintOutput"
    fi 

    lintOutput=$(lintLogStartingWithComponent "$file")
    if [ $? -eq 0 ]; then
        found_linting_error=true
        while IFS= read -r line; do
            printLintError "Log message should not start with the component (ex: 'component:', 'mixed component-with-dash:')" \
            "$(echo $line | tr -s [:space:])"
        done <<< "$lintOutput"
    fi

    lintOutput=$(lintErrorLogsBeggining "$file")
    if [ $? -eq 0 ]; then
        found_linting_error=true
        while IFS= read -r line; do
            printLintError "Error messages should start with 'failed to'" \
            "$(echo $line | tr -s [:space:])"
        done <<< "$lintOutput"
    fi
done

if [ $found_linting_error = true ]; then
    exit 1
fi

exit 0
