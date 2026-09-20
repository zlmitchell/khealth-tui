# Progress of a detached command: its exit status once written, and the
# tail of its log. __LOG__ / __EXIT__ are the files reset_rke2.sh chose.
LOG='__LOG__'; EXITF='__EXIT__'
[ -f "$EXITF" ] && say "exit=$(cat "$EXITF" 2>/dev/null)"
say "---LOG"
tail -n 25 "$LOG" 2>/dev/null | cut -c1-400
