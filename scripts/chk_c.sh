#!/bin/sh
cat /home/daytona/.gitconfig 2>&1 | head -20
ls -la /home/daytona/.daytona /home/daytona/.mintlify /home/daytona/repos 2>&1 | head -40
