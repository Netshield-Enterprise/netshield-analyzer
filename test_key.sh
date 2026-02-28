#!/bin/bash
mkdir -p ~/.netshield
echo "NSPRO-541934E6-913EFF11" > ~/.netshield/credentials

# verify read
cat ~/.netshield/credentials
