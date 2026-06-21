#!/bin/bash

# Load environment variables
source ./init_env.sh

echo "[+] ------- LOAD TEST -------"

# Test1
k6 run -e DPOP_TYPE=VALID_DPOP -e EXPECTED_STATUS=200 loadtest.js

# Test2
k6 run -e DPOP_TYPE=HACKER_DPOP -e EXPECTED_STATUS=403 loadtest.js

# Test3
k6 run -e DPOP_TYPE=WRONG_URL_DPOP -e EXPECTED_STATUS=403 loadtest.js

# Test4
k6 run -e DPOP_TYPE=WRONG_ATH_DPOP -e EXPECTED_STATUS=403 loadtest.js

# Test5
k6 run -e DPOP_TYPE=FUTURE_DPOP -e EXPECTED_STATUS=403 loadtest.js

echo "[+] ------- FINISHED -------"