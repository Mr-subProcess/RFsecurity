# Upstream API references

- HackRF `libhackrf` public header: https://github.com/greatscottgadgets/hackrf/blob/main/host/libhackrf/src/hackrf.h
- HackRF One device documentation: https://hackrf.readthedocs.io/en/stable/hackrf_one.html
- HackRF command-line tools: https://hackrf.readthedocs.io/en/latest/hackrf_tools.html

RFSEC uses the documented RX callback lifecycle: initialize, open, configure, start RX, signal stop from the callback/main loop, call stop from the main thread, then close and exit. Check the upstream header and the exact version installed on the target system when building against a different libhackrf release.
