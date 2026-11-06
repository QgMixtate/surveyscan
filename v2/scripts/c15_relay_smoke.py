#!/usr/bin/env python3
"""Real compiled opt-in1.2 relay with synthetic enrolled agent/scoped Transit/PG.

Explicit test configuration selects the protocol; agent capability negotiation
and actual Windows collection/service are not exercised by this entry point.
"""
from c15_center_smoke import main

if __name__ == '__main__':
    main(relay12=True)
