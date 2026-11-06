#!/usr/bin/env python3
"""Real compiled opt-in1.2 relay with synthetic enrolled agent/scoped Transit/PG.

Explicit test configuration enables the protocol. An enrolled synthetic agent
verifies both signed capability frames over actual mTLS before delivery; actual
Windows collection/service and daemon automatic negotiation remain unrun.
"""
from c15_center_smoke import main

if __name__ == '__main__':
    main(relay12=True)
