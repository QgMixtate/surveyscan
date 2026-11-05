#!/usr/bin/env python3
"""Read durable C14 evidence and distinguish a live runner from a stale running marker."""
import argparse
import datetime
import json
from pathlib import Path
import sys
import uuid

from dev import STATE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    args = parser.parse_args()
    if str(uuid.UUID(args.run_id)) != args.run_id:
        parser.error('canonical UUID required')
    path = STATE/'c14-soak'/args.run_id/'status.json'
    report = json.loads(path.read_text())
    state = report['status']
    if state in ('preparing', 'running'):
        try:
            command = Path('/proc/'+str(report['pid'])+'/cmdline').read_bytes().split(b'\0')
            alive = args.run_id.encode() in command
        except OSError:
            alive = False
        at = report.get('last_sample', {}).get('at', report['started_at'])
        age = (datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(at.replace('Z','+00:00'))).total_seconds()
        report['runtime_observed'] = {'pid_matches_run':alive, 'sample_age_seconds':round(age,3),
                                      'state':'live' if alive and age <= 120 else 'stale_or_interrupted'}
        if not alive or age > 120:
            print(json.dumps(report,indent=2))
            return 2
    print(json.dumps(report,indent=2))
    return 0 if state not in ('failed','interrupted') else 2


if __name__ == '__main__':sys.exit(main())
