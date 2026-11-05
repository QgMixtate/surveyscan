#!/usr/bin/env python3
"""Summarize durable C14 measurements without exposing configs, keys or host facts."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import uuid

from dev import STATE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    args = parser.parse_args()
    if str(uuid.UUID(args.run_id)) != args.run_id:
        parser.error('canonical UUID required')
    result = subprocess.run([sys.executable, str(Path(__file__).with_name('soak_status.py')), args.run_id],
                            capture_output=True, text=True, timeout=10)
    if result.returncode not in (0, 2) or not result.stdout:
        raise SystemExit('cannot inspect run status')
    state = json.loads(result.stdout)
    path = STATE/'c14-soak'/args.run_id/'samples.jsonl'
    samples = []
    if path.exists():
        if path.stat().st_size > 64*1024*1024:
            raise SystemExit('sample file exceeds bounded report size')
        raw = path.read_text()
        # A live append may be in progress; only complete records are evidence.
        lines = raw.splitlines()
        if not raw.endswith('\n'):
            lines = lines[:-1]
        samples = [json.loads(line) for line in lines]
    latest = samples[-1] if samples else {}
    roles = ('agent', 'collector', 'center')
    report = {'package':'C14', 'run_id':args.run_id, 'kind':state['kind'],
              'recorded_status':state['status'], 'runtime_observed':state.get('runtime_observed'),
              'accepted_24h':state['kind']=='actual-soak' and state['status']=='passed'
                             and state['required_seconds'] >= 86400 and state.get('elapsed_seconds',0) >= 86400
                             and bool(state.get('measured_ended_at')),
              'source_revision':state['source_revision'], 'source_dirty':state['source_dirty'],
              'binary_sha256':state.get('binary_sha256'), 'runner_sha256':state.get('runner_sha256'),
              'measured_started_at':state.get('measured_started_at'),
              'measured_ended_at':state.get('measured_ended_at'),
              'required_seconds':state['required_seconds'], 'recorded_elapsed_seconds':state.get('elapsed_seconds',0),
              'complete_samples':len(samples), 'last_sample_at':latest.get('at'),
              'latest_observations':latest.get('observations'), 'end_observations':state.get('end_observations'),
              'max_inventory_age_seconds':max((s['inventory_age_seconds'] for s in samples), default=None),
              'max_source_inventory_age_seconds':max((s['source_inventory_age_seconds'] for s in samples if s.get('source_inventory_age_seconds') is not None), default=None),
              'peak_rss_kib':{role:max((s['rss_kib'].get(role,0) for s in samples), default=0) for role in roles},
              'latest_rss_kib':latest.get('rss_kib'),
              'peak_pending_files':{role:max((s[role+'_pending'] for s in samples), default=0) for role in ('agent','collector')},
              'peak_pending_bytes':{role:max((s[role+'_pending_bytes'] for s in samples), default=0) for role in ('agent','collector')},
              'latest_pending_files':{role:latest.get(role+'_pending') for role in ('agent','collector')},
              'end_pending_drained':state.get('pending_drained'),
              'peak_outbox_unapplied':max((s['outbox_unapplied'] for s in samples if s.get('outbox_unapplied') is not None), default=None),
              'latest_renewal_receipts':latest.get('renewal_receipts'),
              'events':state['events'],
              'scope':'sampled acceptance measurements, not production capacity/SLA; running/stale/failed/preflight never count as24h acceptance'}
    print(json.dumps(report, indent=2))
    return result.returncode


if __name__ == '__main__':sys.exit(main())
