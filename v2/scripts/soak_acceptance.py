#!/usr/bin/env python3
"""Read-only C14 evidence gate. It never starts a run, changes a result or advances the plan."""
import argparse
import datetime
import json
import math
from pathlib import Path
import subprocess
import sys
import uuid

from dev import ROOT, STATE

FAULTS = ('agent_link_cut', 'agent_restart_while_disconnected', 'agent_link_restored',
          'center_link_cut', 'agent_collect_while_center_disconnected', 'center_link_restored',
          'collector_restart', 'center_restart')
IDENTITY_FIELDS = ('run_id', 'kind', 'source_revision', 'source_dirty', 'binary_sha256',
                   'runner_sha256', 'versions', 'intervals', 'required_seconds', 'measured_started_at')


class EvidenceError(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise EvidenceError(code)


def stamp(value):
    value = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    need(value.tzinfo is not None, 'timestamp_without_timezone')
    return value.timestamp()


def json_lines(path, complete):
    need(path.stat().st_size <= 64*1024*1024, 'evidence_file_too_large')
    raw = path.read_text()
    lines = raw.splitlines()
    if raw and not raw.endswith('\n'):
        need(not complete, 'incomplete_final_jsonl_record')
        lines = lines[:-1]
    return [json.loads(line) for line in lines]


def audit(state, samples, events, reference):
    """Consistency checks supplement the frozen runner's live SQL/UID/ACK assertions."""
    need(state['kind'] == 'actual-soak', 'preflight_cannot_accept_24h')
    need(state['status'] not in ('failed', 'interrupted'), 'run_failed_or_interrupted')
    need(state['status'] in ('preparing', 'running', 'passed'), 'unknown_run_state')
    if state['status'] == 'preparing':
        need(state.get('runtime_observed', {}).get('state') == 'live', 'runner_stale_or_missing')
        return {'status':'pending', 'accepted_24h':False, 'pending_gates':['first_committed_inventory']}
    for name in IDENTITY_FIELDS:
        need(state[name] == reference[name], 'reference_mismatch_'+name)
    need(state['source_dirty'] is False and state['required_seconds'] >= 86400, 'unqualified_source_or_duration')
    need(state.get('samples') == len(samples) and bool(samples), 'sample_count_mismatch')
    need(state['last_sample'] == samples[-1], 'unbound_last_sample')
    need(events[:len(state['events'])] == state['events'], 'event_ledger_mismatch')
    if state['status'] == 'passed':
        need(events == state['events'], 'unbound_final_event')
    start = stamp(state['measured_started_at'])
    need(samples[0]['elapsed_seconds'] <= 120, 'missing_initial_monitoring')
    previous_elapsed, previous_at, previous_count, previous_seq = -1, start-1, 0, 0
    readiness_failures = 0
    max_gap = 0
    for sample in samples:
        elapsed, at = sample['elapsed_seconds'], stamp(sample['at'])
        count, seq = sample['observations'], int(sample['max_source_sequence'])
        need(math.isfinite(elapsed) and elapsed >= 0 and elapsed > previous_elapsed and at > previous_at, 'nonmonotonic_samples')
        need(abs(at-start-elapsed) <= 120, 'wall_monotonic_clock_disagreement')
        gap = elapsed-previous_elapsed if previous_elapsed >= 0 else elapsed
        need(gap <= 120, 'monitoring_gap_over_120s')
        max_gap = max(max_gap, gap)
        need(count >= previous_count and seq >= previous_seq and seq >= count, 'observation_counter_regressed')
        for key in ('inventory_age_seconds', 'source_inventory_age_seconds'):
            need(math.isfinite(sample[key]) and 0 <= sample[key] <= 300, 'freshness_out_of_budget')
        for role, limit in (('agent',4194304), ('collector',1048576)):
            need(0 <= sample[role+'_pending_bytes'] <= limit and sample[role+'_pending'] >= 0, 'spool_out_of_budget')
        sections = sample['sections']
        need(set(sections) <= {'ok','partial','unavailable','unsupported','not_requested','unknown'}
             and all(isinstance(n,int) and n >= 0 for n in sections.values())
             and sum(sections.values()) >= count, 'missing_or_invalid_section_counts')
        need(sample['outbox_unapplied'] >= 0, 'invalid_outbox_count')
        need(isinstance(sample['ready'], bool), 'invalid_readiness_sample')
        readiness_failures = 0 if sample['ready'] else readiness_failures+1
        need(readiness_failures <= 4, 'persistent_readiness_failure')
        previous_elapsed, previous_at, previous_count, previous_seq = elapsed, at, count, seq
    need(0 <= state['elapsed_seconds']-previous_elapsed <= 300, 'missing_final_monitoring')
    names = [e['event'] for e in state['events']]
    need(names and names[0] == 'measured_window_started', 'missing_window_start')
    need(len(names) == len(set(names)), 'duplicate_scheduled_event')
    known = ('measured_window_started', *FAULTS, 'final_drain_started', 'measured_window_completed')
    need(all(name in known for name in names), 'unknown_scheduled_event')
    need([known.index(name) for name in names] == sorted(known.index(name) for name in names), 'scheduled_events_out_of_order')
    previous_at = start-1
    for event in state['events']:
        at = stamp(event['at'])
        need(at >= previous_at, 'nonmonotonic_events')
        if 'elapsed_seconds' in event:
            need(abs(at-start-event['elapsed_seconds']) <= 120, 'event_clock_disagreement')
        previous_at = at
    checks = ['pinned source/binaries/runner/config match start reference',
              'complete bound sample/event ledgers and monotonic real timestamps',
              'monitor gaps<=120s, freshness<=300s, bounded spools/readiness failures',
              'observation/sequence counters do not regress; scheduled events ordered']
    if state['status'] != 'passed':
        need(state.get('runtime_observed', {}).get('state') == 'live', 'runner_stale_or_missing')
        return {'status':'pending', 'accepted_24h':False, 'checks':checks, 'samples':len(samples),
                'max_sample_gap_seconds':round(max_gap,3), 'recorded_elapsed_seconds':state['elapsed_seconds'],
                'pending_gates':['real24h completion', 'finite final drain', 'both real leaf renewals', 'completion event']}
    need(state['elapsed_seconds'] >= state['required_seconds'], 'real_duration_too_short')
    end = stamp(state['measured_ended_at'])
    need(end-start >= 86400 and abs(end-start-state['elapsed_seconds']) <= 120, 'wall_duration_too_short_or_inconsistent')
    need(previous_elapsed >= state['required_seconds']-120, 'samples_do_not_cover_24h')
    need(all(name in names for name in FAULTS), 'missing_required_fault')
    need('final_drain_started' in names and names[-1] == 'measured_window_completed', 'completion_not_finalized')
    need(state['events'][-1].get('accepted_24h') is True, 'missing_actual_completion_marker')
    need(state.get('pending_drained') is True and all(state.get('observed_pending', {}).get(r) is True for r in ('agent','collector')), 'missing_queue_recovery_evidence')
    need(state['end_observations'] >= previous_count and state['end_observations'] > state['initial_observations']+2, 'missing_final_observation_progress')
    need(samples[-1]['renewal_receipts'] >= 2, 'missing_real_machine_renewals')
    return {'status':'passed', 'accepted_24h':True, 'checks':checks+['real>=24h covered, all faults, final drain and real renewals recorded'],
            'samples':len(samples), 'max_sample_gap_seconds':round(max_gap,3), 'recorded_elapsed_seconds':state['elapsed_seconds']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    parser.add_argument('--reference', type=Path, default=ROOT.parent/'docs/plans/surveyscan-v2/evidence/C14-soak.json')
    args = parser.parse_args()
    need(str(uuid.UUID(args.run_id)) == args.run_id, 'canonical_run_uuid_required')
    result = subprocess.run([sys.executable, str(Path(__file__).with_name('soak_status.py')), args.run_id],
                            capture_output=True, text=True, timeout=10)
    need(bool(result.stdout) and result.returncode in (0,2), 'cannot_read_runner_status')
    state = json.loads(result.stdout)
    directory = STATE/'c14-soak'/args.run_id
    if state['status'] == 'preparing':
        report = audit(state, [], [], {})
        print(json.dumps(report))
        return 3
    complete = state['status'] == 'passed'
    samples = json_lines(directory/'samples.jsonl', complete)
    if not complete:
        samples = samples[:state.get('samples',0)]  # live append may precede atomic status publication
    events = json_lines(directory/'events.jsonl', complete)
    need(args.reference.stat().st_size <= 65536, 'reference_too_large')
    report = audit(state, samples, events, json.loads(args.reference.read_text()))
    report.update(package='C14', task='C14.02 evidence review', run_id=args.run_id,
                  scope='read-only evidence consistency; live SQL UID/dedup/final conservation rely on pinned runner assertions; not a release approval')
    print(json.dumps(report, indent=2))
    return 0 if report['accepted_24h'] else 3


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (EvidenceError, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'package':'C14','status':'rejected','accepted_24h':False,
                          'reason':str(error) if isinstance(error,EvidenceError) else 'unreadable_or_invalid_evidence'}))
        sys.exit(2)
