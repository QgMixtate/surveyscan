"""Synthetic evidence mutations test the gate; none are real soak/release evidence."""
import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from soak_acceptance import audit, EvidenceError, IDENTITY_FIELDS, json_lines


def fixture():
    """Fictional 2020 ledger, never written to .local or published as an accepted run."""
    start = dt.datetime(2020,1,1,tzinfo=dt.timezone.utc)
    def at(seconds):return (start+dt.timedelta(seconds=seconds)).isoformat()
    state = {'run_id':'00000000-0000-4000-8000-000000000001','kind':'actual-soak','status':'passed',
             'source_revision':'a'*40,'source_dirty':False,'binary_sha256':{'agent':'b'*64},
             'runner_sha256':'c'*64,'versions':{'agent':{'revision':'a'*40}},
             'intervals':{'inventory_seconds':60,'monitor_seconds':30},'required_seconds':86400,
             'measured_started_at':at(0),'measured_ended_at':at(86402),'elapsed_seconds':86402,
             'initial_observations':1,'end_observations':1441,'pending_drained':True,
             'observed_pending':{'agent':True,'collector':True}}
    schedule = [(0,'measured_window_started'),(3600,'agent_link_cut'),(3601,'agent_restart_while_disconnected'),
                (3720,'agent_link_restored'),(7200,'center_link_cut'),(7201,'agent_collect_while_center_disconnected'),
                (7320,'center_link_restored'),(10800,'collector_restart'),(14400,'center_restart'),
                (86400,'final_drain_started'),(86402,'measured_window_completed')]
    events = [{'at':at(t),'event':name,'elapsed_seconds':t} for t,name in schedule]
    events[-1]['accepted_24h'] = True
    state['events'] = copy.deepcopy(events)
    samples = []
    for t in range(0,86400,60):
        count = 1+t//60
        samples.append({'at':at(t),'elapsed_seconds':t,'observations':count,'max_source_sequence':str(count),
                        'inventory_age_seconds':5,'source_inventory_age_seconds':5,
                        'agent_pending_bytes':0,'collector_pending_bytes':0,'agent_pending':0,'collector_pending':0,
                        'ready':True,'sections':{'ok':count*3},'outbox_unapplied':0,
                        'renewal_receipts':2 if t >= 23*3600 else 0})
    state.update(samples=len(samples),last_sample=copy.deepcopy(samples[-1]))
    reference = {key:copy.deepcopy(state[key]) for key in IDENTITY_FIELDS}
    return state, samples, events, reference


class AcceptanceGateTests(unittest.TestCase):
    def setUp(self):self.s,self.rows,self.events,self.ref = fixture()

    def rejects(self, code):
        with self.assertRaisesRegex(EvidenceError, code):audit(self.s,self.rows,self.events,self.ref)

    def test_complete_synthetic_ledger_only_exercises_validator(self):
        self.assertTrue(audit(self.s,self.rows,self.events,self.ref)['accepted_24h'])

    def test_live_prefix_is_pending_even_when_all_faults_occurred(self):
        self.rows = self.rows[:481]
        self.events = self.events[:9]
        self.s.update(status='running',elapsed_seconds=self.rows[-1]['elapsed_seconds'],samples=len(self.rows),
                      last_sample=copy.deepcopy(self.rows[-1]),events=copy.deepcopy(self.events),runtime_observed={'state':'live'})
        result = audit(self.s,self.rows,self.events,self.ref)
        self.assertEqual(result['status'],'pending')
        self.assertFalse(result['accepted_24h'])

    def test_claimed_pass_with_short_duration_is_rejected(self):
        self.s['required_seconds'] = self.ref['required_seconds'] = 120
        self.rejects('unqualified_source_or_duration')

    def test_preflight_never_qualifies_as_actual(self):
        self.s['kind'] = 'preflight'
        self.rejects('preflight_cannot_accept_24h')

    def test_missing_fault_cannot_be_hidden_by_completed_marker(self):
        self.events = [e for e in self.events if e['event']!='center_link_cut']
        self.s['events'] = copy.deepcopy(self.events)
        self.rejects('missing_required_fault')

    def test_monitoring_gap_rejects_a_claimed_full_window(self):
        del self.rows[5:12]
        self.s['samples'] = len(self.rows)
        self.rejects('monitoring_gap_over_120s')

    def test_counter_regression_and_missing_renewal_rejected(self):
        self.rows[20]['observations'] = 1
        self.rejects('observation_counter_regressed')
        self.s,self.rows,self.events,self.ref = fixture()
        self.rows[-1]['renewal_receipts'] = self.s['last_sample']['renewal_receipts'] = 0
        self.rejects('missing_real_machine_renewals')

    def test_changed_frozen_binary_identity_rejected(self):
        self.s['binary_sha256']['agent'] = 'd'*64
        self.rejects('reference_mismatch_binary_sha256')

    def test_stale_process_and_failed_run_never_qualify(self):
        self.s.update(status='running',runtime_observed={'state':'stale_or_interrupted'})
        self.rejects('runner_stale_or_missing')
        self.s['status'] = 'failed'
        self.rejects('run_failed_or_interrupted')

    def test_partial_live_line_not_promoted_to_final_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'samples.jsonl'
            path.write_text(json.dumps(self.rows[0])+'\n'+json.dumps(self.rows[1])[:12])
            self.assertEqual(len(json_lines(path,False)),1)
            with self.assertRaisesRegex(EvidenceError,'incomplete_final_jsonl_record'):json_lines(path,True)


if __name__ == '__main__':unittest.main()
