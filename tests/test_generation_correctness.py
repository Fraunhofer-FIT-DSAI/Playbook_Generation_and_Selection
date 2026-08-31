#!/usr/bin/env python3
from __future__ import annotations

import itertools
import os
import sys
import unittest
from pathlib import Path

from cvss import CVSS3


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "generation_phase" / "source"
sys.path.insert(0, str(SOURCE))
sys.path.insert(0, str(SOURCE / "Incident_generation"))
sys.path.insert(0, str(SOURCE / "Response_generation"))
os.environ["CVE_MITRE_ENRICHED_PATH"] = str(
    ROOT / "data" / "scenario_profiles" / "CVE_MITRE_enriched.scenario.csv"
)
os.environ["MULVAL_INPUT_ROOT"] = str(SOURCE / "mulval-inputs")

original_cwd = Path.cwd()
try:
    os.chdir(SOURCE)
    from Incident_generation.incidents import IncidentGenerator  # noqa: E402
    from Response_generation import extractDefenseKnowledge as defense  # noqa: E402
finally:
    os.chdir(original_cwd)


def test_cvss_subscores() -> None:
    count = 0
    for av, ac, pr, ui, scope, c, i, a in itertools.product(
        "NALP",
        "LH",
        "NLH",
        "NR",
        "UC",
        "HLN",
        "HLN",
        "HLN",
    ):
        vector = (
            f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/"
            f"S:{scope}/C:{c}/I:{i}/A:{a}"
        )
        expected = CVSS3(vector)
        exploitability, impact = defense.extract_exploitability_and_impact(vector)
        assert exploitability == round(float(expected.esc), 2), vector
        assert impact == round(max(float(expected.isc), 0.0), 2), vector
        count += 1
    assert count == 2592


def test_real_incident_risk_and_provenance() -> None:
    generator = IncidentGenerator("scenario_Chemical", max_incidents=20)
    incidents = generator.get_goal_based_incidents()[:20]
    assert incidents
    for incident in incidents:
        residual_risks = []
        for k in range(11):
            rows, before, after = defense.create_countermeasure_table(incident, top_k=k)
            assert after <= before + 1e-9
            residual_risks.append(after)
            if k == 0:
                assert rows.empty
                assert after == before
            if not rows.empty:
                queried = {str(step["mitre"]).split()[-1] for step in incident}
                assert set(rows["off_tech_id"]).issubset(queried)
        assert all(
            current <= previous + 1e-9
            for previous, current in zip(residual_risks, residual_risks[1:])
        )


class GenerationCorrectnessTests(unittest.TestCase):
    def test_cvss_subscores(self) -> None:
        test_cvss_subscores()

    def test_real_incident_risk_and_provenance(self) -> None:
        test_real_incident_risk_and_provenance()
