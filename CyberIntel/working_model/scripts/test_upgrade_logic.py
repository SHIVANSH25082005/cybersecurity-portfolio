import sys
import os
import sqlite3

# Set path so we can import services
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from confidence_analysis import calculate_ip_confidence
from time_analysis import calculate_time_proximity
from services.modus_operandi_service import detect_case_mo, get_mo_stats
from services.hypothesis_service import generate_hypothesis
from services.contradiction_service import detect_case_contradictions
from services.provenance_service import get_record_provenance

def test_normalization():
    print("Testing category-based normalization...")
    res = calculate_ip_confidence("185.220.101.45", case_id="CASE999", enable_cross_case=True)
    assert len(res) > 0
    best = res[0]
    dims = best["dimensions"]
    
    # Ensure scores are between 0 and 1
    for name, dim in dims.items():
        score = dim["score"]
        assert 0.0 <= score <= 1.0, f"Dimension {name} score {score} out of bounds"
        print(f"  Dimension {name}: category={dim['category']}, score={score}")
    print("Normalization tests passed!\n")

def test_contradictions():
    print("Testing logical contradiction detection...")
    contradictions = detect_case_contradictions("CASE999")
    assert len(contradictions) > 0, "No contradictions found in CASE999"
    
    found_travel = False
    for c in contradictions:
        print(f"  Detected [{c['severity']}]: {c['type']} - {c['description']}")
        if c["type"] == "impossible_travel":
            found_travel = True
            
    assert found_travel, "Impossible travel contradiction not detected"
    print("Contradiction tests passed!\n")

def test_hypothesis_ranking():
    print("Testing hypothesis ranking and sufficiency fallback...")
    hyp = generate_hypothesis("CASE999")
    assert hyp["likely_scenario"] == "Fraud Ring"
    print(f"  CASE999 Primary Scenario: {hyp['likely_scenario']} (Confidence: {hyp['confidence_level']})")
    
    ranked = hyp["ranked_hypotheses"]
    assert len(ranked) == 5, "Ranked hypotheses list must contain all 5 options"
    for h in ranked:
        assert "%" not in str(h["name"]), "Scenario name contains percentage"
        assert "%" not in str(h["strength"]), "Scenario strength contains percentage"
        print(f"  Scenario: {h['name']} | Score: {h['score']} | Strength: {h['strength']}")
        
    # Test sufficiency fallback
    hyp_empty = generate_hypothesis("CASE_EMPTY_TEST")
    assert hyp_empty["likely_scenario"] == "No Supported Investigative Hypothesis"
    assert hyp_empty["confidence_level"] == "Insufficient Evidence"
    print("Hypothesis ranking and sufficiency tests passed!\n")

def test_historical_separation():
    print("Testing separation of direct case evidence from historical intelligence...")
    res_local = calculate_ip_confidence("49.37.120.10", case_id="CASE001", enable_cross_case=False)
    res_cross = calculate_ip_confidence("49.37.120.10", case_id="CASE001", enable_cross_case=True)
    
    dim_local = res_local[0]["dimensions"]
    dim_cross = res_cross[0]["dimensions"]
    
    assert dim_local["recurrence"]["score"] == 0.0
    assert dim_cross["recurrence"]["score"] > 0.0
    print("Historical separation tests passed!\n")

def test_request_cache():
    print("Testing request-level caching...")
    try:
        from flask import Flask, g
        app = Flask("test_app")
        with app.test_request_context():
            calculate_time_proximity("49.37.120.10", "CASE999", False)
            assert hasattr(g, "request_cache"), "g has no request_cache attribute"
            cache_keys_before = len(g.request_cache)
            assert cache_keys_before > 0
            
            calculate_time_proximity("49.37.120.10", "CASE999", False)
            cache_keys_after = len(g.request_cache)
            assert cache_keys_before == cache_keys_after, "New cache entry created instead of hit"
            print("  Request-level cache hit verified successfully.")
    except ImportError:
        print("  Flask not installed, skipping request-level cache context test.")
    print("Cache tests passed!\n")

if __name__ == "__main__":
    print("==================================================")
    print("RUNNING LOGIC UPGRADE VERIFICATION SUITE")
    print("==================================================")
    test_normalization()
    test_contradictions()
    test_hypothesis_ranking()
    test_historical_separation()
    test_request_cache()
    print("ALL TESTS PASSED SUCCESSFULLY!")
