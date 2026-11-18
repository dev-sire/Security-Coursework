"""
PIPELINE ORCHESTRATOR
-----------------------
Runs the full chain end-to-end and writes dashboard/feed.json, which
dashboard/index.html reads to render the live-looking dashboard.

Steps:
  1. Run sandbox ransomware BEHAVIOR simulation (benign, no real encryption)
  2. Evaluate local detection rules against telemetry
  3. Run mock ML training + real-structure inference
  4. Get LLM opinion (Gemini if GEMINI_API_KEY set, else clearly-labeled mock)
  5. Generate FADE-style mock firewall dataset + evaluate firewall rules
  6. Write combined feed.json for the dashboard UI
"""

import json
import os
import sys
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "detection"))
sys.path.insert(0, os.path.join(BASE_DIR, "firewall"))
sys.path.insert(0, os.path.join(BASE_DIR, "sandbox"))

import simulate_ransomware_behavior as sandbox_sim
import local_rules
import ml_classifier
import llm_opinion
import generate_fade_dataset
import fade_firewall

FEED_OUT = os.path.join(BASE_DIR, "dashboard", "feed.json")


def main():
    print("=" * 60)
    print("STEP 1/5: Running sandbox ransomware behavior simulation")
    print("=" * 60)
    sandbox_sim.run()

    print("\n" + "=" * 60)
    print("STEP 2/5: Evaluating local detection rules")
    print("=" * 60)
    alerts = local_rules.evaluate()
    print(f"-> {len(alerts)} rule(s) triggered")

    print("\n" + "=" * 60)
    print("STEP 3/5: ML classifier (real gradient-descent training + held-out evaluation)")
    print("=" * 60)
    ml_metrics, trained_model = ml_classifier.mock_train()
    telemetry_events = local_rules.load_telemetry()
    ml_result = ml_classifier.predict(telemetry_events, model=trained_model)
    print(f"-> ML verdict: {ml_result['predicted_label']} (p={ml_result['ransomware_probability']})")

    print("\n" + "=" * 60)
    print("STEP 4/5: LLM opinion (Gemini API if key present, else mock)")
    print("=" * 60)
    llm_result = llm_opinion.get_llm_opinion(alerts, ml_result)
    print(f"-> LLM source: {llm_result['source']}")

    print("\n" + "=" * 60)
    print("STEP 5/5: FADE-style firewall module")
    print("=" * 60)
    generate_fade_dataset.generate()
    firewall_result = fade_firewall.evaluate_flows()
    print(f"-> Firewall: {firewall_result['blocked_count']} blocked / "
          f"{firewall_result['total_flows_evaluated']} evaluated")

    feed = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sandbox": {
            "environment": "PROD-ENDPOINT-07",
            "status": "collection_complete",
            "telemetry_events": telemetry_events,
        },
        "local_rules": {
            "alerts": alerts,
        },
        "ml": {
            "training_metrics": ml_metrics,
            "inference_result": ml_result,
        },
        "llm": llm_result,
        "firewall": {
            "dataset_note": "Network flow telemetry evaluated against FADE-style behavioral signatures.",
            "total_flows_evaluated": firewall_result["total_flows_evaluated"],
            "blocked_count": firewall_result["blocked_count"],
            "allowed_count": firewall_result["allowed_count"],
            "blocked_flows": firewall_result["blocked_flows"][:30],
        },
        "trustworthy_ai_controls": {
            "human_review_required": llm_result["human_review_required"],
            "confidence_qualifier": llm_result["confidence_qualifier"],
            "evidence_logged": True,
            "notes": "Automated detections require human analyst confirmation before containment actions are authorized.",
        },
    }

    os.makedirs(os.path.dirname(FEED_OUT), exist_ok=True)
    with open(FEED_OUT, "w") as f:
        json.dump(feed, f, indent=2)

    print(f"\nPipeline complete. Dashboard feed written to {FEED_OUT}")
    print("Open dashboard/index.html in a browser to view results.")


if __name__ == "__main__":
    main()
