"""Regression tests for bounded analyst risk scoring."""
from risk import alert_risk, analysis_risk

def test_risk_is_bounded():
    assert 0 <= alert_risk("CRITICAL","HIGH",100,True) <= 100
    assert 0 <= analysis_risk([]) <= 100

def test_volume_does_not_alone_force_maximum():
    findings=[{"severity":"LOW","confidence":"LOW","count":10000,"correlated":False}]
    assert analysis_risk(findings) < 100

if __name__=="__main__":
    test_risk_is_bounded()
    test_volume_does_not_alone_force_maximum()
    print("Vanguard-SIEM risk regression suite: PASS")
