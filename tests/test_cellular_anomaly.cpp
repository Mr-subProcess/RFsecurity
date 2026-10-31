#include "rfsec/cellular_anomaly.hpp"

#include <cassert>
#include <iostream>

int main() {
    using namespace rfsec::telecom;
    std::vector<CellObservation> observations;
    observations.push_back({1000, "LTE", "286", "01", "10", "cell-A", 11, 6300, -70.0, -10.0, "enabled"});
    observations.push_back({2000, "LTE", "999", "99", "11", "cell-B", 11, 6300, -40.0, -8.0, "disabled"});
    CellAnomalyDetector detector({"286-01"});
    const auto result = detector.analyze(observations);
    assert(result.observations == 2);
    bool unapproved = false, cipher = false, collision = false;
    for (const auto& f : result.findings) {
        unapproved |= f.code == "UNAPPROVED_PLMN";
        cipher |= f.code == "CIPHERING_REPORTED_DISABLED";
        collision |= f.code == "PCI_IDENTITY_COLLISION";
    }
    assert(unapproved && cipher && collision);
    std::cout << "cellular anomaly tests passed\n";
}
