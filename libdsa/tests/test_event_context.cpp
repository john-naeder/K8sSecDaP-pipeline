// Tests for the Alert runtime/K8s context fields surviving serialization.
// (Event JSON parsing lives in the pipeline binary's engine.cpp; here we cover
// the libdsa-owned Alert::to_json contract that the pipeline relies on.)

#include "dsa/soc/alert.h"

#include <gtest/gtest.h>
#include <string>

using dsa::soc::Alert;
using dsa::soc::Severity;

TEST(AlertContext, EmitsPodContextWhenSet) {
    Alert a;
    a.type         = "port_scan";
    a.source       = "10.244.1.5";
    a.timestamp_ns = 1700000000000ULL;
    a.severity     = Severity::Medium;
    a.namespace_   = "prod";
    a.pod_name     = "frontend-7d9c";
    a.container_id = "abcabc123";
    a.comm         = "nmap";

    const std::string j = a.to_json();
    EXPECT_NE(j.find("\"namespace\":\"prod\""), std::string::npos);
    EXPECT_NE(j.find("\"pod_name\":\"frontend-7d9c\""), std::string::npos);
    EXPECT_NE(j.find("\"container_id\":\"abcabc123\""), std::string::npos);
    EXPECT_NE(j.find("\"comm\":\"nmap\""), std::string::npos);
}

TEST(AlertContext, OmitsPodContextWhenEmpty) {
    Alert a;
    a.type   = "port_scan";
    a.source = "10.244.1.5";

    const std::string j = a.to_json();
    EXPECT_EQ(j.find("\"pod_name\""), std::string::npos);
    EXPECT_EQ(j.find("\"container_id\""), std::string::npos);
    EXPECT_EQ(j.find("\"comm\""), std::string::npos);
}
