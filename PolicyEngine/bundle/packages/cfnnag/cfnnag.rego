package paas.packages.cfnnag

import data.paas.lib.policy

# ---------
# Interface
# ---------

packageId = "cfnnag"
packageVersion = "0.0.1"
violationCount = 0
policies = p {
  p = policySet
}

#------------
# Policy sets
#------------

# mandatory policies TBD
policySet[p] {
  p = []
}

policySet[p] {
  p := [
    {
      "level": "mandatory",
      "packageId": "cfnnag",
      "policyId": "cfnnag_compliance_violations",
      "parameters": {}
    }
  ]
}

# --------
# Policies
# --------

cfnnag_compliance_violations = result {
  # get violations
  violationFailureCount := input.request.attestations["ecp/att-cfnnag"].total_failure_count
  
  violationFailureCount > violationCount

  result := policy.createPolicyResult( 
    packageId,
    "cfnnag_compliance_check_failed", 
    "fail",
    "CFNNAG compliance check failed",
    []
  )
} else = result {

  result := policy.createPolicyResult( 
    packageId,
    "cfnnag_compliance_check_passed", 
    "pass",
    "CFNNAG compliance check passed",
    []
  )
}
