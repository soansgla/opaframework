package paas.packages.cve

import data.paas.lib.policy

# ---------
# Interface
# ---------

packageId = "cve"
packageVersion = "0.0.1"
totalCVELowCount = 5
totalCVEMediumCount = 2
totalCVEHighCount = 0
totalCVECriticalCount = 0
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
      "packageId": "cve",
      "policyId": "cve_low_severity",
      "parameters": {}
    },
    {
      "level": "mandatory",
      "packageId": "cve",
      "policyId": "cve_medium_severity",
      "parameters": {}
    },
    {
      "level": "mandatory",
      "packageId": "cve",
      "policyId": "cve_high_severity",
      "parameters": {}
    },
    {
      "level": "mandatory",
      "packageId": "cve",
      "policyId": "cve_critical_severity",
      "parameters": {}
    }
  ]
}

cve_low_severity = result {
  # get violations
  cve_low_Count := input.request.attestations["ecp/att-cvescan"].severityCount.low
  
  cve_low_Count > totalCVELowCount

  result := policy.createPolicyResult( 
    packageId,
    "cve_low_severity", 
    "fail",
    "CVE scan for severity low is above threshold",
    []
  )
} else = result {

  result := policy.createPolicyResult( 
    packageId,
    "cve_low_severity", 
    "pass",
    "CVE scan passed for low severity",
    []
  )
}

cve_medium_severity = result {
  # get violations
  cve_medium_Count := input.request.attestations["ecp/att-cvescan"].severityCount.medium
  
  cve_medium_Count > totalCVEMediumCount

  result := policy.createPolicyResult( 
    packageId,
    "cve_medium_severity", 
    "fail",
    "CVE scan for severity medium is above threshold",
    []
  )
} else = result {

  result := policy.createPolicyResult( 
    packageId,
    "cve_medium_severity", 
    "pass",
    "CVE scan passed for severity medium",
    []
  )
}

cve_high_severity = result {
  # get violations
  cve_high_Count := input.request.attestations["ecp/att-cvescan"].severityCount.high
  
  cve_high_Count > totalCVEHighCount

  result := policy.createPolicyResult( 
    packageId,
    "cve_high_severity", 
    "fail",
    "CVE scan for severity high is above threshold",
    []
  )
} else = result {

  result := policy.createPolicyResult( 
    packageId,
    "cve_high_severity", 
    "pass",
    "CVE scan passed for severity high",
    []
  )
}

cve_critical_severity = result {
  # get violations
  cve_critical_Count := input.request.attestations["ecp/att-cvescan"].severityCount.critical
  
  cve_critical_Count > totalCVECriticalCount

  result := policy.createPolicyResult( 
    packageId,
    "cve_critical_severity", 
    "fail",
    "CVE scan for severity critical is above threshold",
    []
  )
} else = result {

  result := policy.createPolicyResult( 
    packageId,
    "cve_critical_severity", 
    "pass",
    "CVE scan passed for severity critical",
    []
  )
}