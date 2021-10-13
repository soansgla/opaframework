package paas.packages.codequality

import data.paas.lib.policy

# ---------
# Interface
# ---------

packageId = "codequality"
packageVersion = "0.0.1"
codequalityCoverageCount = 80
codequalitySecurityVulnerabilities = 1
codequalitySecurityRating = 1
policies = p {
  p = policySet
}

#------------
# Policy sets
#------------

# mandatory policies 
policySet[p] {
  p = []
}

policySet[p] {
  p := [
    {
      "level": "non-mandatory",
      "packageId": "codequality",
      "policyId": "codequality_coverage_overall",
      "parameters": {}
    },
    {
      "level": "non-mandatory",
      "packageId": "codequality",
      "policyId": "codequality_security_vulnerabilities",
      "parameters": {}
    },
    {
      "level": "non-mandatory",
      "packageId": "codequality",
      "policyId": "codequality_security_rating",
      "parameters": {}
    }
  ]
}

codequality_coverage_overall = result {
  # get violations
  codequality_coverage_count := input.request.attestations["ecp/att-codequality"].coverage.overall
  
  codequality_coverage_count < codequalityCoverageCount

  result := policy.createPolicyResult( 
    packageId,
    "codequality_coverage_overall", 
    "fail",
    "CodeQuality coverage is below threshold value",
    []
  )
} else = result {

  result := policy.createPolicyResult( 
    packageId,
    "codequality_coverage_overall", 
    "pass",
    "CodeQuality coverage passed",
    []
  )
}

codequality_security_vulnerabilities = result {
  # get violations
  codequality_security_vulnerabilities := input.request.attestations["ecp/att-codequality"].security.overall.vulnerabilities
  
  codequality_security_vulnerabilities > codequalitySecurityVulnerabilities

  result := policy.createPolicyResult( 
    packageId,
    "codequality_security_vulnerabilities", 
    "fail",
    "CodeQuality security vulerabilities is above threshold value",
    []
  )
} else = result {

  result := policy.createPolicyResult( 
    packageId,
    "codequality_security_vulnerabilities", 
    "pass",
    "CodeQuality security vulerabilities passed",
    []
  )
}

codequality_security_rating = result {
  # get violations
  codequality_security_rating := input.request.attestations["ecp/att-codequality"].security.overall.securityRating
  
  codequality_security_rating > codequalitySecurityRating

  result := policy.createPolicyResult( 
    packageId,
    "codequality_security_rating", 
    "fail",
    "CodeQuality security rating is above threshold value",
    []
  )
} else = result {

  result := policy.createPolicyResult( 
    packageId,
    "codequality_security_rating", 
    "pass",
    "CodeQuality security rating passed",
    []
  )
}