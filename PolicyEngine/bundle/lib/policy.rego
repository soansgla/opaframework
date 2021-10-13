package paas.lib.policy

import data.paas.lib.object
#import data.metaverse

# missingAttestation() creates a dummy attestation to use in attestation results 
# when the actual attestation is missing
missingAttestation(attestationTypeId, targetType, targetId) = att {
  att := {
    "attestationId": "-",
    "attestationTypeId": attestationTypeId,
    "targetType":  targetType,
    "targetId": targetId,
    "created": "",
    "details": {},
    "interpretation": false,
    "signature": ""
  }
}

# createAttestationResults creates an array of attestation results from an array of attestation statuses
# The reason for having an array of attestation statuses and turning that into results is that
# the array of statuses contains the entire attestation and may be used by the policy for decisioning.
# Attestation results is a cut down object that is returned as part of the decision log. 
createAttestationResults(attestationStatuses) = res {
  res := [ attStatus |
    attStat := attestationStatuses[_]
    att := attStat.attestation 

    # TODO - decide just how much info goes into this summary. 
    # Adding more, like attestationTypeId and authority id, might make the UI easier
    # since it could display more without having to go and fetch the full attestation data.
    # Need to think about it from an audit perspective as well.

    attStatus := {
      "attestationId": att.attestationId,
      "targetType": att.targetType,
      "targetId": att.targetId,
      "status": attStat.status,
      "msg": attStat.msg
    }
  ]
}

# createPolicyResult creates a result to be passed back to a policy runner
createPolicyResult(packageId, policyId, status, msg, attestationResults) = result {
  result := {
    "packageId": packageId,
    "id": policyId,
    "status": status,
    "msg": msg,
    "attestationResults": attestationResults
  }
}

# createPolicyResponse creates a response object which is a policy result plus extra info
createPolicyResponse(packageId, policyInfo, result) = response {
  response := {
    "packageId": packageId,
    "policyId": policyInfo.policyId,
    "level": policyInfo.level,
    "parameters": policyInfo.parameters,
    "status": result.status,
    "msg": result.msg,
    "attestationResults": result.attestationResults
  }
}

# createRunResponse creates the overall response from a policy runner
createRunResponse(requestType, packages, policies, responses, missingResults) = response {
  response := {
    "requestType": requestType,
    "status": getOverallStatus(responses),
    "packages": packages,
    "metaverseVersion": "0.1",
    "policies": policies,
    "missingResults": missingResults,
    "responses": responses
  }
}

invalidRequest = res {
  result := createPolicyResult( 
    "core",
    "validRequestType",
    "fail",
    sprintf("Unknown requestType - '%s'", [ input.request.requestType]),
    []
  )

  mainpolicy := {
    "level": "mandatory",
    "policyId": "main/validRequestType",
    "parameters": {}
  }

  response := createPolicyResponse("core", mainpolicy, result)

  res = {
    "metaverseVersion": "_",
    "packages": [],
    "policies": [],
    "requestType": input.request.requestType,
    "responses": [ response ],
    "status": "fail"
  }
}

# if any mandatory policy status is not "pass" then overall status isn't pass
getOverallStatus(responses) = res {
  responses[idx].level == "mandatory"
  responses[idx].status == "fail"
  res := "fail"
} else = res {
  responses[idx].level == "mandatory"
  responses[idx].status == "undetermined"
  res := "undetermined"
} else = res {
  res := "pass"
}

params(policies) = res {
  res := {
    "parameters": { packageId : objs | 
      packageId := policies[_][_].packageId
      objs := { policyId : params | 
        policies[x][y].packageId == packageId
        pol := policies[x][y]
        policyId := policies[x][y].policyId
        params := pol.parameters
      }
    }
  }
}

run(packages, policies, policyInput) = response {
  r = [ r2 |
    p = policies[_][_]
    inputPlusParams := object.union(policyInput, params(policies))    
    r1 = data.paas.packages[p.packageId][p.policyId] with input as inputPlusParams
    r2 = createPolicyResponse(p.packageId, p, r1)
  ]

  policyIds = { fullId | 
    p = policies[_][_]
    fullId = sprintf("%s/%s", [p.packageId, p.policyId])
  }
  resultIds = { fullId | 
    p = r[_]
    fullId = sprintf("%s/%s", [p.packageId, p.policyId])
  }
  missingResults = policyIds - resultIds
  packageInfo := [ pkg |  
    pname := packages[_]
    pversion := data.paas.packages[pname].packageVersion
    pkg := { 
      "packageId": pname,
      "version": pversion
    }
  ]
   
  response = createRunResponse(
    input.request.requestType,
    packageInfo,
    #metaverse.version,
    policyIds,
    r,
    missingResults
  )
}

flattenPolicySet(policySet) = result {
    result = [ policy | 
    policy = policySet[_]
  ]
}
