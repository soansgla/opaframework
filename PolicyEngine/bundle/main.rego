package main

import data.paas.lib.policy

# Entry point for decisions
decision = res {
  res = data.paas.runners[input.request.requestType].run
} else = res {
  res = policy.invalidRequest
}

# params = res {
#     res = policy.params(data.paas.runners[input.request.requestType].policies)
# }

# Entry point for list of applicable policies and their severities and parameters
policies = res {
  res = [ r | 
    r = data.paas.runners[input.request.requestType].policies[_][_]
  ]
} else = res {
  res = policy.invalidRequest
}

# Entry point for retrieving a list of applicable policy policyMetadata, including required attestations
# policyMetadata = res {
#   res = { fullId : meta |
#     p = policies[_] 
#     fullId = sprintf("%s/%s", [p.packageId, p.policyId])
#     pMeta := data.metaverse.policyPackages[p.packageId].policies[p.policyId]
#     attestations := { a.id: a | a := data.metaverse.attestations[pMeta.attestations[_]]}

#     meta := {
#       "id": pMeta.id,
#       "description": pMeta.description,
#       "parameters": pMeta.parameters,
#       "attestations": attestations
#     }
#   }
# } else = res {
#   res = policy.invalidRequest
# }

# Entry point for simple list of the ids applicable policies
policyIds = res {
  res = { fullId | 
    p = policies[_]
    fullId := sprintf("%s/%s", [p.packageId, p.policyId])
  }
} else = res {
  res = policy.invalidRequest
}
