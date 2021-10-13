package paas.runners.app_pr

import data.paas.lib.policy
import data.metaverse

#----------
# Interface
#----------

policies = p {
  p = combinedPolicies with input as policyInput
}

run = response {
  response := policy.run(packages, policies, policyInput)
}

#-------
# Config
#-------

packages = [
  "base",
  "cyber_kubernetes",
  "sdlc_kubernetes"
]

# policyInput enriches the raw input with data that are relevant to many policies
# so that every policy doesn't have to individually do every lookup

policyInput = i {
	i = {
    	"request": input.request,
      "app": metaverse.apps[input.request.releaseCandidate.appId]
    }
}

# combinedPolicies combines the policy instances as returned from packages with 
# any additional sources, such as AppSpace entry criteria. 

# Right now App PR checks don't have any additional sources

combinedPolicies[p] {
  p = data.paas.packages[packages[_]].policies[_]
}
