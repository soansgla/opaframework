package paas.runners.deployment

import data.paas.lib.policy

#----------
# Interface
#----------

policies = p {
  p = combinedPolicies with input as policyInput
}

run = response {
  response = policy.run(packages, policies, policyInput)
}

#-------
# Config
#-------

packages = [
  "cfnnag",
  "cve",
  "codequality"
]

# policyInput enriches the raw input with data that are relevant to many policies 
# so that every individual policy doesn't have to do every lookup itself
# For deployment rules right now this is the App and AppSpace definitions

policyInput = i {
	i = {
    	"request": input.request,
    }
}

# combinedPolicies combines the package-defined policy instances with the AppSpace entry criteria
# For deployments we need an app id and an appspace id, the default base policies don't check this
combinedPolicies[p] {
  p = data.paas.packages[packages[_]].policies[_]
}


