package packages.cfnnag

import data.main
import data.paas.packages.cfnnag.test.inputs

test_failure{
    i=inputs.failure_input
    results=data.main with input as i.input
    results.decision.status = "fail"
}

test_success{
    i=inputs.success_input
    results=data.main with input as i.input
    results.decision.status = "pass"
}

# test_no_attestation{
#     i=inputs.no_attestation_input
#     results=data.main with input as i.input
#     results.decision.status = "fail"
# }