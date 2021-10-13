package paas.packages.cfnnag.test.inputs

failure_input  = {
    "input":{
       "request":{
          "requestType":"deployment",
          "appspaceId":"",
          "user":"",
          "releaseCandidate":{
             "id":"",
             "appId":""
          },
          "attestations":{
            "ecp/att-cfnnag":{
                "id":"2",
                "total_failure_count":10,
                "content":[
                   {
                      "filename":"/codebuild/output/src706827623/src/infra/cdk.out/InfraStack.template.json",
                      "file_results":{
                         "failure_count":10,
                         "violations":[
 
                         ]
                      }
                   }
                ]
            }
          }
       }
    }
 }