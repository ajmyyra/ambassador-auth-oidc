package main

import (
	"context"
	"fmt"
	"io/ioutil"

	"github.com/open-policy-agent/opa/rego"
)

func main() {

	ctx := context.Background()

	input := map[string]interface{}{"user": "admin@example.com", "path": []string{"headers"}, "method": "GET"}

	policyFileName := "simplepolicy.rego"
	// load policy
	module, err := ioutil.ReadFile(policyFileName)
	if err != nil {
		panic(err)
	}

	// Create query that produces a single document.
	regoObj := rego.New(
		rego.Query("data.httpapi.authz.allow"),
		rego.Module(policyFileName, string(module)),
		rego.Input(input),
	)

	// Run evaluation.
	rs, err := regoObj.Eval(ctx)
	if err != nil {
		panic(err)
	}
	// Inspect result.
	fmt.Println("value:", rs[0].Expressions[0].Value)
	fmt.Println("err:", err)

}
