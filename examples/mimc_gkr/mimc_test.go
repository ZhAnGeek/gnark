// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mimc

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	groth162 "github.com/consensys/gnark/internal/backend/bn254/groth16"
	"github.com/consensys/gnark/test"
	"os"
	"testing"
)

func TestPreimage(t *testing.T) {
	assert := test.NewAssert(t)

	// Creates the assignments values
	var bN = 4
	var mimcCircuit = Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "13773339841907060410779975660651653092173439740197484094397177791676767249280",
		Any0:     0,
		Any1:     1,
	}
	mimcCircuit.GKRs.AllocateGKRCircuit(bN)

	// circuit
	var circuit Circuit
	circuit.GKRs.AllocateGKRCircuit(bN)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs(), frontend.WithGKRBN(bN))
	assert.NoError(err)

	file, err := os.Create("ccs.save")
	ccs.WriteTo(file)

	pk, vk, err := groth16.Setup(ccs)

	fileSol, err := os.Create("Verifier.sol")
	defer fileSol.Close()
	err = vk.ExportSolidity(fileSol)
	if err != nil {
		panic(err)
	}
	assert.NoError(err)

	fileVk, err := os.Create("vk.save")
	defer fileVk.Close()
	if err != nil {
		panic(err)
	}
	vk.WriteRawTo(fileVk)

	filePk, err := os.Create("pk.save")
	defer filePk.Close()
	if err != nil {
		panic(err)
	}
	pk.WriteRawTo(filePk)

	filePkCom, err := os.Create("pk.commitmentKey.save")
	pk.(*groth162.ProvingKey).WriteRawCommitmentKeyTo(filePkCom)

	// groth16: Prove & Verify
	witness, err := frontend.NewWitness(&mimcCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)

	proof, err := groth16.Prove(ccs, pk, witness)
	assert.NoError(err)

	publicWitness, err := witness.Public()
	fileWitness, err := os.Create("witness.save")
	defer fileWitness.Close()
	if err != nil {
		panic(err)
	}
	witness.WriteTo(fileWitness)
	assert.NoError(err)

	err = groth16.Verify(proof, vk, publicWitness)
	bytes, _ := json.Marshal(proof)
	fmt.Println(string(bytes))
	proofFile, err := os.Create("proof.save")
	proof.WriteTo(proofFile)

	fmt.Print("[")
	for i := range publicWitness.Vector().(bn254.Vector) {
		fmt.Print(publicWitness.Vector().(bn254.Vector)[i].String())
		fmt.Print(",")
	}
	fmt.Print(0)
	fmt.Println("]")
	assert.NoError(err)

}

func TestPreimagePoseidon(t *testing.T) {
	assert := test.NewAssert(t)

	// Creates the assignments values
	var bN = 4
	var mimcCircuit = CircuitByPoseidon{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "13773339841907060410779975660651653092173439740197484094397177791676767249280",
	}

	// circuit
	var circuit CircuitByPoseidon
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs(), frontend.WithGKRBN(bN))
	assert.NoError(err)

	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)

	// groth16: Prove & Verify
	witness, err := frontend.NewWitness(&mimcCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)

	proof, err := groth16.Prove(ccs, pk, witness)
	assert.NoError(err)

	publicWitness, err := witness.Public()
	assert.NoError(err)

	err = groth16.Verify(proof, vk, publicWitness)
	assert.NoError(err)

}
