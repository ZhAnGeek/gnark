package mimc

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	groth162 "github.com/consensys/gnark/internal/backend/bn254/groth16"
	"os"
	"testing"
)

func TestReload(t *testing.T) {

	// Creates the assignments values
	var bN = 4
	var mimcCircuit = Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "13773339841907060410779975660651653092173439740197484094397177791676767249280",
		Any0:     0,
		Any1:     1,
	}
	mimcCircuit.GKRs.AllocateGKRCircuit(bN)

	vk := groth16.NewVerifyingKey(ecc.BN254)
	name := fmt.Sprintf("vk.save")
	vkFile, err := os.Open(name)
	_, err = vk.ReadFrom(vkFile)

	pk := groth16.NewProvingKey(ecc.BN254)
	pkname := fmt.Sprintf("pk.save")
	pkFile, err := os.Open(pkname)

	if err != nil {
		panic(err)
	}
	pk.UnsafeReadFrom(pkFile)

	filePkCom, err := os.Open("pk.commitmentKey.save")
	pk.(*groth162.ProvingKey).UnsafeReadCommitmentKeyFrom(filePkCom)

	witnessname := fmt.Sprintf("witness.save")
	witnessFile, err := os.Open(witnessname)
	witness, err := frontend.NewWitness(&mimcCircuit, ecc.BN254.ScalarField())
	witness.ReadFrom(witnessFile)
	publicWitness, err := witness.Public()

	cs2 := groth16.NewCS(ecc.BN254)
	cs2name := fmt.Sprintf("ccs.save")
	cs2File, err := os.Open(cs2name)
	cs2.ReadFrom(cs2File)

	proofFile, err := os.Open("proof.save")
	proof := groth16.NewProof(ecc.BN254)
	proof.ReadFrom(proofFile)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
