package gkr

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
	bn254witness "github.com/consensys/gnark/internal/backend/bn254/witness"
	"github.com/consensys/gnark/std/gkr/circuit"
	"reflect"
	"sync"
)

func witnessGenerator(id ecc.ID, inputs [][]fr.Element, bN, batchSize, initialLength int) (results []fr.Element, startLength, endLength int) {
	nativeCircuits := CreateMimcCircuitBatch(batchSize)
	provers := make([]Prover, len(nativeCircuits))
	slices := make([]GkrCircuitSlice, len(nativeCircuits))
	assignments := make([]circuit.Assignment, len(nativeCircuits))
	sliceResults := make([][]fr.Element, len(nativeCircuits))

	for i := range nativeCircuits {
		nativeCircuit := nativeCircuits[i]
		assignment := nativeCircuit.Assign(inputs, 10)
		outputs := assignment.Values[batchSize]
		prover := NewProver(nativeCircuit, assignment)
		c := AllocateGKRMimcTestCircuitBatch(bN, i)

		provers[i] = prover
		slices[i] = c
		assignments[i] = assignment

		for i := range inputs {
			for j := range inputs[i] {
				// copy gate should stay with initial inputs
				// cipher gate needs to copy
				if j < len(inputs[i])/2 {
					inputs[i][j] = outputs[i][j]
				}
			}
		}
	}

	wg := sync.WaitGroup{}
	for i := range nativeCircuits {
		wg.Add(1)
		go func(i int) {
			prover := provers[i]
			c := slices[i]
			assignment := assignments[i]
			proofg := prover.Prove(10)
			qInitialprime, _ := GetInitialQPrimeAndQAndInput(bN, 0, assignment.Values[0][0])
			c.Assign(proofg, assignment.Values[0], assignment.Values[batchSize], qInitialprime)

			w, err := witness.New(id, nil)
			if err != nil {
				panic(err)
			}

			tVariable := reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
			w.Schema, err = w.Vector.FromAssignment(&c, tVariable, false)
			if err != nil {
				panic(err)
			}

			// first start len
			if i == 0 {
				startLength = initialLength - w.Vector.Len()*(7-i)
			}
			witnessToSolution := *w.Vector.(*bn254witness.Witness)
			sliceResults[i] = witnessToSolution
			wg.Done()
			//for j := initialLength - vectors.Len()*(7-i); j < initialLength-vectors.Len()*(6-i); j++ {
			//	results = append(results, vectors[j-initialLength+vectors.Len()*(7-i)])
			//}
			endLength = initialLength
		}(i)
	}
	wg.Wait()
	for i := range sliceResults {
		results = append(results, sliceResults[i]...)
	}
	return results, startLength, endLength
}

func init() {
	cs.RegisterGKRWitnessGeneratorHandler(witnessGenerator)
}
