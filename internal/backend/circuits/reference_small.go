package circuits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

const nbConstraintsRefSmall = 5

type referenceSmallCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *referenceSmallCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	for i := 0; i < nbConstraintsRefSmall; i++ {
		circuit.X = cs.Mul(circuit.X, circuit.X)
	}
	cs.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}

func init() {
	var circuit, good, bad, public referenceSmallCircuit

	good.X.Assign(2)

	// compute expected Y
	var expectedY big.Int
	expectedY.SetUint64(2)

	for i := 0; i < nbConstraintsRefSmall; i++ {
		expectedY.Mul(&expectedY, &expectedY)
	}

	good.Y.Assign(expectedY)

	bad.X.Assign(3)
	bad.Y.Assign(expectedY)

	public.Y.Assign(expectedY)

	addEntry("reference_small", &circuit, &good, &bad, &public)
}
