
// SPDX-License-Identifier: AML
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// 2019 OKIMS

pragma solidity ^0.8.0;

library Pairing {

    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /*
     * @return The negation of p, i.e. p.plus(p.negate()) should be zero.
     */
    function negate(G1Point memory p) internal pure returns (G1Point memory) {

        // The prime q in the base field F_q for G1
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        } else {
            return G1Point(p.X, PRIME_Q - (p.Y % PRIME_Q));
        }
    }

    /*
     * @return The sum of two points of G1
     */
    function plus(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory r) {

        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        require(success,"pairing-add-failed");
    }


    /*
     * Same as plus but accepts raw input instead of struct
     * @return The sum of two points of G1, one is represented as array
     */
    function plus_raw(uint256[4] memory input, G1Point memory r) internal view {
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 {invalid()}
        }

        require(success, "pairing-add-failed");
    }

    /*
     * @return The product of a point on G1 and a scalar, i.e.
     *         p == p.scalar_mul(1) and p.plus(p) == p.scalar_mul(2) for all
     *         points p.
     */
    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {

        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success,"pairing-mul-failed");
    }


    /*
     * Same as scalar_mul but accepts raw input instead of struct,
     * Which avoid extra allocation. provided input can be allocated outside and re-used multiple times
     */
    function scalar_mul_raw(uint256[3] memory input, G1Point memory r) internal view {
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 {invalid()}
        }
        require(success, "pairing-mul-failed");
    }

    /* @return The result of computing the pairing check
     *         e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
     *         For example,
     *         pairing([P1(), P1().negate()], [P2(), P2()]) should return true.
     */
    function pairing(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {

        G1Point[4] memory p1 = [a1, b1, c1, d1];
        G2Point[4] memory p2 = [a2, b2, c2, d2];
        uint256 inputSize = 24;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < 4; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].X;
            input[j + 1] = p1[i].Y;
            input[j + 2] = p2[i].X[0];
            input[j + 3] = p2[i].X[1];
            input[j + 4] = p2[i].Y[0];
            input[j + 5] = p2[i].Y[1];
        }

        uint256[1] memory out;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        require(success,"pairing-opcode-failed");

        return out[0] != 0;
    }
}

contract Verifier {

    using Pairing for *;

    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct VerifyingKey {
        Pairing.G1Point alfa1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G2Point g2;
        Pairing.G2Point gRootSigmaNeg2;
        // []G1Point IC (K in gnark) appears directly in verifyProof
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alfa1 = Pairing.G1Point(uint256(19845275157305329817270712870519327215928423877226694661654428772600392127152), uint256(5922205489357142657390257703736199065513502779240849693441482100386398267819));
        vk.beta2 = Pairing.G2Point([uint256(1645848163885121275220139782053746932358907108335041462279771492889258039331), uint256(6655739033283305608289797207305117981238198119342833785876005459365504160204)], [uint256(9276425540726747244089840267709488572797545832022628786459156828316307139110), uint256(15003585545947341870333319385358644806988202419252599345781997183717698525242)]);
        vk.gamma2 = Pairing.G2Point([uint256(13247951322102494626900509434764500167395205191629382888796428668361334021498), uint256(4026958170738042276473170623611565136963263409240730945263149557395114552702)], [uint256(6512429680125388706271036610609682545361127101289075027835543443745930617012), uint256(5674757341978077172259191117474559762537064248795618381253762677618980013599)]);
        vk.delta2 = Pairing.G2Point([uint256(8684269618223764824471771605556307616072271922372547557364789871752166671729), uint256(1469314478632896630621510280152153112645074597070383750000134930577145409276)], [uint256(17901501574817329782989482824606660963215201428244130213207816543773230951501), uint256(14748323676376642351570777124193896608562858281323044336913850926188595395642)]);
		vk.g2 = Pairing.G2Point([uint256(15441851398081905723229859929074729503086595290721268231181172220162000804071), uint256(9760778954455154901431403698364139801760641153935749707489925091887679730056), uint256(1461830313526063875130343207402771263144508948525039197015117912274617688425), uint256(9187560299696423682366016256662795080820537382916262442152078670009486255909)]);
		vk.gRootSigmaNeg2 = Pairing.G2Point([uint256(2011218808780311195760069163620178658189889778386923877620985226990410816748), uint256(15435969678631777703822761975116324919528649384580180428913618169166190099310), uint256(11389472479695792187508254453204572754657983897689351287753772727653041448230), uint256(3693165019018644723941696519775578442333913601280109321750917848156896443485)]);
    }

    function verifyingKey2() internal pure returns (VerifyingKey memory vk) {
		vk[0] = 19845275157305329817270712870519327215928423877226694661654428772600392127152;
		vk[1] = 5922205489357142657390257703736199065513502779240849693441482100386398267819;
		vk[2] = 1645848163885121275220139782053746932358907108335041462279771492889258039331;
		vk[3] = 6655739033283305608289797207305117981238198119342833785876005459365504160204;
		vk[4] = 9276425540726747244089840267709488572797545832022628786459156828316307139110;
		vk[5] = 15003585545947341870333319385358644806988202419252599345781997183717698525242;
		vk[6] = 13247951322102494626900509434764500167395205191629382888796428668361334021498;
		vk[7] = 4026958170738042276473170623611565136963263409240730945263149557395114552702;
		vk[8] = 6512429680125388706271036610609682545361127101289075027835543443745930617012;
		vk[9] = 5674757341978077172259191117474559762537064248795618381253762677618980013599;
		vk[10] = 8684269618223764824471771605556307616072271922372547557364789871752166671729;
		vk[11] = 1469314478632896630621510280152153112645074597070383750000134930577145409276;
		vk[12] = 17901501574817329782989482824606660963215201428244130213207816543773230951501;
		vk[13] = 14748323676376642351570777124193896608562858281323044336913850926188595395642;
		vk[14] = 15441851398081905723229859929074729503086595290721268231181172220162000804071;
		vk[15] = 9760778954455154901431403698364139801760641153935749707489925091887679730056;
		vk[16] = 1461830313526063875130343207402771263144508948525039197015117912274617688425;
		vk[17] = 9187560299696423682366016256662795080820537382916262442152078670009486255909;
		vk[18] = 2011218808780311195760069163620178658189889778386923877620985226990410816748;
		vk[19] = 15435969678631777703822761975116324919528649384580180428913618169166190099310;
		vk[20] = 11389472479695792187508254453204572754657983897689351287753772727653041448230;
		vk[21] = 3693165019018644723941696519775578442333913601280109321750917848156896443485;
    }

    function ic(uint16 block_size) internal pure returns (uint256[] memory gammaABC) {

	}

    // accumulate scalarMul(mul_input) into q
    // that is computes sets q = (mul_input[0:2] * mul_input[3]) + q
    function accumulate(
        uint256[3] memory mul_input,
        Pairing.G1Point memory p,
        uint256[4] memory buffer,
        Pairing.G1Point memory q
    ) internal view {
        // computes p = mul_input[0:2] * mul_input[3]
        Pairing.scalar_mul_raw(mul_input, p);

        // point addition inputs
        buffer[0] = q.X;
        buffer[1] = q.Y;
        buffer[2] = p.X;
        buffer[3] = p.Y;

        // q = p + q
        Pairing.plus_raw(buffer, q);
    }

    /*
     * @returns Whether the proof is valid given the hardcoded verifying key
     *          above and the public inputs
     */
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[4] calldata input
    ) public view returns (bool r) {

        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);

        // Make sure that proof.A, B, and C are each less than the prime q
        require(proof.A.X < PRIME_Q, "verifier-aX-gte-prime-q");
        require(proof.A.Y < PRIME_Q, "verifier-aY-gte-prime-q");

        require(proof.B.X[0] < PRIME_Q, "verifier-bX0-gte-prime-q");
        require(proof.B.Y[0] < PRIME_Q, "verifier-bY0-gte-prime-q");

        require(proof.B.X[1] < PRIME_Q, "verifier-bX1-gte-prime-q");
        require(proof.B.Y[1] < PRIME_Q, "verifier-bY1-gte-prime-q");

        require(proof.C.X < PRIME_Q, "verifier-cX-gte-prime-q");
        require(proof.C.Y < PRIME_Q, "verifier-cY-gte-prime-q");

        // Make sure that every input is less than the snark scalar field
        for (uint256 i = 0; i < input.length; i++) {
            require(input[i] < SNARK_SCALAR_FIELD,"verifier-gte-snark-scalar-field");
        }

        VerifyingKey memory vk = verifyingKey();

        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);

        // Buffer reused for addition p1 + p2 to avoid memory allocations
        // [0:2] -> p1.X, p1.Y ; [2:4] -> p2.X, p2.Y
        uint256[4] memory add_input;

        // Buffer reused for multiplication p1 * s
        // [0:2] -> p1.X, p1.Y ; [3] -> s
        uint256[3] memory mul_input;

        // temporary point to avoid extra allocations in accumulate
        Pairing.G1Point memory q = Pairing.G1Point(0, 0);

        vk_x.X = uint256(17398737229141406093750087386448053117094619507158245455991836877092665338748); // vk.K[0].X
        vk_x.Y = uint256(19489598086828763855562128806729640022348544315375116692279680855651638449865); // vk.K[0].Y
        mul_input[0] = uint256(10800383561645168233196988494743911810136654265054911923198926329341727678658); // vk.K[1].X
        mul_input[1] = uint256(18227146134060743457767300880246520276274093420861732388050919455812293998989); // vk.K[1].Y
        mul_input[2] = input[0];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[1] * input[0]
        mul_input[0] = uint256(10562118524020482130640648524803112772729907046796250048475749309474342289207); // vk.K[2].X
        mul_input[1] = uint256(15239640106902636009286072350134119643106815792189139927972735538781137403660); // vk.K[2].Y
        mul_input[2] = input[1];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[2] * input[1]
        mul_input[0] = uint256(10562118524020482130640648524803112772729907046796250048475749309474342289207); // vk.K[3].X
        mul_input[1] = uint256(6648602764936639212960333395123155445589495365108683734716302355864088804923); // vk.K[3].Y
        mul_input[2] = input[2];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[3] * input[2]
        mul_input[0] = uint256(4645650585440261187262147979163175014259192824703598857921824335155310329869); // vk.K[4].X
        mul_input[1] = uint256(5062130210350555025357164978656153210678644546058473938933671473560196950206); // vk.K[4].Y
        mul_input[2] = input[3];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[4] * input[3]

        return Pairing.pairing(
            Pairing.negate(proof.A),
            proof.B,
            vk.alfa1,
            vk.beta2,
            vk_x,
            vk.gamma2,
            proof.C,
            vk.delta2
        );
    }
}
