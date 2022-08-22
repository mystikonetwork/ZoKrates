use crate::scheme::{NonUniversalScheme, Scheme};
use crate::solidity::solidity_pairing_lib;
use crate::{G1Affine, G2Affine, MpcScheme, SolidityCompatibleField, SolidityCompatibleScheme};
use regex::Regex;
use serde::{Deserialize, Serialize};
use zokrates_field::Field;

#[derive(Serialize)]
pub struct G16;

#[derive(Serialize, Deserialize, Clone)]
pub struct ProofPoints<G1, G2> {
    pub a: G1,
    pub b: G2,
    pub c: G1,
}

#[derive(Serialize, Deserialize)]
pub struct VerificationKey<G1, G2> {
    pub alpha: G1,
    pub beta: G2,
    pub gamma: G2,
    pub delta: G2,
    pub gamma_abc: Vec<G1>,
}

impl<T: Field> Scheme<T> for G16 {
    const NAME: &'static str = "g16";

    type VerificationKey = VerificationKey<G1Affine, G2Affine>;
    type ProofPoints = ProofPoints<G1Affine, G2Affine>;
}

impl<T: Field> NonUniversalScheme<T> for G16 {}
impl<T: Field> MpcScheme<T> for G16 {}

impl<T: SolidityCompatibleField> SolidityCompatibleScheme<T> for G16 {
    type Proof = Self::ProofPoints;

    fn export_solidity_verifier(
        vk: <G16 as Scheme<T>>::VerificationKey,
    ) -> (String, String, String) {
        let (mut template_text, mut template_lib_text, solidity_pairing_lib_sans_bn256g2) = (
            String::from(CONTRACT_TEMPLATE),
            String::from(CONTRACT_LIB_TEMPLATE),
            solidity_pairing_lib(false),
        );

        let vk_regex = Regex::new(r#"(<%vk_[^i%]*%>)"#).unwrap();
        let vk_gamma_abc_len_regex = Regex::new(r#"(<%vk_gamma_abc_length%>)"#).unwrap();
        let vk_gamma_abc_repeat_regex = Regex::new(r#"(<%vk_gamma_abc_pts%>)"#).unwrap();
        let vk_input_len_regex = Regex::new(r#"(<%vk_input_length%>)"#).unwrap();
        let input_loop = Regex::new(r#"(<%input_loop%>)"#).unwrap();
        let input_argument = Regex::new(r#"(<%input_argument%>)"#).unwrap();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.alpha.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.beta.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.gamma.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.delta.to_string().as_str())
            .into_owned();

        let gamma_abc_count: usize = vk.gamma_abc.len();
        template_text = vk_gamma_abc_len_regex
            .replace(
                template_text.as_str(),
                format!("{}", gamma_abc_count).as_str(),
            )
            .into_owned();

        template_text = vk_input_len_regex
            .replace(
                template_text.as_str(),
                format!("{}", gamma_abc_count - 1).as_str(),
            )
            .into_owned();

        // feed input values only if there are any
        template_text = if gamma_abc_count > 1 {
            input_loop.replace(
                template_text.as_str(),
                r#"
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }"#,
            )
        } else {
            input_loop.replace(template_text.as_str(), "")
        }
        .to_string();

        // take input values as argument only if there are any
        template_text = if gamma_abc_count > 1 {
            input_argument.replace(template_text.as_str(), ", uint[] memory input")
        } else {
            input_argument.replace(template_text.as_str(), "")
        }
        .to_string();

        let mut gamma_abc_repeat_text = String::new();
        for (i, g1) in vk.gamma_abc.iter().enumerate() {
            gamma_abc_repeat_text.push_str(
                format!(
                    "vk.gamma_abc[{}] = Pairing.G1Point({});",
                    i,
                    g1.to_string().as_str()
                )
                .as_str(),
            );
            if i < gamma_abc_count - 1 {
                gamma_abc_repeat_text.push_str("\n        ");
            }
        }

        template_text = vk_gamma_abc_repeat_regex
            .replace(template_text.as_str(), gamma_abc_repeat_text.as_str())
            .into_owned();

        let re = Regex::new(r"(?P<v>0[xX][0-9a-fA-F]{64})").unwrap();
        template_text = re.replace_all(&template_text, "uint256($v)").to_string();
        template_lib_text = re
            .replace_all(&template_lib_text, "uint256($v)")
            .to_string();

        (
            solidity_pairing_lib_sans_bn256g2,
            template_text,
            template_lib_text,
        )
    }
}

const CONTRACT_LIB_TEMPLATE: &str = r#"
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.7;
import "./Pairing.sol";
library VerifierLib {
    error InvalidParam();
    error NotOnCurve();

    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
}
"#;

const CONTRACT_TEMPLATE: &str = r#"
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.7;
import "./Pairing.sol";
import "./VerifierLib.sol";
contract Verifier {
    function verifyingKey() pure internal returns (VerifierLib.VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(<%vk_alpha%>);
        vk.beta = Pairing.G2Point(<%vk_beta%>);
        vk.gamma = Pairing.G2Point(<%vk_gamma%>);
        vk.delta = Pairing.G2Point(<%vk_delta%>);
        vk.gamma_abc = new Pairing.G1Point[](<%vk_gamma_abc_length%>);
        <%vk_gamma_abc_pts%>
    }
    function verify(uint[] memory input, VerifierLib.Proof memory proof) internal view returns (bool) {
        uint256 fieldSize = Pairing.FIELD_SIZE;
        VerifierLib.VerifyingKey memory vk = verifyingKey();
        if (input.length + 1 != vk.gamma_abc.length) revert VerifierLib.InvalidParam();
        if (proof.a.X >= fieldSize) revert VerifierLib.InvalidParam();
        if (proof.a.Y >= fieldSize) revert VerifierLib.InvalidParam();
        if (proof.b.X[0] >= fieldSize) revert VerifierLib.InvalidParam();
        if (proof.b.Y[0] >= fieldSize) revert VerifierLib.InvalidParam();
        if (proof.b.X[1] >= fieldSize) revert VerifierLib.InvalidParam();
        if (proof.b.Y[1] >= fieldSize) revert VerifierLib.InvalidParam();
        if (proof.c.X >= fieldSize) revert VerifierLib.InvalidParam();
        if (proof.c.Y >= fieldSize) revert VerifierLib.InvalidParam();
        if (!Pairing.isOnCurve(proof.a)) revert VerifierLib.NotOnCurve();
        if (!Pairing.isOnCurve(proof.b)) revert VerifierLib.NotOnCurve();
        if (!Pairing.isOnCurve(proof.c)) revert VerifierLib.NotOnCurve();
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.addition(Pairing.G1Point(0, 0), vk.gamma_abc[0]);
        for (uint i = 0; i < input.length; i++) {
            if (input[i] >= fieldSize) revert VerifierLib.InvalidParam();
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        if (!Pairing.isOnCurve(vk_x)) revert VerifierLib.NotOnCurve();
        return Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta);
    }
    function verifyTx(VerifierLib.Proof memory proof<%input_argument%>) public view returns (bool r) {
        if (input.length != <%vk_input_length%>) revert VerifierLib.InvalidParam();
        return verify(input, proof);
    }
}
"#;
