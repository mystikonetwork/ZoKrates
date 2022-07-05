use crate::proof_system::scheme::{NonUniversalScheme, Scheme};
use crate::proof_system::solidity::solidity_pairing_lib;
use crate::proof_system::{G1Affine, G2Affine, SolidityCompatibleField, SolidityCompatibleScheme};
use regex::Regex;
use serde::{Deserialize, Serialize};
use zokrates_field::Field;

#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize)]
pub struct PGHR13;

#[derive(Serialize, Deserialize, Clone)]
pub struct ProofPoints<G1, G2> {
    pub a: G1,
    pub a_p: G1,
    pub b: G2,
    pub b_p: G1,
    pub c: G1,
    pub c_p: G1,
    pub h: G1,
    pub k: G1,
}

#[derive(Serialize, Deserialize)]
pub struct VerificationKey<G1, G2> {
    pub a: G2,
    pub b: G1,
    pub c: G2,
    pub gamma: G2,
    pub gamma_beta_1: G1,
    pub gamma_beta_2: G2,
    pub z: G2,
    pub ic: Vec<G1>,
}

impl<T: Field> Scheme<T> for PGHR13 {
    const NAME: &'static str = "pghr13";

    type VerificationKey = VerificationKey<G1Affine, G2Affine>;
    type ProofPoints = ProofPoints<G1Affine, G2Affine>;
}

impl<T: Field> NonUniversalScheme<T> for PGHR13 {}

impl<T: SolidityCompatibleField> SolidityCompatibleScheme<T> for PGHR13 {
    type Proof = Self::ProofPoints;

    fn export_solidity_verifier(
        vk: <PGHR13 as Scheme<T>>::VerificationKey,
    ) -> (String, String, String) {
        let (mut template_text, mut template_lib_text, solidity_pairing_lib) = (
            String::from(CONTRACT_TEMPLATE),
            String::from(CONTRACT_LIB_TEMPLATE),
            solidity_pairing_lib(false),
        );

        // replace things in template
        let vk_regex = Regex::new(r#"(<%vk_[^i%]*%>)"#).unwrap();
        let vk_ic_len_regex = Regex::new(r#"(<%vk_ic_length%>)"#).unwrap();
        let vk_ic_repeat_regex = Regex::new(r#"(<%vk_ic_pts%>)"#).unwrap();
        let vk_input_len_regex = Regex::new(r#"(<%vk_input_length%>)"#).unwrap();
        let input_loop = Regex::new(r#"(<%input_loop%>)"#).unwrap();
        let input_argument = Regex::new(r#"(<%input_argument%>)"#).unwrap();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.a.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.b.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.c.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.gamma.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.gamma_beta_1.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.gamma_beta_2.to_string().as_str())
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), vk.z.to_string().as_str())
            .into_owned();

        let ic_count: usize = vk.ic.len();
        template_text = vk_ic_len_regex
            .replace(template_text.as_str(), format!("{}", ic_count).as_str())
            .into_owned();

        template_text = vk_input_len_regex
            .replace(template_text.as_str(), format!("{}", ic_count - 1).as_str())
            .into_owned();

        // feed input values only if there are any
        template_text = if ic_count > 1 {
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
        template_text = if ic_count > 1 {
            input_argument.replace(
                template_text.as_str(),
                format!(", uint[{}] memory input", ic_count - 1).as_str(),
            )
        } else {
            input_argument.replace(template_text.as_str(), "")
        }
        .to_string();

        let mut ic_repeat_text = String::new();
        for (i, g1) in vk.ic.iter().enumerate() {
            ic_repeat_text.push_str(
                format!(
                    "vk.ic[{}] = Pairing.G1Point({});",
                    i,
                    g1.to_string().as_str()
                )
                .as_str(),
            );
            if i < ic_count - 1 {
                ic_repeat_text.push_str("\n        ");
            }
        }

        template_text = vk_ic_repeat_regex
            .replace(template_text.as_str(), ic_repeat_text.as_str())
            .into_owned();

        let re = Regex::new(r"(?P<v>0[xX][0-9a-fA-F]{64})").unwrap();
        template_text = re.replace_all(&template_text, "uint256($v)").to_string();
        template_lib_text = re
            .replace_all(&template_lib_text, "uint256($v)")
            .to_string();

        (solidity_pairing_lib, template_text, template_lib_text)
    }
}

const CONTRACT_LIB_TEMPLATE: &str = r#"
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
import "./Pairing.sol";
library VerifierLib {
    struct VerifyingKey {
        Pairing.G2Point a;
        Pairing.G1Point b;
        Pairing.G2Point c;
        Pairing.G2Point gamma;
        Pairing.G1Point gamma_beta_1;
        Pairing.G2Point gamma_beta_2;
        Pairing.G2Point z;
        Pairing.G1Point[] ic;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G1Point a_p;
        Pairing.G2Point b;
        Pairing.G1Point b_p;
        Pairing.G1Point c;
        Pairing.G1Point c_p;
        Pairing.G1Point h;
        Pairing.G1Point k;
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
pragma solidity ^0.8.0;
import "./Pairing.sol";
import "./VerifierLib.sol";
contract Verifier {
    function verifyingKey() pure internal returns (VerifierLib.VerifyingKey memory vk) {
        vk.a = Pairing.G2Point(<%vk_a%>);
        vk.b = Pairing.G1Point(<%vk_b%>);
        vk.c = Pairing.G2Point(<%vk_c%>);
        vk.gamma = Pairing.G2Point(<%vk_g%>);
        vk.gamma_beta_1 = Pairing.G1Point(<%vk_gb1%>);
        vk.gamma_beta_2 = Pairing.G2Point(<%vk_gb2%>);
        vk.z = Pairing.G2Point(<%vk_z%>);
        vk.ic = new Pairing.G1Point[](<%vk_ic_length%>);
        <%vk_ic_pts%>
    }

    function verify(uint[] memory input, VerifierLib.Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifierLib.VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.ic.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.ic[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.ic[0]);
        if (!Pairing.pairingProd2(proof.a, vk.a, Pairing.negate(proof.a_p), Pairing.P2())) return false;
        if (!Pairing.pairingProd2(vk.b, proof.b, Pairing.negate(proof.b_p), Pairing.P2())) return false;
        if (!Pairing.pairingProd2(proof.c, vk.c, Pairing.negate(proof.c_p), Pairing.P2())) return false;
        if (!Pairing.pairingProd3(
            proof.k, vk.gamma,
            Pairing.negate(Pairing.addition(vk_x, Pairing.addition(proof.a, proof.c))), vk.gamma_beta_2,
            Pairing.negate(vk.gamma_beta_1), proof.b
        )) return false;
        if (!Pairing.pairingProd3(
                Pairing.addition(vk_x, proof.a), proof.b,
                Pairing.negate(proof.h), vk.z,
                Pairing.negate(proof.c), Pairing.P2()
        )) return false;
        return true;
    }
    function verifyTx(
            VerifierLib.Proof memory proof<%input_argument%>
        ) public view returns (bool) {
        require(input.length == <%vk_input_length%>, "invalid input length");
        return verify(input, proof);
    }
}
"#;
