extern crate libc;

use self::libc::{c_char, c_int};
use ir;
use proof_system::bn128::utils::libsnark::{prepare_generate_proof, prepare_setup};
use proof_system::bn128::utils::solidity::{
    SOLIDITY_G2_ADDITION_LIB, SOLIDITY_PAIRING_LIB, SOLIDITY_PAIRING_LIB_V2,
};
use proof_system::ProofSystem;

use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};

use zokrates_field::field::FieldPrime;

pub struct PGHR13 {}

impl PGHR13 {
    pub fn new() -> PGHR13 {
        PGHR13 {}
    }
}

extern "C" {
    fn _pghr13_setup(
        A: *const u8,
        B: *const u8,
        C: *const u8,
        A_len: c_int,
        B_len: c_int,
        C_len: c_int,
        constraints: c_int,
        variables: c_int,
        inputs: c_int,
        pk_path: *const c_char,
        vk_path: *const c_char,
    ) -> bool;

    fn _pghr13_generate_proof(
        pk_path: *const c_char,
        proof_path: *const c_char,
        public_inputs: *const u8,
        public_inputs_length: c_int,
        private_inputs: *const u8,
        private_inputs_length: c_int,
    ) -> bool;
}

impl ProofSystem for PGHR13 {
    fn setup(&self, program: ir::Prog<FieldPrime>, pk_path: &str, vk_path: &str) {
        let (
            a_arr,
            b_arr,
            c_arr,
            a_vec,
            b_vec,
            c_vec,
            num_constraints,
            num_variables,
            num_inputs,
            pk_path_cstring,
            vk_path_cstring,
        ) = prepare_setup(program, pk_path, vk_path);

        unsafe {
            _pghr13_setup(
                a_arr.as_ptr(),
                b_arr.as_ptr(),
                c_arr.as_ptr(),
                a_vec.len() as i32,
                b_vec.len() as i32,
                c_vec.len() as i32,
                num_constraints as i32,
                num_variables as i32,
                num_inputs as i32,
                pk_path_cstring.as_ptr(),
                vk_path_cstring.as_ptr(),
            );
        }
    }

    fn generate_proof(
        &self,
        program: ir::Prog<FieldPrime>,
        witness: ir::Witness<FieldPrime>,
        pk_path: &str,
        proof_path: &str,
    ) -> bool {
        let (
            pk_path_cstring,
            proof_path_cstring,
            public_inputs_arr,
            public_inputs_length,
            private_inputs_arr,
            private_inputs_length,
        ) = prepare_generate_proof(program, witness, pk_path, proof_path);

        println!(
            "{:?}",
            (pk_path_cstring.clone(), proof_path_cstring.clone(),)
        );

        unsafe {
            _pghr13_generate_proof(
                pk_path_cstring.as_ptr(),
                proof_path_cstring.as_ptr(),
                public_inputs_arr[0].as_ptr(),
                public_inputs_length as i32,
                private_inputs_arr[0].as_ptr(),
                private_inputs_length as i32,
            )
        }
    }

    fn export_solidity_verifier(&self, reader: BufReader<File>, is_abiv2: bool) -> String {
        let mut lines = reader.lines();

        let (mut template_text, solidity_pairing_lib) = if is_abiv2 {
            (
                String::from(CONTRACT_TEMPLATE_V2),
                String::from(SOLIDITY_PAIRING_LIB_V2),
            )
        } else {
            (
                String::from(CONTRACT_TEMPLATE),
                String::from(SOLIDITY_PAIRING_LIB),
            )
        };

        let ic_template = String::from("vk.ic[index] = Pairing.G1Point(points);"); //copy this for each entry

        //replace things in template
        let vk_regex = Regex::new(r#"(<%vk_[^i%]*%>)"#).unwrap();
        let vk_ic_len_regex = Regex::new(r#"(<%vk_ic_length%>)"#).unwrap();
        let vk_ic_index_regex = Regex::new(r#"index"#).unwrap();
        let vk_ic_points_regex = Regex::new(r#"points"#).unwrap();
        let vk_ic_repeat_regex = Regex::new(r#"(<%vk_ic_pts%>)"#).unwrap();
        let vk_input_len_regex = Regex::new(r#"(<%vk_input_length%>)"#).unwrap();

        for _ in 0..7 {
            let current_line: String = lines
                .next()
                .expect("Unexpected end of file in verification key!")
                .unwrap();
            let current_line_split: Vec<&str> = current_line.split("=").collect();
            assert_eq!(current_line_split.len(), 2);
            template_text = vk_regex
                .replace(template_text.as_str(), current_line_split[1].trim())
                .into_owned();
        }

        let current_line: String = lines
            .next()
            .expect("Unexpected end of file in verification key!")
            .unwrap();
        let current_line_split: Vec<&str> = current_line.split("=").collect();
        assert_eq!(current_line_split.len(), 2);
        let ic_count: i32 = current_line_split[1].trim().parse().unwrap();

        template_text = vk_ic_len_regex
            .replace(template_text.as_str(), format!("{}", ic_count).as_str())
            .into_owned();
        template_text = vk_input_len_regex
            .replace(template_text.as_str(), format!("{}", ic_count - 1).as_str())
            .into_owned();

        let mut ic_repeat_text = String::new();
        for x in 0..ic_count {
            let mut curr_template = ic_template.clone();
            let current_line: String = lines
                .next()
                .expect("Unexpected end of file in verification key!")
                .unwrap();
            let current_line_split: Vec<&str> = current_line.split("=").collect();
            assert_eq!(current_line_split.len(), 2);
            curr_template = vk_ic_index_regex
                .replace(curr_template.as_str(), format!("{}", x).as_str())
                .into_owned();
            curr_template = vk_ic_points_regex
                .replace(curr_template.as_str(), current_line_split[1].trim())
                .into_owned();
            ic_repeat_text.push_str(curr_template.as_str());
            if x < ic_count - 1 {
                ic_repeat_text.push_str("\n        ");
            }
        }
        template_text = vk_ic_repeat_regex
            .replace(template_text.as_str(), ic_repeat_text.as_str())
            .into_owned();

        let re = Regex::new(r"(?P<v>0[xX][0-9a-fA-F]{64})").unwrap();
        template_text = re.replace_all(&template_text, "uint256($v)").to_string();

        format!(
            "{}{}{}",
            SOLIDITY_G2_ADDITION_LIB, solidity_pairing_lib, template_text
        )
    }

    fn export_avm_verifier(&self, reader: BufReader<File>) -> String {
        let mut lines = reader.lines();
        let mut template_text = String::from(CONTRACT_AVM_TEMPLATE);

        let ic_template = String::from("ic[index] = new G1Point(coord, coord);"); //copy this for each entry

        //replace things in template
        let vk_regex = Regex::new(r#"(<%vk_[^i%]*%>)"#).unwrap();
        let vk_ic_len_regex = Regex::new(r#"(<%vk_ic_length%>)"#).unwrap();
        let vk_ic_index_regex = Regex::new(r#"index"#).unwrap();
        let vk_ic_points_regex = Regex::new(r#"coord"#).unwrap();
        let vk_ic_repeat_regex = Regex::new(r#"(<%vk_ic_pts%>)"#).unwrap();

        let vk_value = Regex::new(r"(?P<v>0[xX][0-9a-fA-F]{64})").unwrap();

        for _ in 0..7 {
            let current_line: String = lines
                .next()
                .expect("Unexpected end of file in verification key!")
                .unwrap();
            let current_line_split: Vec<&str> = current_line.split("=").collect();
            assert_eq!(current_line_split.len(), 2);

            let mut values = Vec::new();
            for value in vk_value.find_iter(current_line_split[1]) {
                values.push(value.as_str());
            }

            if values.len() == 4 {
                template_text = vk_regex.replace(template_text.as_str(), values[1])
                    .into_owned();
                template_text = vk_regex.replace(template_text.as_str(), values[0])
                    .into_owned();
                template_text = vk_regex.replace(template_text.as_str(), values[3])
                    .into_owned();
                template_text = vk_regex.replace(template_text.as_str(), values[2])
                    .into_owned();
            } else if values.len() == 2 {
                template_text = vk_regex.replace(template_text.as_str(), values[0])
                    .into_owned();
                template_text = vk_regex.replace(template_text.as_str(), values[1])
                    .into_owned();
            }
        }

        let current_line: String = lines
            .next()
            .expect("Unexpected end of file in verification key!")
            .unwrap();
        let current_line_split: Vec<&str> = current_line.split("=").collect();
        assert_eq!(current_line_split.len(), 2);
        let ic_count: i32 = current_line_split[1].trim().parse().unwrap();

        template_text = vk_ic_len_regex
            .replace(template_text.as_str(), format!("{}", ic_count).as_str())
            .into_owned();

        let mut ic_repeat_text = String::new();
        for x in 0..ic_count {
            let mut curr_template = ic_template.clone();
            let current_line: String = lines
                .next()
                .expect("Unexpected end of file in verification key!")
                .unwrap();
            let current_line_split: Vec<&str> = current_line.split("=").collect();
            assert_eq!(current_line_split.len(), 2);
            curr_template = vk_ic_index_regex
                .replace(curr_template.as_str(), format!("{}", x).as_str())
                .into_owned();
            for value in vk_value.find_iter(current_line_split[1]) {
                curr_template = vk_ic_points_regex
                    .replace(curr_template.as_str(), value.as_str())
                    .into_owned();
            }

            ic_repeat_text.push_str(curr_template.as_str());
            if x < ic_count - 1 {
                ic_repeat_text.push_str("\n        ");
            }
        }
        template_text = vk_ic_repeat_regex
            .replace(template_text.as_str(), ic_repeat_text.as_str())
            .into_owned();

        let re = Regex::new(r"0[xX](?P<v>[0-9a-fA-F]{64})").unwrap();
        template_text = re.replace_all(&template_text, "\"$v\"").to_string();
        format!("{}", template_text)
    }
}

const CONTRACT_TEMPLATE_V2: &str = r#"contract Verifier {
    using Pairing for *;
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
        Pairing.G1Point k;
        Pairing.G1Point h;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
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
    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.ic.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.ic[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.ic[0]);
        if (!Pairing.pairingProd2(proof.a, vk.a, Pairing.negate(proof.a_p), Pairing.P2())) return 1;
        if (!Pairing.pairingProd2(vk.b, proof.b, Pairing.negate(proof.b_p), Pairing.P2())) return 2;
        if (!Pairing.pairingProd2(proof.c, vk.c, Pairing.negate(proof.c_p), Pairing.P2())) return 3;
        if (!Pairing.pairingProd3(
            proof.k, vk.gamma,
            Pairing.negate(Pairing.addition(vk_x, Pairing.addition(proof.a, proof.c))), vk.gamma_beta_2,
            Pairing.negate(vk.gamma_beta_1), proof.b
        )) return 4;
        if (!Pairing.pairingProd3(
                Pairing.addition(vk_x, proof.a), proof.b,
                Pairing.negate(proof.h), vk.z,
                Pairing.negate(proof.c), Pairing.P2()
        )) return 5;
        return 0;
    }
    event Verified(string s);
    function verifyTx(
            Proof memory proof,
            uint[<%vk_input_length%>] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            emit Verified("Transaction successfully verified.");
            return true;
        } else {
            return false;
        }
    }
}
"#;

const CONTRACT_TEMPLATE: &str = r#"contract Verifier {
    using Pairing for *;
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
        Pairing.G1Point k;
        Pairing.G1Point h;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
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
    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.ic.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.ic[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.ic[0]);
        if (!Pairing.pairingProd2(proof.a, vk.a, Pairing.negate(proof.a_p), Pairing.P2())) return 1;
        if (!Pairing.pairingProd2(vk.b, proof.b, Pairing.negate(proof.b_p), Pairing.P2())) return 2;
        if (!Pairing.pairingProd2(proof.c, vk.c, Pairing.negate(proof.c_p), Pairing.P2())) return 3;
        if (!Pairing.pairingProd3(
            proof.k, vk.gamma,
            Pairing.negate(Pairing.addition(vk_x, Pairing.addition(proof.a, proof.c))), vk.gamma_beta_2,
            Pairing.negate(vk.gamma_beta_1), proof.b
        )) return 4;
        if (!Pairing.pairingProd3(
                Pairing.addition(vk_x, proof.a), proof.b,
                Pairing.negate(proof.h), vk.z,
                Pairing.negate(proof.c), Pairing.P2()
        )) return 5;
        return 0;
    }
    event Verified(string s);
    function verifyTx(
            uint[2] memory a,
            uint[2] memory a_p,
            uint[2][2] memory b,
            uint[2] memory b_p,
            uint[2] memory c,
            uint[2] memory c_p,
            uint[2] memory h,
            uint[2] memory k,
            uint[<%vk_input_length%>] memory input
        ) public returns (bool r) {
        Proof memory proof;
        proof.a = Pairing.G1Point(a[0], a[1]);
        proof.a_p = Pairing.G1Point(a_p[0], a_p[1]);
        proof.b = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.b_p = Pairing.G1Point(b_p[0], b_p[1]);
        proof.c = Pairing.G1Point(c[0], c[1]);
        proof.c_p = Pairing.G1Point(c_p[0], c_p[1]);
        proof.h = Pairing.G1Point(h[0], h[1]);
        proof.k = Pairing.G1Point(k[0], k[1]);
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            emit Verified("Transaction successfully verified.");
            return true;
        } else {
            return false;
        }
    }
}
"#;

const CONTRACT_AVM_TEMPLATE: &str = r#"// This file is MIT Licensed
package org.oan.tetryon;

import avm.Blockchain;
import org.aion.avm.tooling.abi.Callable;

import java.math.BigInteger;
import java.util.Arrays;

@SuppressWarnings({"WeakerAccess", "unused"})
public class Verifier {

    protected static class VerifyingKey {

        public final G2Point a;
        public final G1Point b;
        public final G2Point c;
        public final G2Point gamma;
        public final G1Point gamma_beta_1;
        public final G2Point gamma_beta_2;
        public final G2Point z;
        public final G1Point[] ic;

        public VerifyingKey(G2Point a, G1Point b, G2Point c,
                            G2Point gamma, G1Point gamma_beta_1, G2Point gamma_beta_2,
                            G2Point z, G1Point[] ic) {
            this.a = a;
            this.b = b;
            this.c = c;
            this.gamma = gamma;
            this.gamma_beta_1 = gamma_beta_1;
            this.gamma_beta_2 = gamma_beta_2;
            this.z = z;
            this.ic = ic;
        }
    }

    public static class Proof {
        public final G1Point a;
        public final G1Point a_p;
        public final G2Point b;
        public final G1Point b_p;
        public final G1Point c;
        public final G1Point c_p;
        public final G1Point k;
        public final G1Point h;

        public Proof(G1Point a, G1Point a_p,
                     G2Point b, G1Point b_p,
                     G1Point c, G1Point c_p,
                     G1Point k, G1Point h) {
            this.a = a;
            this.a_p = a_p;
            this.b = b;
            this.b_p = b_p;
            this.c = c;
            this.c_p = c_p;
            this.k = k;
            this.h = h;
        }

        // serialized as a | b | c
        public byte[] serialize() {
            byte[] s = new byte[Fp.ELEMENT_SIZE*18];

            byte[] aByte = G1.serialize(this.a);
            byte[] apByte = G1.serialize(this.a_p);
            byte[] bByte = G2.serialize(this.b);
            byte[] bpByte = G1.serialize(this.b_p);
            byte[] cByte = G1.serialize(this.c);
            byte[] cpByte = G1.serialize(this.c_p);
            byte[] kByte = G1.serialize(this.k);
            byte[] hByte = G1.serialize(this.h);

            System.arraycopy(aByte, 0, s, 0, aByte.length);
            System.arraycopy(apByte, 0, s, 2*Fp.ELEMENT_SIZE, apByte.length);
            System.arraycopy(bByte, 0, s, 4*Fp.ELEMENT_SIZE, bByte.length);
            System.arraycopy(bpByte, 0, s, 8*Fp.ELEMENT_SIZE, bpByte.length);
            System.arraycopy(cByte, 0, s, 10*Fp.ELEMENT_SIZE, cByte.length);
            System.arraycopy(cpByte, 0, s, 12*Fp.ELEMENT_SIZE, cpByte.length);
            System.arraycopy(kByte, 0, s, 14*Fp.ELEMENT_SIZE, kByte.length);
            System.arraycopy(hByte, 0, s, 16*Fp.ELEMENT_SIZE, hByte.length);

            return s;
        }

        public static Proof deserialize(byte[] data) {
            Blockchain.require(data.length == 18*Fp.ELEMENT_SIZE);

            G1Point a = G1.deserialize(Arrays.copyOfRange(data, 0, 2*Fp.ELEMENT_SIZE));
            G1Point a_p = G1.deserialize(Arrays.copyOfRange(data, 2*Fp.ELEMENT_SIZE, 4*Fp.ELEMENT_SIZE));
            G2Point b = G2.deserialize(Arrays.copyOfRange(data, 4*Fp.ELEMENT_SIZE, 8*Fp.ELEMENT_SIZE));
            G1Point b_p = G1.deserialize(Arrays.copyOfRange(data, 8*Fp.ELEMENT_SIZE, 10*Fp.ELEMENT_SIZE));
            G1Point c = G1.deserialize(Arrays.copyOfRange(data, 10*Fp.ELEMENT_SIZE, 12*Fp.ELEMENT_SIZE));
            G1Point c_p = G1.deserialize(Arrays.copyOfRange(data, 12*Fp.ELEMENT_SIZE, 14*Fp.ELEMENT_SIZE));
            G1Point k = G1.deserialize(Arrays.copyOfRange(data, 14*Fp.ELEMENT_SIZE, 16*Fp.ELEMENT_SIZE));
            G1Point h = G1.deserialize(Arrays.copyOfRange(data, 16*Fp.ELEMENT_SIZE, 18*Fp.ELEMENT_SIZE));

            return new Proof(a, a_p, b, b_p, c, c_p, k, h);
        }
    }

    protected static VerifyingKey verifyingKey() {
        G2Point a = new G2Point(<%vk_axx%>,
                <%vk_axy%>,
                <%vk_ayx%>,
                <%vk_ayy%>);

        G1Point b = new G1Point(<%vk_bx%>,
                <%vk_by%>);

        G2Point c = new G2Point(<%vk_cxx%>,
                <%vk_cxy%>,
                <%vk_cyx%>,
                <%vk_cyy%>);

        G2Point gamma = new G2Point(<%vk_gxx%>,
                <%vk_gxy%>,
                <%vk_gyx%>,
                <%vk_gyy%>);

        G1Point gamma_beta_1 = new G1Point(<%vk_gbax%>,
                <%vk_gbay%>);

        G2Point gamma_beta_2 = new G2Point(<%vk_gbbxx%>,
                <%vk_gbbxy%>,
                <%vk_gbbyx%>,
                <%vk_gbbyy%>);

        G2Point z = new G2Point(<%vk_zxx%>,
                <%vk_zxy%>,
                <%vk_zyx%>,
                <%vk_zyy%>);

        G1Point[] ic = new G1Point[<%vk_ic_length%>];
        <%vk_ic_pts%>

        return new VerifyingKey(a, b, c, gamma, gamma_beta_1, gamma_beta_2, z, ic);
    }

    static final BigInteger snarkScalarField = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");

    public static boolean verify(BigInteger[] input, Proof proof) throws Exception {
        VerifyingKey vk = verifyingKey();
        Blockchain.require(input.length + 1 == vk.ic.length);
        G1Point X = new G1Point(Fp.zero(), Fp.zero());
        for (int i = 0; i < input.length; i++) {
            Blockchain.require(input[i].compareTo(snarkScalarField) < 0);
            G1Point tmp = G1.mul(vk.ic[i + 1], input[i]);
            if (i == 0)
                X = tmp;
            else
                X = G1.add(X, tmp);
        }
        X = G1.add(X, vk.ic[0]);

        if (!Pairing.pairingProd2(proof.a, vk.a, G1.negate(proof.a_p), G2.G2_P)) {
            return false;
        }

        if (!Pairing.pairingProd2(vk.b, proof.b, G1.negate(proof.b_p), G2.G2_P)) {
            return false;
        }

        if (!Pairing.pairingProd2(proof.c, vk.c, G1.negate(proof.c_p), G2.G2_P)) {
            return false;
        }

        if (!Pairing.pairingProd3(proof.k, vk.gamma,
                G1.negate(G1.add(X, G1.add(proof.a, proof.c))), vk.gamma_beta_2,
                G1.negate(vk.gamma_beta_1), proof.b)) {
            return false;
        }

        return Pairing.pairingProd3(G1.add(X, proof.a), proof.b,
                G1.negate(proof.h), vk.z,
                G1.negate(proof.c), G2.G2_P);
    }

    @Callable
    public static boolean verify(BigInteger[] input, byte[] proof) {
        Blockchain.println("verify() called");

        try {
            if (verify(input, Proof.deserialize(proof))) {
                Blockchain.log("VerifySnark".getBytes(), BigInteger.ONE.toByteArray());
                return true;
            }
        } catch (Exception e) {
            Blockchain.println("verify() failed with exception: " + e.getMessage());
        }

        Blockchain.log("VerifySnark".getBytes(), BigInteger.ZERO.toByteArray());
        return false;
    }
}
"#;
