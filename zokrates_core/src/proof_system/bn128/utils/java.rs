pub const JAVA_LIB_FP: &str = r#"// This file is MIT Licensed
package org.oan.tetryon;

import java.math.BigInteger;

/**
 * Represents an element of field F_p.
 */
public class Fp {
    // an element in Fp can be encoded in 32 bytes
    public static int ELEMENT_SIZE = 32;

    public static final BigInteger FIELD_MODULUS = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");

    public final BigInteger c0;

    public Fp(BigInteger c0) {
        this.c0 = c0;
    }

    public Fp(long c0) {
        this(BigInteger.valueOf(c0));
    }

    public static Fp zero() {
        return new Fp(BigInteger.ZERO);
    }

    public boolean isZero() {
        return c0.equals(BigInteger.ZERO);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Fp that = (Fp) o;
        return this.c0.equals(that.c0);
    }

    @Override
    public int hashCode() {
        return c0.hashCode();
    }

    @Override
    public String toString() {
        return Util.bytesToHex(c0.toByteArray());
    }
}

"#;

pub const JAVA_LIB_FP2: &str = r#"// This file is MIT Licensed
package org.oan.tetryon;

import java.math.BigInteger;

/**
 * Represents an element of the field F_p^2 (F_p[i]/(i^2 + 1)).
 *
 * F_q2(a + bi, a is real coeff, b is imaginary)
 */
public class Fp2 {
    public static final BigInteger FIELD_MODULUS = new BigInteger("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16);

    public final BigInteger a;
    public final BigInteger b;

    // (a + bi, a is real coeff, b is imaginary)
    public Fp2(BigInteger a, BigInteger b) {
        this.a = a;
        this.b = b;
    }

    public static Fp2 zero() {
        return new Fp2(BigInteger.ZERO, BigInteger.ZERO);
    }

    public static Fp2 one() {
        return new Fp2(BigInteger.ONE, BigInteger.ZERO);
    }

    public boolean isZero() {
        return a.equals(BigInteger.ZERO) && b.equals(BigInteger.ZERO);
    }

    public Fp2 add(Fp2 that) {
        return new Fp2(
                addmod(this.a, that.a, FIELD_MODULUS),
                addmod(this.b, that.b, FIELD_MODULUS)
        );
    }

    public Fp2 subtract(Fp2 that) {
        return new Fp2(
                submod(this.a, that.a, FIELD_MODULUS),
                submod(this.b, that.b, FIELD_MODULUS)
        );
    }

    public Fp2 multiply(Fp2 that) {
        /*
         * (a + bx) * (c + dx) // 1 + x^2
         * = (ac - bd) + (ad + bc)x
         */
        return new Fp2(
                submod(mulmod(this.a, that.a, FIELD_MODULUS), mulmod(this.b, that.b, FIELD_MODULUS), FIELD_MODULUS),
                addmod(mulmod(this.a, that.b, FIELD_MODULUS), mulmod(this.b, that.a, FIELD_MODULUS), FIELD_MODULUS)
        );
    }

    public Fp2 multiply(BigInteger s) {
        return new Fp2(
                mulmod(this.a, s, FIELD_MODULUS),
                mulmod(this.b, s, FIELD_MODULUS)
        );
    }

    public Fp2 divide(Fp2 other) {
        return multiply(other.inverse());
    }

    public Fp2 inverse() {
        /*
         * Assume this = a + bx and inverse = c + dx, then
         * (ac - bd) + (ad + bc)x = 1, then
         * ac - bd = 1
         * ad + bc = 0.
         * Solving the above linear equations, we get
         * c = a * (a^2 + b^2)^-1
         * d = -b * (a^2 + b^2)^-1
         */
        BigInteger inv = addmod(
                mulmod(this.b, this.b, FIELD_MODULUS),
                mulmod(this.a, this.a, FIELD_MODULUS),
                FIELD_MODULUS
        ).modInverse(FIELD_MODULUS);

        return new Fp2(
                mulmod(this.a, inv, FIELD_MODULUS),
                FIELD_MODULUS.subtract(mulmod(this.b, inv, FIELD_MODULUS))
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Fp2 that = (Fp2) o;
        return this.a.equals(that.a) && this.b.equals(that.b);
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = 31 * result + this.a.hashCode();
        result = 31 * result + this.b.hashCode();

        return result;
    }

    private static BigInteger addmod(BigInteger a, BigInteger b, BigInteger c) {
        return a.add(b).mod(c);
    }

    private static BigInteger submod(BigInteger a, BigInteger b, BigInteger c) {
        return a.subtract(b).mod(c);
    }

    private static BigInteger mulmod(BigInteger a, BigInteger b, BigInteger c) {
        return a.multiply(b).mod(c);
    }

    @Override
    public String toString() {
        return "(" + Util.bytesToHex(a.toByteArray()) + ", " + Util.bytesToHex(b.toByteArray()) + ")";
    }
}

"#;

pub const JAVA_LIB_G1: &str = r#"// This file is MIT Licensed
package org.oan.tetryon;

import avm.AltBn128;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * A collection of Elliptic Curve operations on G1 for alt_bn128. This implementation is
 * heavily based on the EC API exposed by the AVM.
 *
 * <p>
 * Curve definition: y^2 = x^3 + b
 * <p>
 */
public class G1 {

    // points in G1 are encoded like so: [p.x || p.y]. Each coordinate is 32-byte aligned.
    public static int POINT_SIZE = 2 * Fp.ELEMENT_SIZE;

    public static byte[] serialize(G1Point p) {
        byte[] data = new byte[POINT_SIZE];

        byte[] px = p.x.c0.toByteArray();
        System.arraycopy(px, 0, data, Fp.ELEMENT_SIZE - px.length, px.length);

        byte[] py = p.y.c0.toByteArray();
        System.arraycopy(py, 0, data, Fp.ELEMENT_SIZE*2 - py.length, py.length);

        return data;
    }

    public static G1Point deserialize(byte[] data) {
        byte[] pxData = Arrays.copyOfRange(data, 0, Fp.ELEMENT_SIZE);
        byte[] pyData = Arrays.copyOfRange(data, Fp.ELEMENT_SIZE, data.length);
        Fp p1x = new Fp(new BigInteger(pxData));
        Fp p1y = new Fp(new BigInteger(pyData));
        G1Point p1 = new G1Point(p1x, p1y);
        return p1;
    }


    // The prime q in the base field F_q for G1
    private static final BigInteger q = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");

    public static G1Point negate(G1Point p) {
        if (p.isZero()) {
            return new G1Point(Fp.zero(), Fp.zero());
        }
        return new G1Point(p.x, new Fp(q.subtract(p.y.c0.mod(q))));
    }

    public static G1Point add(G1Point p1, G1Point p2) throws Exception {
        byte[] p1data = serialize(p1);
        byte[] p2data = serialize(p2);
        byte[] resultData = AltBn128.g1EcAdd(p1data, p2data);
        G1Point result = deserialize(resultData);
        return result;
    }

    public static G1Point mul(G1Point p, BigInteger s) throws Exception {
        byte[] pdata = serialize(p);

        byte[] resultData = AltBn128.g1EcMul(pdata, s);
        G1Point result = deserialize(resultData);
        return result;
    }
}

"#;

pub const JAVA_LIB_G1POINT: &str = r#"// This file is MIT Licensed
package org.oan.tetryon;

import java.math.BigInteger;

/**
 * Represents a point on G1.
 */
public class G1Point {
    public final Fp x;
    public final Fp y;

    public G1Point(String x, String y) {
        this.x = new Fp(new BigInteger(x, 16));
        this.y = new Fp(new BigInteger(y, 16));
    }

    public G1Point(Fp x, Fp y) {
        this.x = x;
        this.y = y;
    }

    public boolean isZero() {
        return x.isZero() && y.isZero();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        G1Point that = (G1Point) o;
        return this.x.equals(that.x) && this.y.equals(that.y);
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = 31 * result + this.x.hashCode();
        result = 31 * result + this.y.hashCode();

        return result;
    }

    @Override
    public String toString() {
        return "(" + x + ", " + y + ")";
    }
}

"#;

pub const JAVA_LIB_G2: &str = r#"// This file is MIT Licensed
package org.oan.tetryon;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * A collection of Elliptic Curve operations on G2 for alt_bn128.
 * <p>
 * Curve definition: y^2 = x^3 + b
 * <p>
 * Ported from https://github.com/musalbas/solidity-BN256G2/blob/master/BN256G2.sol
 */
public class G2 {

    // points in G2, encoded like so: [p1[0].x || p1[0].y || p1[1].x || p2[1].y || p2[0].x]. Each coordinate is 32-byte aligned.
    public static int POINT_SIZE = 4 * Fp.ELEMENT_SIZE;

    public static byte[] serialize(G2Point p) {
        byte[] data = new byte[POINT_SIZE]; // zero byte array

        byte[] px1 = p.x.a.toByteArray();
        System.arraycopy(px1, 0, data, Fp.ELEMENT_SIZE*1 - px1.length, px1.length);

        byte[] px2 = p.x.b.toByteArray();
        System.arraycopy(px2, 0, data, Fp.ELEMENT_SIZE*2 - px2.length, px2.length);

        byte[] py1 = p.y.a.toByteArray();
        System.arraycopy(py1, 0, data, Fp.ELEMENT_SIZE*3 - py1.length, py1.length);

        byte[] py2 = p.y.b.toByteArray();
        System.arraycopy(py2, 0, data, Fp.ELEMENT_SIZE*4 - py2.length, py2.length);
        return data;
    }

    public static G2Point deserialize(byte[] data) {

        byte[] px1Data = Arrays.copyOfRange(data, 0, Fp.ELEMENT_SIZE);
        byte[] px2Data = Arrays.copyOfRange(data, 1*Fp.ELEMENT_SIZE, 2*Fp.ELEMENT_SIZE);
        byte[] py1Data = Arrays.copyOfRange(data, 2*Fp.ELEMENT_SIZE, 3*Fp.ELEMENT_SIZE);
        byte[] py2Data = Arrays.copyOfRange(data, 3*Fp.ELEMENT_SIZE, data.length);

        Fp2 x = new Fp2(new BigInteger(px1Data), new BigInteger(px2Data));
        Fp2 y = new Fp2(new BigInteger(py1Data), new BigInteger(py2Data));

        G2Point p = new G2Point(x, y);

        return p;
    }

    public static final Fp2 TWIST_B = new Fp2(
            new BigInteger("2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5", 16),
            new BigInteger("9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2", 16)
    );

    /**
     * Adds two points.
     *
     * @param p1 the first point
     * @param p2 the second point
     * @return p1 + p2
     */
    public static G2Point ECTwistAdd(G2Point p1, G2Point p2) {
        if (p1.isZero()) {
            if (!p2.isZero()) {
                assert isOnCurve(p2);
            }
            return p2;
        } else if (p2.isZero()) {
            assert isOnCurve(p1);
            return p1;
        }

        assert isOnCurve(p1);
        assert isOnCurve(p2);

        G2Point p3 = ECTwistAdd(toJacobian(p1), toJacobian(p2)).toAffine();

        return p3;
    }

    /**
     * Multiplies a point by a scalar.
     *
     * @param p the point
     * @param s the multiplier
     * @return s * p
     */
    public static G2Point ECTwistMul(G2Point p, BigInteger s) {
        if (!p.isZero()) {
            assert isOnCurve(p);
        }

        G2Point p2 = ECTwistMul(toJacobian(p), s).toAffine();

        return p2;
    }

    protected static boolean isOnCurve(G2Point p) {
        Fp2 y2 = p.y.multiply(p.y); // y^2
        Fp2 x3 = p.x.multiply(p.x).multiply(p.x); // x^3
        Fp2 diff = y2.subtract(x3).subtract(TWIST_B); // y^2 - x^3 - B

        return diff.isZero();
    }

    protected static JacobianPoint ECTwistAdd(JacobianPoint p1, JacobianPoint p2) {
        if (p1.z.isZero()) {
            return p2;
        } else if (p2.z.isZero()) {
            return p1;
        }

        Fp2 U1 = p2.y.multiply(p1.z); // U1 = p2.y * p1.z
        Fp2 U2 = p1.y.multiply(p2.z); // U2 = p1.y * p2.z
        Fp2 V1 = p2.x.multiply(p1.z); // V1 = p2.x * p1.z
        Fp2 V2 = p1.x.multiply(p2.z); // V2 = p1.x * p2.z

        if (p2.x.equals(V2)) {
            if (p2.y.equals(U2)) {
                return ECTwistDouble(p1);
            }

            return new JacobianPoint(Fp2.one(), Fp2.one(), Fp2.zero());
        }

        Fp2 W = p1.z.multiply(p2.z); // W = p1.z * p2.z
        Fp2 V = V1.subtract(V2); // V = V1 - V2
        Fp2 V_2 = V.multiply(V);
        Fp2 V_3 = V_2.multiply(V);
        // z = V^3 * W
        Fp2 z = V_3.multiply(W);

        Fp2 U = U1.subtract(U2); // U = U1 - U2
        Fp2 U_2 = U.multiply(U);
        Fp2 A = U_2.multiply(W).subtract(V_3).subtract(V_2.multiply(V2).multiply(BigInteger.TWO));
        // x = V * (U^2 * W - V^3 - 2 * V^2 * V2)
        Fp2 x = V.multiply(A);

        // y = U * (v^2 * V2 - A) - V^3 * U2
        Fp2 y = U.multiply(V_2.multiply(V2).subtract(A)).subtract(V_3.multiply(U2));

        return new JacobianPoint(x, y, z);
    }

    protected static JacobianPoint ECTwistMul(JacobianPoint p, BigInteger s) {
        JacobianPoint p2 = new JacobianPoint(Fp2.zero(), Fp2.zero(), Fp2.zero());

        while (!s.equals(BigInteger.ZERO)) {
            if (s.testBit(0)) {
                p2 = ECTwistAdd(p2, p);
            }

            p = ECTwistDouble(p);

            s = s.divide(BigInteger.TWO);
        }

        return p2;
    }

    protected static JacobianPoint ECTwistDouble(JacobianPoint p) {
        Fp2 W = p.x.multiply(p.x).multiply(BigInteger.valueOf(3)); // W = 3 * x * x
        Fp2 S = p.y.multiply(p.z); // S = y * z
        Fp2 B = p.x.multiply(p.y).multiply(S); // B = x * y * S
        Fp2 H = W.multiply(W).subtract(B.multiply(BigInteger.valueOf(8))); // H = W * W - 8 * B
        Fp2 S_2 = S.multiply(S); // S^2
        Fp2 S_3 = S_2.multiply(S); // S^3

        // y = W * (4 * B - H) - 8 * y * y * S^2
        Fp2 y = W.multiply(B.multiply(BigInteger.valueOf(4)).subtract(H))
                .subtract(p.y.multiply(p.y).multiply(BigInteger.valueOf(8)).multiply(S_2));
        // x = 2 * H * S
        Fp2 x = H.multiply(S).multiply(BigInteger.TWO);
        // z = 8 * S^3
        Fp2 z = S_3.multiply(BigInteger.valueOf(8));

        return new JacobianPoint(x, y, z);
    }

    protected static JacobianPoint toJacobian(G2Point p) {
        return p.isZero() ? new JacobianPoint(Fp2.one(), Fp2.one(), Fp2.zero()) : new G2.JacobianPoint(p.x, p.y, Fp2.one());
    }

    public static class JacobianPoint {
        public final Fp2 x;
        public final Fp2 y;
        public final Fp2 z;

        public JacobianPoint(Fp2 x, Fp2 y, Fp2 z) {
            this.x = x;
            this.y = y;
            this.z = z;
        }

        public G2Point toAffine() {
            if (z.isZero()) {
                return new G2Point(Fp2.zero(), Fp2.zero());
            } else {
                Fp2 inv = z.inverse();
                return new G2Point(x.multiply(inv), y.multiply(inv));
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            JacobianPoint that = (JacobianPoint) o;
            return this.x.equals(that.x) && this.y.equals(that.y) && this.z.equals(that.z);
        }

        @Override
        public int hashCode() {
            int result = 1;
            result = 31 * result + this.x.hashCode();
            result = 31 * result + this.y.hashCode();
            result = 31 * result + this.z.hashCode();

            return result;
        }

        @Override
        public String toString() {
            return "((" + x.a + ", " + x.b + "), (" + y.a + ", " + y.b + "), (" + z.a + ", " + z.b + "))";
        }
    }
}

"#;

pub const JAVA_LIB_G2POINT: &str = r#"// This file is MIT Licensed
package org.oan.tetryon;

import java.math.BigInteger;

/**
 * Represents a point on the elliptic curve.
 */
public class G2Point {
    public final Fp2 x;
    public final Fp2 y;

    public G2Point(String x_a, String x_b, String y_a, String y_b) {
        this.x = new Fp2(new BigInteger(x_a, 16), new BigInteger(x_b, 16));
        this.y = new Fp2(new BigInteger(y_a, 16), new BigInteger(y_b, 16));
    }

    public G2Point(Fp2 x, Fp2 y) {
        this.x = x;
        this.y = y;
    }

    public boolean isZero() {
        return x.isZero() && y.isZero();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        G2Point that = (G2Point) o;
        return this.x.equals(that.x) && this.y.equals(that.y);
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = 31 * result + this.x.hashCode();
        result = 31 * result + this.y.hashCode();

        return result;
    }

    @Override
    public String toString() {
        return "(" + x + ", " + y + ")";
    }
}

"#;

pub const JAVA_LIB_PAIRING: &str = r#"// This file is MIT Licensed
package org.oan.tetryon;

import avm.AltBn128;

import java.math.BigInteger;


/**
 * A library of pairing operations.
 */
public class Pairing {

    /**
     * Returns the generator of G1
     */
    public static G1Point P1() {
        return new G1Point(new Fp(1), new Fp(2));
    }

    /**
     * Returns the generator of G2
     */
    public static G2Point P2() {
        return new G2Point(
                new Fp2(new BigInteger("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
                        new BigInteger("10857046999023057135944570762232829481370756359578518086990519993285655852781")),
                new Fp2(new BigInteger("4082367875863433681332203403145435568316851327593401208105741076214120093531"),
                        new BigInteger("8495653923123431417604973247489272438418190587263600148770280649306958101930"))
        );
    }

    /**
     * Bilinear pairing check.
     *
     * @param p1
     * @param p2
     * @return
     */
    public static boolean pairing(G1Point[] p1, G2Point[] p2) throws Exception {
        if (p1.length != p2.length) {
            throw new IllegalArgumentException("Points are not in pair");
        }

        byte[] g1ListData = new byte[p1.length * G1.POINT_SIZE];
        byte[] g2ListData = new byte[p1.length * G2.POINT_SIZE];

        for (int i = 0; i < p1.length; i++) {
            System.arraycopy(G1.serialize(p1[i]), 0, g1ListData, i*G1.POINT_SIZE, G1.POINT_SIZE);
            System.arraycopy(G2.serialize(p2[i]), 0, g2ListData, i*G2.POINT_SIZE, G2.POINT_SIZE);
        }

        return AltBn128.isPairingProdEqualToOne(g1ListData, g2ListData);
    }

    public static boolean pairingProd1(G1Point a1, G2Point a2) throws Exception {
        return pairing(new G1Point[]{a1}, new G2Point[]{a2});
    }

    public static boolean pairingProd2(G1Point a1, G2Point a2, G1Point b1, G2Point b2) throws Exception {
        return pairing(new G1Point[]{a1, b1}, new G2Point[]{a2, b2});
    }

    @SuppressWarnings("unused")
    public static boolean pairingProd3(G1Point a1, G2Point a2, G1Point b1, G2Point b2, G1Point c1, G2Point c2) throws Exception {
        return pairing(new G1Point[]{a1, b1, c1}, new G2Point[]{a2, b2, c2});
    }

    public static boolean pairingProd4(G1Point a1, G2Point a2, G1Point b1, G2Point b2, G1Point c1, G2Point c2, G1Point d1, G2Point d2) throws Exception {
        return pairing(new G1Point[]{a1, b1, c1, d1}, new G2Point[]{a2, b2, c2, d2});
    }
}

"#;

pub const JAVA_LIB_UTIL: &str = r#"// This file is MIT Licensed
package org.oan.tetryon;

public class Util {

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}

"#;



















