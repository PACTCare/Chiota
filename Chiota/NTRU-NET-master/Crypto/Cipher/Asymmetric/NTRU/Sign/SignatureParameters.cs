#region Directives
using System;
using System.IO;
using System.Text;
using Numeric;
#endregion

namespace NTRU.Sign
{
/**
 * A set of parameters for NtruSign. Several predefined parameter sets are available and new ones can be created as well.
 */
    public enum BasisType { STANDARD, TRANSPOSE };
    public enum KeyGenAlg { RESULTANT, FLOAT };
    public enum TernaryPolynomialType { SIMPLE, PRODUCT };

    public class SignatureParameters : ICloneable
    {
        #region Constants
        #endregion
        #region Fields
        #endregion
        #region Constructor
        #endregion
        #region Public Methods
        #endregion
        #region Private Methods
        #endregion
        /** Gives 128 bits of security */
        public static SignatureParameters APR2011_439 = new SignatureParameters(439, 2048, 146, 1, BasisType.TRANSPOSE, 0.165f, 400, 280, false, true, KeyGenAlg.RESULTANT, "SHA-256");

        /** Like <code>APR2011_439</code>, this parameter set gives 128 bits of security but uses product-form polynomials */
        public static SignatureParameters APR2011_439_PROD = new SignatureParameters(439, 2048, 9, 8, 5, 1, BasisType.TRANSPOSE, 0.165f, 400, 280, false, true, KeyGenAlg.RESULTANT, "SHA-256");

        /** Gives 256 bits of security */
        public static SignatureParameters APR2011_743 = new SignatureParameters(743, 2048, 248, 1, BasisType.TRANSPOSE, 0.127f, 405, 360, true, false, KeyGenAlg.RESULTANT, "SHA-512");

        /** Like <code>APR2011_439</code>, this parameter set gives 256 bits of security but uses product-form polynomials */
        public static SignatureParameters APR2011_743_PROD = new SignatureParameters(743, 2048, 11, 11, 15, 1, BasisType.TRANSPOSE, 0.127f, 405, 360, true, false, KeyGenAlg.RESULTANT, "SHA-512");

        /** Generates key pairs quickly. Use for testing only. */
        public static SignatureParameters TEST157 = new SignatureParameters(157, 256, 29, 1, BasisType.TRANSPOSE, 0.38f, 200, 80, false, false, KeyGenAlg.RESULTANT, "SHA-256");
        /** Generates key pairs quickly. Use for testing only. */
        public static SignatureParameters TEST157_PROD = new SignatureParameters(157, 256, 5, 5, 8, 1, BasisType.TRANSPOSE, 0.38f, 200, 80, false, false, KeyGenAlg.RESULTANT, "SHA-256");



        public int N;
        public int q;
        public int d, d1, d2, d3, B;
        public float beta, betaSq, normBound, normBoundSq;
        public int signFailTolerance = 100;
        public float keyNormBound, keyNormBoundSq;
        public bool primeCheck;   // true if N and 2N+1 are prime
        public BasisType basisType;
        public int bitsF = 6;   // max #bits needed to encode one coefficient of the polynomial F
        public bool sparse;   // whether to treat ternary polynomials as sparsely populated
        public KeyGenAlg keyGenAlg;
        public String hashAlg;
        public TernaryPolynomialType polyType;

        /**
         * Constructs a parameter set that uses ternary private keys (i.e. </code>polyType=SIMPLE</code>).
         * @param N            number of polynomial coefficients
         * @param q            modulus
         * @param d            number of -1's in the private polynomials <code>f</code> and <code>g</code>
         * @param B            number of perturbations
         * @param basisType    whether to use the standard or transpose lattice
         * @param beta         balancing factor for the transpose lattice
         * @param normBound    maximum norm for valid signatures
         * @param keyNormBound maximum norm for the polynomials <code>F</code> and <code>G</code>
         * @param primeCheck   whether <code>2N+1</code> is prime
         * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link SparseTernaryPolynomial} vs {@link DenseTernaryPolynomial})
         * @param keyGenAlg    <code>RESULTANT</code> produces better bases, <code>FLOAT</code> is slightly faster. <code>RESULTANT</code> follows the EESS standard while <code>FLOAT</code> is described in Hoffstein et al: An Introduction to Mathematical Cryptography.
         * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
         */
        public SignatureParameters(int N, int q, int d, int B, BasisType basisType, float beta, float normBound, float keyNormBound, bool primeCheck, bool sparse, KeyGenAlg keyGenAlg, String hashAlg)
        {
            this.N = N;
            this.q = q;
            this.d = d;
            this.B = B;
            this.basisType = basisType;
            this.beta = beta;
            this.normBound = normBound;
            this.keyNormBound = keyNormBound;
            this.primeCheck = primeCheck;
            this.sparse = sparse;
            this.keyGenAlg = keyGenAlg;
            this.hashAlg = hashAlg;
            polyType = TernaryPolynomialType.SIMPLE;
            init();
        }

        /**
         * Constructs a parameter set that uses product-form private keys (i.e. </code>polyType=PRODUCT</code>).
         * @param N            number of polynomial coefficients
         * @param q            modulus
         * @param d1           number of -1's in the private polynomials <code>f</code> and <code>g</code>
         * @param d2           number of -1's in the private polynomials <code>f</code> and <code>g</code>
         * @param d3           number of -1's in the private polynomials <code>f</code> and <code>g</code>
         * @param B            number of perturbations
         * @param basisType    whether to use the standard or transpose lattice
         * @param beta         balancing factor for the transpose lattice
         * @param normBound    maximum norm for valid signatures
         * @param keyNormBound maximum norm for the polynomials <code>F</code> and <code>G</code>
         * @param primeCheck   whether <code>2N+1</code> is prime
         * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link SparseTernaryPolynomial} vs {@link DenseTernaryPolynomial})
         * @param keyGenAlg    <code>RESULTANT</code> produces better bases, <code>FLOAT</code> is slightly faster. <code>RESULTANT</code> follows the EESS standard while <code>FLOAT</code> is described in Hoffstein et al: An Introduction to Mathematical Cryptography.
         * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
         */
        public SignatureParameters(int N, int q, int d1, int d2, int d3, int B, BasisType basisType, float beta, float normBound, float keyNormBound, bool primeCheck, bool sparse, KeyGenAlg keyGenAlg, String hashAlg)
        {
            this.N = N;
            this.q = q;
            this.d1 = d1;
            this.d2 = d2;
            this.d3 = d3;
            this.B = B;
            this.basisType = basisType;
            this.beta = beta;
            this.normBound = normBound;
            this.keyNormBound = keyNormBound;
            this.primeCheck = primeCheck;
            this.sparse = sparse;
            this.keyGenAlg = keyGenAlg;
            this.hashAlg = hashAlg;
            polyType = TernaryPolynomialType.PRODUCT;
            init();
        }

        private void init()
        {
            betaSq = beta * beta;
            normBoundSq = normBound * normBound;
            keyNormBoundSq = keyNormBound * keyNormBound;
        }

        /**
         * Reads a parameter set from an input stream.
         * @param is an input stream
         * @throws IOException
         */
        public SignatureParameters(MemoryStream ins)
        {
            BinaryReader dis = new BinaryReader(ins);
            N = dis.ReadInt32();
            q = dis.ReadInt32();
            d = dis.ReadInt32();
            d1 = dis.ReadInt32();
            d2 = dis.ReadInt32();
            d3 = dis.ReadInt32();
            B = dis.ReadInt32();
            basisType = (BasisType)dis.ReadInt32();
            beta = dis.ReadSingle();
            normBound = dis.ReadSingle();
            keyNormBound = dis.ReadSingle();
            signFailTolerance = dis.ReadInt32();
            primeCheck = dis.ReadBoolean();
            sparse = dis.ReadBoolean();
            bitsF = dis.ReadInt32();
            keyGenAlg = (KeyGenAlg)dis.ReadInt32();
            hashAlg = dis.ReadString();
            polyType = (TernaryPolynomialType)dis.ReadInt32();
            init();
        }

        /**
         * Returns the length of a signature made with this parameter set.<br/>
         * The length does not depend on the message size.
         * @return the length in bytes
         */
        public int getOutputLength()
        {
            int logq = 32 - IntUtils.numberOfLeadingZeros(q - 1);   // ceil(log q)
            int polyLen = (N * logq + 7) / 8;   // length of a polynomial in bytes
            return polyLen + 4;   // add 4 for the retry count
        }

        /**
         * Writes the parameter set to an output stream
         * @param os an output stream
         * @throws IOException
         */
        public void writeTo(MemoryStream os)
        {
            BinaryWriter dos = new BinaryWriter(os);
            dos.Write(N);
            dos.Write(q);
            dos.Write(d);
            dos.Write(d1);
            dos.Write(d2);
            dos.Write(d3);
            dos.Write(B);
            dos.Write((int)basisType);
            dos.Write(beta);
            dos.Write(normBound);
            dos.Write(keyNormBound);
            dos.Write(signFailTolerance);
            dos.Write(primeCheck);
            dos.Write(sparse);
            dos.Write(bitsF);
            dos.Write((int)keyGenAlg);
            dos.Write(hashAlg);
            dos.Write((int)polyType);
        }

        //@Override
        public SignatureParameters Clone()
        {
            if (polyType == TernaryPolynomialType.SIMPLE)
                return new SignatureParameters(N, q, d, B, basisType, beta, normBound, keyNormBound, primeCheck, sparse, keyGenAlg, hashAlg);
            else
                return new SignatureParameters(N, q, d1, d2, d3, B, basisType, beta, normBound, keyNormBound, primeCheck, sparse, keyGenAlg, hashAlg);
        }

        //@Override
        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            result = prime * result + B;
            result = prime * result + N;
            result = prime * result + ((basisType == null) ? 0 : basisType.GetHashCode());
            long temp;
            temp = IntUtils.floatToIntBits(beta);
            result = prime * result + (int)(temp ^ (IntUtils.URShift(temp, 32)));
            temp = IntUtils.floatToIntBits(betaSq);
            result = prime * result + (int)(temp ^ (IntUtils.URShift(temp, 32)));
            result = prime * result + bitsF;
            result = prime * result + d;
            result = prime * result + d1;
            result = prime * result + d2;
            result = prime * result + d3;
            result = prime * result + ((hashAlg == null) ? 0 : hashAlg.GetHashCode());
            result = prime * result + ((keyGenAlg == null) ? 0 : keyGenAlg.GetHashCode());
            temp = IntUtils.floatToIntBits(keyNormBound);
            result = prime * result + (int)(temp ^ (IntUtils.URShift(temp, 32)));
            temp = IntUtils.floatToIntBits(keyNormBoundSq);
            result = prime * result + (int)(temp ^ (IntUtils.URShift(temp, 32)));
            temp = IntUtils.floatToIntBits(normBound);
            result = prime * result + (int)(temp ^ (IntUtils.URShift(temp, 32)));
            temp = IntUtils.floatToIntBits(normBoundSq);
            result = prime * result + (int)(temp ^ (IntUtils.URShift(temp, 32)));
            result = prime * result + ((polyType == null) ? 0 : polyType.GetHashCode());
            result = prime * result + (primeCheck ? 1231 : 1237);
            result = prime * result + q;
            result = prime * result + signFailTolerance;
            result = prime * result + (sparse ? 1231 : 1237);
            return result;
        }

        //@Override
        public override bool Equals(Object obj)
        {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (!(obj.GetType().IsAssignableFrom(typeof(SignatureParameters))))
                return false;
            SignatureParameters other = (SignatureParameters)obj;
            if (B != other.B)
                return false;
            if (N != other.N)
                return false;
            if (basisType == null)
            {
                if (other.basisType != null)
                    return false;
            }
            else if (!basisType.Equals(other.basisType))
                return false;
            if (IntUtils.floatToIntBits(beta) != IntUtils.floatToIntBits(other.beta))
                return false;
            if (IntUtils.floatToIntBits(betaSq) != IntUtils.floatToIntBits(other.betaSq))
                return false;
            if (bitsF != other.bitsF)
                return false;
            if (d != other.d)
                return false;
            if (d1 != other.d1)
                return false;
            if (d2 != other.d2)
                return false;
            if (d3 != other.d3)
                return false;
            if (hashAlg == null)
            {
                if (other.hashAlg != null)
                    return false;
            }
            else if (!hashAlg.Equals(other.hashAlg))
                return false;
            if (keyGenAlg == null)
            {
                if (other.keyGenAlg != null)
                    return false;
            }
            else if (!keyGenAlg.Equals(other.keyGenAlg))
                return false;
            if (IntUtils.floatToIntBits(keyNormBound) != IntUtils.floatToIntBits(other.keyNormBound))
                return false;
            if (IntUtils.floatToIntBits(keyNormBoundSq) != IntUtils.floatToIntBits(other.keyNormBoundSq))
                return false;
            if (IntUtils.floatToIntBits(normBound) != IntUtils.floatToIntBits(other.normBound))
                return false;
            if (IntUtils.floatToIntBits(normBoundSq) != IntUtils.floatToIntBits(other.normBoundSq))
                return false;
            if (polyType == null)
            {
                if (other.polyType != null)
                    return false;
            }
            else if (!polyType.Equals(other.polyType))
                return false;
            if (primeCheck != other.primeCheck)
                return false;
            if (q != other.q)
                return false;
            if (signFailTolerance != other.signFailTolerance)
                return false;
            if (sparse != other.sparse)
                return false;
            return true;
        }

        //@Override
        public override String ToString()
        {
            //DecimalFormat format = new DecimalFormat("0.00");

            StringBuilder output = new StringBuilder("SignatureParameters(N=" + N + " q=" + q);
            if (polyType == TernaryPolynomialType.SIMPLE)
                output.Append(" polyType=SIMPLE d=" + d);
            else
                output.Append(" polyType=PRODUCT d1=" + d1 + " d2=" + d2 + " d3=" + d3);
            output.Append(" B=" + B + " basisType=" + basisType + " beta=" + beta +
                    " normBound=" + normBound + " keyNormBound=" + keyNormBound +
                    " prime=" + primeCheck + " sparse=" + sparse + " keyGenAlg=" + keyGenAlg + " hashAlg=" + hashAlg + ")");
            return output.ToString();
        }

        object ICloneable.Clone()
        {
            return this.Clone();
        }
    }
}