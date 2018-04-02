#region Directives
using System;
using System.IO;
using NTRU.Polynomial;
using Numeric;
#endregion

namespace NTRU.Sign
{
    public class Basis
    {
        #region Fields
        public IPolynomial f;
        public IPolynomial fPrime;
        public IntegerPolynomial h;
        public int N;
        public int q;
        private TernaryPolynomialType polyType;
        private BasisType basisType;
        private double keyNormBoundSq;
        #endregion

        #region Constructor

        /**
         * Constructs a new basis from polynomials <code>f, f', h</code>.
         * @param f
         * @param fPrime
         * @param h
         * @param params NtruSign parameters
         */
        public Basis(IPolynomial f, IPolynomial fPrime, IntegerPolynomial h, int q, TernaryPolynomialType polyType, BasisType basisType, double keyNormBoundSq)
        {
            this.f = f;
            this.fPrime = fPrime;
            this.h = h;
            this.N = h.Coeffs.Length;
            this.q = q;
            this.polyType = polyType;
            this.basisType = basisType;
            this.keyNormBoundSq = keyNormBoundSq;
        }

        /**
         * Reads a basis from an input stream and constructs a new basis.
         * @param is an input stream
         * @param params NtruSign parameters
         * @param include_h whether to read the polynomial <code>h</code> (<code>true</code>) or only <code>f</code> and <code>f'</code> (<code>false</code>)
         * @throws IOException
         */
        public Basis(MemoryStream ins, int N, int q, bool sparse, TernaryPolynomialType polyType, BasisType basisType, double keyNormBoundSq, bool include_h)
        {
            this.N = N;
            this.q = q;
            this.polyType = polyType;
            this.basisType = basisType;
            this.keyNormBoundSq = keyNormBoundSq;

            if (polyType == TernaryPolynomialType.PRODUCT)
                f = ProductFormPolynomial.FromBinary(ins, N);
            else
            {
                IntegerPolynomial fInt = IntegerPolynomial.FromBinary3Tight(ins, N);
                if (sparse)
                    f = new SparseTernaryPolynomial(fInt);
                else
                    f = new DenseTernaryPolynomial(fInt);
            }

            if (basisType == BasisType.STANDARD)
            {
                IntegerPolynomial fPrimeInt = IntegerPolynomial.FromBinary(ins, N, q);
                for (int i = 0; i < fPrimeInt.Coeffs.Length; i++)
                    fPrimeInt.Coeffs[i] -= q / 2;
                fPrime = fPrimeInt;
            }
            else
                if (polyType == TernaryPolynomialType.PRODUCT)
                    fPrime = ProductFormPolynomial.FromBinary(ins, N);
                else
                    fPrime = IntegerPolynomial.FromBinary3Tight(ins, N);

            if (include_h)
                h = IntegerPolynomial.FromBinary(ins, N, q);
        }
        #endregion

        #region Public Methods
        
        /**
         * Writes the basis to an output stream
         * @param os an output stream
         * @param include_h whether to write the polynomial <code>h</code> (<code>true</code>) or only <code>f</code> and <code>f'</code> (<code>false</code>)
         * @throws IOException
         */
        public void encode(MemoryStream os, bool include_h)
        {
            BinaryWriter bwr = new BinaryWriter(os);
            bwr.Write(getEncoded(f));
            if (basisType == BasisType.STANDARD)
            {
                IntegerPolynomial fPrimeInt = fPrime.ToIntegerPolynomial();
                for (int i = 0; i < fPrimeInt.Coeffs.Length; i++)
                    fPrimeInt.Coeffs[i] += q / 2;
                bwr.Write(fPrimeInt.ToBinary(q));
            }
            else
                bwr.Write(getEncoded(fPrime));
            if (include_h)
                bwr.Write(h.ToBinary(q));
        }


        /**
         * Tests if the basis is valid.
         * @param h the polynomial h (either from the public key or from this basis)
         * @return <code>true</code> if the basis is valid, <code>false</code> otherwise
         */
        public bool isValid(IntegerPolynomial h)
        {
            if (f.ToIntegerPolynomial().Coeffs.Length != N)
                return false;
            if (fPrime.ToIntegerPolynomial().Coeffs.Length != N)
                return false;

            if (h.Coeffs.Length != N || !h.IsReduced(q))
                return false;

            // determine F, G, g from f, fPrime, h using the eqn. fG-Fg=q
            IPolynomial FPoly = basisType == BasisType.STANDARD ? fPrime : f.Multiply(h, q);
            IntegerPolynomial F = FPoly.ToIntegerPolynomial();
            IntegerPolynomial fq = f.ToIntegerPolynomial().InvertFq(q);
            IPolynomial g;
            if (basisType == BasisType.STANDARD)
                g = f.Multiply(h, q);
            else
                g = fPrime;
            IntegerPolynomial G = g.Multiply(F);
            G.Coeffs[0] -= q;
            G = G.Multiply(fq, q);
            G.ModCenter(q);

            // check norms of F and G
            if (!new FGBasis(f, fPrime, h, F, G, q, polyType, basisType, keyNormBoundSq).isNormOk())
                return false;
            // check norms of f and g
            int factor = N / 24;
            if (f.ToIntegerPolynomial().CenteredNormSq(q) * factor >= F.CenteredNormSq(q))
                return false;
            if (g.ToIntegerPolynomial().CenteredNormSq(q) * factor >= G.CenteredNormSq(q))
                return false;

            // check ternarity
            if (polyType == TernaryPolynomialType.SIMPLE)
            {
                if (!f.ToIntegerPolynomial().IsTernary())
                    return false;
                if (!g.ToIntegerPolynomial().IsTernary())
                    return false;
            }
            else
            {
                if (!(f.GetType().IsAssignableFrom(typeof(ProductFormPolynomial))))
                    return false;
                if (!(g.GetType().IsAssignableFrom(typeof(ProductFormPolynomial))))
                    return false;
            }

            return true;
        }
        #endregion

        #region Private Methods
                private byte[] getEncoded(IPolynomial p)
        {
            if (p.GetType().IsAssignableFrom(typeof(ProductFormPolynomial)))
                return ((ProductFormPolynomial)p).toBinary();
            else
                return p.ToIntegerPolynomial().ToBinary3Tight();
        }
        #endregion

        #region Overrides
        public override bool Equals(object obj)
        {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (!(obj.GetType().IsAssignableFrom(typeof(Basis))))
                return false;
            Basis other = (Basis)obj;
            if (N != other.N)
                return false;
            if (basisType != other.basisType)
                return false;
            if (f == null)
            {
                if (other.f != null)
                    return false;
            }
            else if (!f.Equals(other.f))
                return false;
            if (fPrime == null)
            {
                if (other.fPrime != null)
                    return false;
            }
            else if (!fPrime.Equals(other.fPrime))
                return false;
            if (h == null)
            {
                if (other.h != null)
                    return false;
            }
            else if (!h.Equals(other.h))
                return false;
            if (BitConverter.DoubleToInt64Bits(keyNormBoundSq) != BitConverter.DoubleToInt64Bits(other.keyNormBoundSq))
                return false;
            if (polyType != other.polyType)
                return false;
            if (q != other.q)
                return false;
            return true;
        }

        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            result = prime * result + N;
            result = prime * result
                    + ((basisType == null) ? 0 : basisType.GetHashCode());
            result = prime * result + ((f == null) ? 0 : f.GetHashCode());
            result = prime * result
                    + ((fPrime == null) ? 0 : fPrime.GetHashCode());
            result = prime * result + ((h == null) ? 0 : h.GetHashCode());
            long temp;
            temp = BitConverter.DoubleToInt64Bits(keyNormBoundSq);
            result = prime * result + (int)(temp ^ (IntUtils.URShift(temp, 32)));
            result = prime * result
                    + ((polyType == null) ? 0 : polyType.GetHashCode());
            result = prime * result + q;
            return result;
        }
        #endregion
    }
}