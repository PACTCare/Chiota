#region Directives
using System;
using System.IO;
using NTRU.Arith;
using NTRU.Exceptions;
using NTRU.Polynomial;
using NTRUEngine.NTRU.Digest;
using Numeric;
#endregion

namespace NTRU.Sign
{
/**
 * Signs, verifies data and generates key pairs.
 * @deprecated the NtruSign algorithm was broken in 2012 by Ducas and Nguyen. See
 *             <a href="http://www.di.ens.fr/~ducas/NTRUSign_Cryptanalysis/DucasNguyen_Learning.pdf">
 *             http://www.di.ens.fr/~ducas/NTRUSign_Cryptanalysis/DucasNguyen_Learning.pdf</a>
 *             for details.
 */
    public class NtruSign
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
        private SignatureParameters param;
        private SHA256 hashAlg;
        private SignatureKeyPair signingKeyPair;
        private SignaturePublicKey verificationKey;

        /**
         * Constructs a new instance with a set of signature parameters.
         * @param params signature parameters
         * @deprecated the NtruSign algorithm is broken
         */
        public NtruSign(SignatureParameters param)
        {
            this.param = param;
        }

        /**
         * Generates a new signature key pair. Uses up to <code>B+1</code> threads
         * if multiple processors are available.
         * @return a key pair
         */
        public SignatureKeyPair generateKeyPair()
        {
            int processors = Environment.ProcessorCount;
            SignaturePrivateKey priv = new SignaturePrivateKey(param);
            int B = param.B;

            //if (processors == 1)
            // generate all B+1 bases in the current thread
            for (int k = B; k >= 0; k--)
                priv.add(generateBoundedBasis());
            /*else {
                List<Future<Basis>> bases = new ArrayList<Future<Basis>>();
            
                // start up to processors-1 new threads and generate B bases
                int numThreads = Math.min(B, processors-1);
                if (numThreads > 0) {
                    ExecutorService executor = Executors.newFixedThreadPool(numThreads);
                    for (int k=B-1; k>=0; k--)
                        bases.add(executor.submit(new BasisGenerationTask()));
                    executor.shutdown();
                }
            
                // generate the remaining basis in the current thread
                Basis basis0 = generateBoundedBasis();
            
                // build the private key
                for (Future<Basis> basis: bases)
                    try {
                        priv.add(basis.get());
                    } catch (Exception e) {
                        throw new NtruException(e);
                    }
                priv.add(basis0);
            }*/

            int q = param.q;
            SignaturePublicKey pub = new SignaturePublicKey(priv.getBasis(0).h, q);
            priv.getBasis(0).h = null;   // remove the public polynomial h from the private key

            SignatureKeyPair kp = new SignatureKeyPair(priv, pub);
            return kp;
        }

        /**
         * Generates a new signature key pair. Runs in a single thread.
         * @return a key pair
         */
        public SignatureKeyPair generateKeyPairSingleThread()
        {
            SignaturePrivateKey priv = new SignaturePrivateKey(param);
            SignaturePublicKey pub = null;

            Basis pubBasis = generateBoundedBasis();
            pub = new SignaturePublicKey(pubBasis.h, param.q);
            pubBasis.h = null;   // remove the public polynomial h from the private key
            priv.add(pubBasis);

            for (int k = param.B; k > 0; k--)
            {
                Basis basis = generateBoundedBasis();
                priv.add(basis);
            }

            SignatureKeyPair kp = new SignatureKeyPair(priv, pub);
            return kp;
        }

        /**
         * Resets the engine for signing a message.
         * @param kp
         * @throws NtruException if the JRE doesn't implement the specified hash algorithm
         */
        public void initSign(SignatureKeyPair kp)
        {
            this.signingKeyPair = kp;
            try
            {
                hashAlg = new SHA256();// MessageDigest.getInstance(param.hashAlg);
            }
            catch (Exception e)
            {
                throw new NtruException(e.Message);
            }
            hashAlg.Reset();
        }

        /**
         * Adds data to sign or verify.
         * @param m
         * @throws NtruException if <code>initSign</code> was not called
         */
        public void update(byte[] m)
        {
            if (hashAlg == null)
                throw new NtruException("Call initSign or initVerify first!");

            hashAlg.BlockUpdate(m, 0, m.Length);
        }

        /**
         * Adds data to sign and computes a signature over this data and any data previously added via {@link #update(byte[])}.
         * @param m
         * @return a signature
         * @throws NtruException if <code>initSign</code> was not called
         */
        public byte[] sign(byte[] m)
        {
            if (hashAlg == null || signingKeyPair == null)
                throw new NtruException("Call initSign first!");

            byte[] msgHash;
            msgHash = hashAlg.ComputeHash(m);
            return signHash(msgHash, signingKeyPair);
        }

        /**
         * Signs a message.<br/>
         * This is a "one stop" method and does not require <code>initSign</code> to be called. Only the message supplied via
         * the parameter <code>m</code> is signed, regardless of prior calls to {@link #update(byte[])}.
         * @param m the message to sign
         * @param kp a key pair (the public key is needed to ensure there are no signing failures)
         * @return a signature
         * @throws NtruException if the JRE doesn't implement the specified hash algorithm
         */
        public byte[] sign(byte[] m, SignatureKeyPair kp)
        {
            try
            {
                // EESS directly passes the message into the MRGM (message representative
                // generation method). Since that is inefficient for long messages, we work
                // with the hash of the message.
                hashAlg = new SHA256();
                byte[] msgHash = hashAlg.ComputeHash(m);
                return signHash(msgHash, kp);
            }
            catch (Exception e)
            {
                throw new NtruException(e.Message);
            }
        }

        private byte[] signHash(byte[] msgHash, SignatureKeyPair kp)
        {
            int r = 0;
            IntegerPolynomial s;
            IntegerPolynomial i;
            do
            {
                r++;
                if (r > param.signFailTolerance)
                    throw new NtruException("Signing failed: too many retries (max=" + param.signFailTolerance + ")");
                i = createMsgRep(msgHash, r);
                s = sign(i, kp);
            } while (!verify(i, s, kp.pub.h));

            byte[] rawSig = s.ToBinary(param.q);

            MemoryStream sbuf = new MemoryStream(rawSig.Length + 4);
            BinaryWriter bwr = new BinaryWriter(sbuf);
            bwr.Write(rawSig);
            bwr.Write(r);
            return sbuf.ToArray();
        }

        private IntegerPolynomial sign(IntegerPolynomial i, SignatureKeyPair kp)
        {
            int N = param.N;
            int q = param.q;
            int perturbationBases = param.B;

            IntegerPolynomial s = new IntegerPolynomial(N);
            int iLoop = perturbationBases;
            while (iLoop >= 1)
            {
                IPolynomial f = kp.priv.getBasis(iLoop).f;
                IPolynomial fPrime = kp.priv.getBasis(iLoop).fPrime;

                IntegerPolynomial y = f.Multiply(i);
                y.Divide(q);
                y = fPrime.Multiply(y);

                IntegerPolynomial x = fPrime.Multiply(i);
                x.Divide(q);
                x = f.Multiply(x);

                IntegerPolynomial si = y;
                si.Subtract(x);
                s.Add(si);

                IntegerPolynomial hi = kp.priv.getBasis(iLoop).h.Clone();
                if (iLoop > 1)
                    hi.Subtract(kp.priv.getBasis(iLoop - 1).h);
                else
                    hi.Subtract(kp.pub.h);
                i = si.Multiply(hi, q);

                iLoop--;
            }

            IPolynomial f2 = kp.priv.getBasis(0).f;
            IPolynomial fPrime2 = kp.priv.getBasis(0).fPrime;

            IntegerPolynomial y2 = f2.Multiply(i);
            y2.Divide(q);
            y2 = fPrime2.Multiply(y2);

            IntegerPolynomial x2 = fPrime2.Multiply(i);
            x2.Divide(q);
            x2 = f2.Multiply(x2);

            y2.Subtract(x2);
            s.Add(y2);
            s.ModPositive(q);
            return s;
        }

        /**
         * Resets the engine for verifying a signature.
         * @param pub the public key to use in the {@link #verify(byte[])} step
         * @throws NtruException if the JRE doesn't implement the specified hash algorithm
         */
        public void initVerify(SignaturePublicKey pub)
        {
            verificationKey = pub;
            try
            {
                hashAlg = new SHA256();
            }
            catch (Exception e)
            {
                throw new NtruException(e.Message);
            }
            hashAlg.Reset();
        }

        /**
         * Verifies a signature for any data previously added via {@link #update(byte[])}.
         * @param sig a signature
         * @return whether the signature is valid
         * @throws NtruException if <code>initVerify</code> was not called
         */
        public bool verify(byte[] sig)
        {
            if (hashAlg == null || verificationKey == null)
                throw new NtruException("Call initVerify first!");

            byte[] msgHash = new byte[hashAlg.DigestSize]; 
            hashAlg.DoFinal(msgHash, 0);
            return verifyHash(msgHash, sig, verificationKey);
        }

        /**
         * Verifies a signature.<br/>
         * This is a "one stop" method and does not require <code>initVerify</code> to be called. Only the message supplied via
         * the parameter <code>m</code> is signed, regardless of prior calls to {@link #update(byte[])}.
         * @param m the message to sign
         * @param sig the signature
         * @param pub a public key
         * @return whether the signature is valid
         * @throws NtruException if the JRE doesn't implement the specified hash algorithm
         */
        public bool verify(byte[] m, byte[] sig, SignaturePublicKey pub)
        {
            try
            {
                byte[] msgHash = hashAlg.ComputeHash(m);
                return verifyHash(msgHash, sig, pub);
            }
            catch (Exception e)
            {
                throw new NtruException(e.Message);
            }
        }

        private bool verifyHash(byte[] msgHash, byte[] sig, SignaturePublicKey pub)
        {
            MemoryStream sbuf = new MemoryStream(sig);
            BinaryReader brr = new BinaryReader(sbuf);
            byte[] rawSig = new byte[sig.Length - 4];
            rawSig = brr.ReadBytes(rawSig.Length);
            IntegerPolynomial s = IntegerPolynomial.FromBinary(rawSig, param.N, param.q);
            int r = brr.ReadInt32();
            return verify(createMsgRep(msgHash, r), s, pub.h);
        }

        private bool verify(IntegerPolynomial i, IntegerPolynomial s, IntegerPolynomial h)
        {
            int q = param.q;
            double normBoundSq = param.normBoundSq;
            double betaSq = param.betaSq;

            IntegerPolynomial t = h.Multiply(s, q);
            t.Subtract(i);
            long centeredNormSq = (long)(s.CenteredNormSq(q) + betaSq * t.CenteredNormSq(q));
            return centeredNormSq <= normBoundSq;
        }

        public IntegerPolynomial createMsgRep(byte[] msgHash, int r)
        {
            int N = param.N;
            int q = param.q;

            int c = 31 - IntUtils.numberOfLeadingZeros(q);
            int B = (c + 7) / 8;
            IntegerPolynomial i = new IntegerPolynomial(N);

            MemoryStream cbuf = new MemoryStream(msgHash.Length + 4);
            BinaryWriter bwr = new BinaryWriter(cbuf);
            bwr.Write(msgHash);
            bwr.Write(r);
            Prng prng = new Prng(cbuf.ToArray(), param.hashAlg);

            for (int t = 0; t < N; t++)
            {
                byte[] o = prng.nextBytes(B);
                int hi = o[o.Length - 1];
                hi >>= 8 * B - c;
                hi <<= 8 * B - c;
                o[o.Length - 1] = (byte)hi;

                MemoryStream obuf = new MemoryStream(4);
                BinaryWriter bwr2 = new BinaryWriter(obuf);

                bwr2.Write(o);
                obuf.Position = 0;
                // reverse byte order so it matches the endianness of java ints
                i.Coeffs[t] = ArrayUtils.ReverseBytes(obuf.ToArray());
            }
            return i;
        }

        /**
         * Creates a basis such that <code>|F| &lt; keyNormBound</code> and <code>|G| &lt; keyNormBound</code>
         * @return a NtruSign basis
         */
        public Basis generateBoundedBasis()
        {
            while (true)
            {
                FGBasis basis = generateBasis();
                if (basis.isNormOk())
                    return basis;
            }
        }

        /**
         * Creates a NtruSign basis consisting of polynomials <code>f, g, F, G, h</code>.<br/>
         * If <code>KeyGenAlg=FLOAT</code>, the basis may not be valid and this method must be rerun if that is the case.<br/>
         * @see #generateBoundedBasis()
         */
        private FGBasis generateBasis() {
        int N = param.N;
        int q = param.q;
        int d = param.d;
        int d1 = param.d1;
        int d2 = param.d2;
        int d3 = param.d3;
        BasisType basisType = param.basisType;
        
        IPolynomial f;
        IntegerPolynomial fInt;
        IPolynomial g;
        IntegerPolynomial gInt;
        IntegerPolynomial fq;
        Resultant rf;
        Resultant rg;
        BigIntEuclidean r;
        
        int _2n1 = 2*N+1;
        bool primeCheck = param.primeCheck;
        
        Random rng = new Random();
        do {
            do {
                if (param.polyType==TernaryPolynomialType.SIMPLE)
                        f = DenseTernaryPolynomial.GenerateRandom(N, d+1, d);
                else
                        f = ProductFormPolynomial.GenerateRandom(N, d1, d2, d3+1, d3);
                fInt = f.ToIntegerPolynomial();
            } while (primeCheck && fInt.Resultant(_2n1).Res.Equals(BigInteger.Zero));
            fq = fInt.InvertFq(q);
        } while (fq == null);
        rf = fInt.Resultant(); 
        
        do {
            do {
                do {
                    if (param.polyType == TernaryPolynomialType.SIMPLE)
                        g = DenseTernaryPolynomial.GenerateRandom(N, d + 1, d);
                    else
                        g = ProductFormPolynomial.GenerateRandom(N, d1, d2, d3 + 1, d3);
                    gInt = g.ToIntegerPolynomial();
                } while (primeCheck && gInt.Resultant(_2n1).Res.Equals(BigInteger.Zero));
            } while (!gInt.IsInvertiblePow2());
            rg = gInt.Resultant();
            r = BigIntEuclidean.Calculate(rf.Res, rg.Res);
        } while (!r.GCD.Equals(BigInteger.One));
        
        BigIntPolynomial A = rf.Rho.Clone();
        A.Multiply(r.X.Multiply(BigInteger.ValueOf(q)));
        BigIntPolynomial B = rg.Rho.Clone();
        B.Multiply(r.Y.Multiply(BigInteger.ValueOf(-q)));
        
        BigIntPolynomial C;
        if (param.keyGenAlg == KeyGenAlg.RESULTANT) {
            int[] fRevCoeffs = new int[N];
            int[] gRevCoeffs = new int[N];
            fRevCoeffs[0] = fInt.Coeffs[0];
            gRevCoeffs[0] = gInt.Coeffs[0];
            for (int i=1; i<N; i++) {
                fRevCoeffs[i] = fInt.Coeffs[N-i];
                gRevCoeffs[i] = gInt.Coeffs[N-i];
            }
            IntegerPolynomial fRev = new IntegerPolynomial(fRevCoeffs);
            IntegerPolynomial gRev = new IntegerPolynomial(gRevCoeffs);
            
            IntegerPolynomial t = f.Multiply(fRev);
            t.Add(g.Multiply(gRev));
            Resultant rt = t.Resultant();
            C = fRev.Multiply(B);   // fRev.mult(B) is actually faster than new SparseTernaryPolynomial(fRev).mult(B), possibly due to cache locality?
            C.Add(gRev.Multiply(A));
            C = C.MultBig(rt.Rho);
            C.Divide(rt.Res);
        }
        else {   // KeyGenAlg.FLOAT
            // calculate ceil(log10(N))
            int log10N = 0;
            for (int i=1; i<N; i*=10)
                log10N++;
            
            // * Cdec needs to be accurate to 1 decimal place so it can be correctly rounded;
            // * fInv loses up to (#digits of longest coeff of B) places in fInv.mult(B);
            // * multiplying fInv by B also multiplies the rounding error by a factor of N;
            // so make #decimal places of fInv the sum of the above.
            BigDecimalPolynomial fInv = rf.Rho.Divide(new BigDecimal(rf.Res), B.GetMaxCoeffLength()+1+log10N);
            BigDecimalPolynomial gInv = rg.Rho.Divide(new BigDecimal(rg.Res), A.GetMaxCoeffLength()+1+log10N);
            
            BigDecimalPolynomial Cdec = fInv.Multiply(B);
            Cdec.Add(gInv.Multiply(A));
            Cdec.Halve();
            C = Cdec.Round();
        }
        
        BigIntPolynomial F = B.Clone();
        F.Subtract(f.Multiply(C));
        BigIntPolynomial G = A.Clone();
        G.Subtract(g.Multiply(C));

        IntegerPolynomial FInt = new IntegerPolynomial(F);
        IntegerPolynomial GInt = new IntegerPolynomial(G);
        minimizeFG(fInt, gInt, FInt, GInt, N);
        
        IPolynomial fPrime;
        IntegerPolynomial h;
        if (basisType == BasisType.STANDARD) {
            fPrime = FInt;
            h = g.Multiply(fq, q);
        }
        else {
            fPrime = g;
            h = FInt.Multiply(fq, q);
        }
        h.ModPositive(q);
        
        return new FGBasis(f, fPrime, h, FInt, GInt, param.q, param.polyType, param.basisType, param.keyNormBoundSq);
    }

        /**
         * Implementation of the optional steps 20 through 26 in EESS1v2.pdf, section 3.5.1.1.
         * This doesn't seem to have much of an effect and sometimes actually increases the
         * norm of F, but on average it slightly reduces the norm.<br/>
         * This method changes <code>F</code> and <code>G</code> but leaves <code>f</code> and
         * <code>g</code> unchanged.
         * @param f
         * @param g
         * @param F
         * @param G
         * @param N
         */
        private void minimizeFG(IntegerPolynomial f, IntegerPolynomial g, IntegerPolynomial F, IntegerPolynomial G, int N)
        {
            int E = 0;
            for (int j = 0; j < N; j++)
                E += 2 * N * (f.Coeffs[j] * f.Coeffs[j] + g.Coeffs[j] * g.Coeffs[j]);

            // [f(1)+g(1)]^2 = 4
            E -= 4;

            IntegerPolynomial u = f.Clone();
            IntegerPolynomial v = g.Clone();
            int j2 = 0;
            int k = 0;
            int maxAdjustment = N;
            while (k < maxAdjustment && j2 < N)
            {
                int D = 0;
                int i = 0;
                while (i < N)
                {
                    int D1 = F.Coeffs[i] * f.Coeffs[i];
                    int D2 = G.Coeffs[i] * g.Coeffs[i];
                    int D3 = 4 * N * (D1 + D2);
                    D += D3;
                    i++;
                }
                // f(1)+g(1) = 2
                int D4 = 4 * (F.SumCoeffs() + G.SumCoeffs());
                D -= D4;

                if (D > E)
                {
                    F.Subtract(u);
                    G.Subtract(v);
                    k++;
                    j2 = 0;
                }
                else if (D < -E)
                {
                    F.Add(u);
                    G.Add(v);
                    k++;
                    j2 = 0;
                }
                j2++;
                u.Rotate1();
                v.Rotate1();
            }
        }

        /*private class BasisGenerationTask implements Callable<Basis> {

            //@Override
            public Basis call() throws Exception {
                return generateBoundedBasis();
            }
        }*/


    }
    /**
     * A subclass of Basis that additionally contains the polynomials <code>F</code> and <code>G</code>.
     */
    public class FGBasis : Basis
    {
        public IntegerPolynomial F, G;
        public int q;
        public double keyNormBoundSq;

        public FGBasis(IPolynomial f, IPolynomial fPrime, IntegerPolynomial h, IntegerPolynomial F, IntegerPolynomial G, int q, TernaryPolynomialType polyType, BasisType basisType, double keyNormBoundSq) :
            base(f, fPrime, h, q, polyType, basisType, keyNormBoundSq)
        {
            ;
            this.F = F;
            this.G = G;
            this.q = q;
            this.keyNormBoundSq = keyNormBoundSq;
        }

        /**
         * Returns <code>true</code> if the norms of the polynomials <code>F</code> and <code>G</code>
         * are within {@link SignatureParameters#keyNormBound}.
         * @return
         */
        public bool isNormOk()
        {
            return (F.CenteredNormSq(q) < keyNormBoundSq && G.CenteredNormSq(q) < keyNormBoundSq);
        }
    }
}