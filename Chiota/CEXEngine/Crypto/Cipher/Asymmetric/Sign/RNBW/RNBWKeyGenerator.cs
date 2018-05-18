#region Directives
using System;
using System.Threading.Tasks;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.Arithmetic;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Principal Algorithms:
// An implementation of the Rainbow Asymmetric Signature Scheme.
// 
// Code Base Guides:
// Portions of this code based on the Bouncy Castle Based on the Bouncy Castle Java 
// <a href="http://bouncycastle.org/latest_releases.html">Release 1.51</a> version.
// 
// Implementation Details:
// An implementation of an Rainbow Asymmetric Signature Scheme. 
// Written by John Underhill, July 06, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW
{
    /// <summary>
    /// An Rainbow Signature Scheme Key-Pair Generator
    /// </summary>
    ///
    /// <example>
    /// <description>Example of creating a keypair:</description>
    /// <code>
    /// RNBWKeyGenerator encParams = RNBWParamSets.RNBWN49L5;
    /// RNBWKeyGenerator keyGen = new RNBWKeyGenerator(encParams);
    /// IAsymmetricKeyPair keyPair = keyGen.GenerateKeyPair();
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.RNBWSign"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.RNBWPublicKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.RNBWPrivateKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKeyPair"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces.IAsymmetricKey"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Prngs"/>
    /// 
    /// <remarks>
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>Selecting Parameters for the <a href="http://eprint.iacr.org/2010/437.pdf">Rainbow Signature Scheme</a></description></item>
    /// </list>
    /// </remarks>
    public sealed class RNBWKeyGenerator : IAsymmetricGenerator
    {
        #region Constants
        private const string ALG_NAME = "RNBWKeyGenerator";
        #endregion

        #region Fields
        // linear affine map L1:
        // matrix of the lin. affine map L1(n-v1 x n-v1 matrix)
        private short[][] _A1; 
        // inverted A1
        private short[][] _A1Inv;
        // translation element of the lin.affine map L1
        private short[] _B1;
        // linear affine map L2:
        // matrix of the lin. affine map (n x n matrix)
        private short[][] _A2;
        // inverted A2
        private short[][] _A2Inv;
        // translation elem of the lin.affine map L2
        private short[] _B2;
        // components of F:
        // u (number of sets S)
        private int _numLayers;
        // layers of polynomials of F
        private MapLayer[] _layers;
        // set of vinegar vars per layer.
        private int[] _VI;
        // components of Public Key
        // quadratic(mixed) coefficients
        private short[][] _pubQuadratic;
        // singular coefficients
        private short[][] _pubSingular;
        // scalars
        private short[] _pubScalar;
        private bool m_isDisposed;
        private RNBWParameters m_rlweParams;
        private IRandom m_rngEngine;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Generator name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="CipherParams">The RNBWParameters instance containing the cipher settings</param>
        /// 
        /// <exception cref="CryptoAsymmetricSignException">Thrown if a Prng that requires pre-initialization is specified; (wrong constructor)</exception>
        public RNBWKeyGenerator(RNBWParameters CipherParams)
        {
            if (CipherParams.RandomEngine == Prngs.PBPrng)
                throw new CryptoAsymmetricSignException("RNBWKeyGenerator:Ctor", "Passphrase based digest and CTR generators must be pre-initialized, use the other constructor!", new ArgumentException());

            m_rlweParams = CipherParams;
            m_rngEngine = GetPrng(CipherParams.RandomEngine);
        }

        /// <summary>
        /// Use an initialized prng to generate the key; use this constructor with an Rng that requires pre-initialization, i.e. PBPrng
        /// </summary>
        /// 
        /// <param name="CipherParams">The RNBWParameters instance containing the cipher settings</param>
        /// <param name="RngEngine">An initialized Prng instance</param>
        public RNBWKeyGenerator(RNBWParameters CipherParams, IRandom RngEngine)
        {
            m_rlweParams = CipherParams;
            m_rngEngine = RngEngine;
        }

        private RNBWKeyGenerator()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~RNBWKeyGenerator()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Generate an encryption Key pair
        /// </summary>
        /// 
        /// <returns>A RNBWKeyPair containing public and private keys</returns>
        public IAsymmetricKeyPair GenerateKeyPair()
        {
            RNBWPrivateKey privKey;
            RNBWPublicKey pubKey;

            _VI = m_rlweParams.Vi;
            _numLayers = m_rlweParams.NumLayers;
            // choose all coefficients at random
            Generate();
            // now marshall them to PrivateKey
            privKey = new RNBWPrivateKey(_A1Inv, _B1, _A2Inv, _B2, _VI, _layers);
            // marshall to PublicKey
            pubKey = new RNBWPublicKey(_VI[_VI.Length - 1] - _VI[0], _pubQuadratic, _pubSingular, _pubScalar);

            return new RNBWKeyPair(pubKey, privKey);
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// This function calls the functions for the random generation of the coefficients
        /// and the matrices needed for the private key and the method for computing the public key
        /// </summary>
        private void Generate()
        {
            if (ParallelUtils.IsParallel)
            {
                Action[] gA = new Action[] {
                    new Action(()=> GenerateL1()), 
                    new Action(()=> GenerateL2()),
                    new Action(()=> GenerateF())
                };
                Parallel.Invoke(gA);
            }
            else
            {
                GenerateL1();
                GenerateL2();
                GenerateF();
            }

            ComputePublicKey();
        }

        /// <summary>
        /// This function generates the invertible affine linear map L1 = A1*x + b1
        /// <para>The translation part b1, is stored in a separate array. 
        /// The inverse of the matrix-part of L1 A1inv is also computed here.
        /// This linear map hides the output of the map F. It is on k^(n-v1).</para>
        /// </summary>
        private void GenerateL1()
        {
            // dimension = n-v1 = vi[last] - vi[first]
            int dim = _VI[_VI.Length - 1] - _VI[0];
            _A1 = ArrayUtils.CreateJagged<short[][]>(dim, dim);
            _A1Inv = null;
            using (ComputeInField cif = new ComputeInField())
            {
                // generation of A1 at random
                while (_A1Inv == null)
                {
                    for (int i = 0; i < dim; i++)
                    {
                        for (int j = 0; j < dim; j++)
                            _A1[i][j] = (short)(m_rngEngine.Next() & GF2Field.MASK);
                    }
                    _A1Inv = cif.Inverse(_A1);
                }
            }
            // generation of the translation vector at random
            _B1 = new short[dim];
            for (int i = 0; i < dim; i++)
                _B1[i] = (short)(m_rngEngine.Next() & GF2Field.MASK);

        }

        /// <summary>
        /// This function generates the invertible affine linear map L2 = A2*x + b2.
        /// <para>The translation part b2, is stored in a separate array.
        /// The inverse of the matrix-part of L2 A2inv is also computed here.
        /// This linear map hides the output of the map F. It is on k^(n).</para>
        /// </summary>
        private void GenerateL2()
        {
            // dimension = n = vi[last]
            int dim = _VI[_VI.Length - 1];
            _A2 = ArrayUtils.CreateJagged<short[][]>(dim, dim);
            _A2Inv = null;

            using (ComputeInField cif = new ComputeInField())
            {
                // generation of A2 at random
                while (_A2Inv == null)
                {
                    for (int i = 0; i < dim; i++)
                    {
                        for (int j = 0; j < dim; j++)
                            _A2[i][j] = (short)(m_rngEngine.Next() & GF2Field.MASK);
                    }
                    _A2Inv = cif.Inverse(_A2);
                }
            }
            // generation of the translation vector at random
            _B2 = new short[dim];
            for (int i = 0; i < dim; i++)
                _B2[i] = (short)(m_rngEngine.Next() & GF2Field.MASK);
        }

        /// <summary>
        /// This function generates the private map F, which consists of u-1 layers.
        /// <para>Each layer consists of oi polynomials where oi = vi[i+1]-vi[i].
        /// The methods for the generation of the coefficients of these polynomials are called here.</para>
        /// </summary>
        private void GenerateF()
        {
            _layers = new MapLayer[_numLayers];

            for (int i = 0; i < _numLayers; i++)
                _layers[i] = new MapLayer(_VI[i], _VI[i + 1], m_rngEngine);
        }

        /// <summary>
        /// This function computes the public key from the private key.
        /// <para>The composition of F with L2 is computed, followed by applying L1 to the composition's result.
        /// The singular and scalar values constitute to the public key as is, the quadratic terms are compacted in CompactPublicKey.</para>
        /// </summary>
        private void ComputePublicKey()
        {
            ComputeInField cif = new ComputeInField();
            int rows = _VI[_VI.Length - 1] - _VI[0];
            int vars = _VI[_VI.Length - 1];
            // Fpub
            short[][][] coeffQuadratic3d = ArrayUtils.CreateJagged<short[][][]>(rows, vars, vars);
            _pubSingular = ArrayUtils.CreateJagged<short[][]>(rows, vars);
            _pubScalar = new short[rows];
            // Coefficients of layers of Private Key F
            short[][][] coeffAlpha;
            short[][][] coeffBeta;
            short[][] coeffGamma;
            short[] coeffEta;
            // Needed for counters;
            int oils = 0;
            int vins = 0;
            // current row (polynomial)
            int crntRow = 0;
            short[] vectTmp = new short[vars]; // vector tmp;
            short sclrTmp = 0;

            // Composition of F and L2: Insert L2 = A2*x+b2 in F
            for (int l = 0; l < _layers.Length; l++)
            {
                // get coefficients of current layer
                coeffAlpha = _layers[l].CoeffAlpha;
                coeffBeta = _layers[l].CoeffBeta;
                coeffGamma = _layers[l].CoeffGamma;
                coeffEta = _layers[l].CoeffEta;
                oils = coeffAlpha[0].Length;
                vins = coeffBeta[0].Length;

                // compute polynomials of layer
                for (int p = 0; p < oils; p++)
                {
                    // multiply alphas
                    for (int x1 = 0; x1 < oils; x1++)
                    {
                        for (int x2 = 0; x2 < vins; x2++)
                        {
                            // multiply polynomial1 with polynomial2
                            vectTmp = cif.MultVect(coeffAlpha[p][x1][x2], _A2[x1 + vins]);
                            coeffQuadratic3d[crntRow + p] = cif.AddSquareMatrix(coeffQuadratic3d[crntRow + p], cif.MultVects(vectTmp, _A2[x2]));
                            // mul poly1 with scalar2
                            vectTmp = cif.MultVect(_B2[x2], vectTmp);
                            _pubSingular[crntRow + p] = cif.AddVect(vectTmp, _pubSingular[crntRow + p]);
                            // mul scalar1 with poly2
                            vectTmp = cif.MultVect(coeffAlpha[p][x1][x2], _A2[x2]);
                            vectTmp = cif.MultVect(_B2[x1 + vins], vectTmp);
                            _pubSingular[crntRow + p] = cif.AddVect(vectTmp, _pubSingular[crntRow + p]);
                            // mul scalar1 with scalar2
                            sclrTmp = GF2Field.MultElem(coeffAlpha[p][x1][x2], _B2[x1 + vins]);
                            _pubScalar[crntRow + p] = GF2Field.AddElem(_pubScalar[crntRow + p], GF2Field.MultElem(sclrTmp, _B2[x2]));
                        }
                    }

                    // multiply betas
                    for (int x1 = 0; x1 < vins; x1++)
                    {
                        for (int x2 = 0; x2 < vins; x2++)
                        {
                            // multiply polynomial1 with polynomial2
                            vectTmp = cif.MultVect(coeffBeta[p][x1][x2], _A2[x1]);
                            coeffQuadratic3d[crntRow + p] = cif.AddSquareMatrix(coeffQuadratic3d[crntRow + p], cif.MultVects(vectTmp, _A2[x2]));
                            // mul poly1 with scalar2
                            vectTmp = cif.MultVect(_B2[x2], vectTmp);
                            _pubSingular[crntRow + p] = cif.AddVect(vectTmp, _pubSingular[crntRow + p]);
                            // mul scalar1 with poly2
                            vectTmp = cif.MultVect(coeffBeta[p][x1][x2], _A2[x2]);
                            vectTmp = cif.MultVect(_B2[x1], vectTmp);
                            _pubSingular[crntRow + p] = cif.AddVect(vectTmp, _pubSingular[crntRow + p]);
                            // mul scalar1 with scalar2
                            sclrTmp = GF2Field.MultElem(coeffBeta[p][x1][x2], _B2[x1]);
                            _pubScalar[crntRow + p] = GF2Field.AddElem(_pubScalar[crntRow + p], GF2Field.MultElem(sclrTmp, _B2[x2]));
                        }
                    }

                    // multiply gammas
                    for (int n = 0; n < vins + oils; n++)
                    {
                        // mul poly with scalar
                        vectTmp = cif.MultVect(coeffGamma[p][n], _A2[n]);
                        _pubSingular[crntRow + p] = cif.AddVect(vectTmp, _pubSingular[crntRow + p]);
                        // mul scalar with scalar
                        _pubScalar[crntRow + p] = GF2Field.AddElem(_pubScalar[crntRow + p], GF2Field.MultElem(coeffGamma[p][n], _B2[n]));
                    }
                    // add eta
                    _pubScalar[crntRow + p] = GF2Field.AddElem(_pubScalar[crntRow + p], coeffEta[p]);
                }

                crntRow = crntRow + oils;
            }

            // Apply L1 = A1*x+b1 to composition of F and L2
            // temporary coefficient arrays
            short[][][] tmpQuad = ArrayUtils.CreateJagged<short[][][]>(rows, vars, vars);
            short[][] tmpSing = ArrayUtils.CreateJagged<short[][]>(rows, vars);
            short[] tmpScal = new short[rows];

            for (int r = 0; r < rows; r++)
            {
                for (int q = 0; q < _A1.Length; q++)
                {
                    tmpQuad[r] = cif.AddSquareMatrix(tmpQuad[r], cif.MultMatrix(_A1[r][q], coeffQuadratic3d[q]));
                    tmpSing[r] = cif.AddVect(tmpSing[r], cif.MultVect(_A1[r][q], _pubSingular[q]));
                    tmpScal[r] = GF2Field.AddElem(tmpScal[r], GF2Field.MultElem(_A1[r][q], _pubScalar[q]));
                }

                tmpScal[r] = GF2Field.AddElem(tmpScal[r], _B1[r]);
            }

            // set public key
            coeffQuadratic3d = tmpQuad;
            _pubSingular = tmpSing;
            _pubScalar = tmpScal;

            CompactPublicKey(coeffQuadratic3d);
            cif.Dispose();
        }

        /// <summary>
        /// The quadratic (or mixed) terms of the public key are compacted from a n x
        /// n matrix per polynomial to an upper diagonal matrix stored in one integer
        /// array of n (n + 1) / 2 elements per polynomial.
        /// <para>The ordering of elements is lexicographic and the result is updating _pubQuadratic, 
        /// which stores the quadratic elements of the public key.</para>
        /// </summary>
        /// <param name="Quadratic">A 3-dimensional array containing a n x n Matrix for each of the n - v1 polynomials</param>
        private void CompactPublicKey(short[][][] Quadratic)
        {
            int polynomials = Quadratic.Length;
            int n = Quadratic[0].Length;
            int entries = n * (n + 1) / 2;// the small gauss
            _pubQuadratic = ArrayUtils.CreateJagged<short[][]>(polynomials, entries);
            int offset = 0;

            for (int p = 0; p < polynomials; p++)
            {
                offset = 0;
                for (int x = 0; x < n; x++)
                {
                    for (int y = x; y < n; y++)
                    {
                        if (y == x)
                            _pubQuadratic[p][offset] = Quadratic[p][x][y];
                        else
                            _pubQuadratic[p][offset] = GF2Field.AddElem(Quadratic[p][x][y], Quadratic[p][y][x]);

                        offset++;
                    }
                }
            }
        }

        /// <summary>
        /// Get the cipher engine
        /// </summary>
        /// 
        /// <param name="Prng">The Prng</param>
        /// 
        /// <returns>An initialized prng</returns>
        private IRandom GetPrng(Prngs Prng)
        {
            switch (Prng)
            {
                case Prngs.CTRPrng:
                    return new CTRPrng();
                case Prngs.SP20Prng:
                    return new SP20Prng();
                case Prngs.DGCPrng:
                    return new DGCPrng();
                case Prngs.CSPPrng:
                    return new CSPPrng();
                case Prngs.BBSG:
                    return new BBSG();
                case Prngs.CCG:
                    return new CCG();
                case Prngs.MODEXPG:
                    return new MODEXPG();
                case Prngs.QCG1:
                    return new QCG1();
                case Prngs.QCG2:
                    return new QCG2();
                default:
                    throw new CryptoAsymmetricSignException("RNBWEncrypt:GetPrng", "The Prng type is not supported!", new ArgumentException());
            }
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!m_isDisposed && Disposing)
            {
                try
                {
                    if (_A1 != null)
                    {
                        Array.Clear(_A1, 0, _A1.Length);
                        _A1 = null;
                    }
                    if (_A2 != null)
                    {
                        Array.Clear(_A2, 0, _A2.Length);
                        _A2 = null;
                    }
                    if (m_rngEngine != null)
                    {
                        m_rngEngine.Dispose();
                        m_rngEngine = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
