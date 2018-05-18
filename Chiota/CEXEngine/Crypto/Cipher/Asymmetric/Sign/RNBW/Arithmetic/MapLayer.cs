#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.Arithmetic
{
    /// <summary>
    /// This class represents a layer of the Rainbow Oil and Vinegar Map.
    /// <para>Each Layer consists of oi polynomials with their coefficients, generated at random.</para>
    /// </summary>
    /// 
    /// <remarks>
    /// <para>To sign a document, we solve a LES (linear equation system) for each layer in
    /// order to find the oil variables of that layer and to be able to use the
    /// variables to compute the signature. This functionality is implemented in the
    /// RainbowSignature-class, by the aid of the private key.</para>
    /// <para>Each layer is a part of the private key.</para>
    /// <para>More information about the layer can be found in the paper of Jintai Ding,
    /// Dieter Schmidt: Rainbow, a New Multivariable Polynomial Signature Scheme.
    /// ACNS 2005: <a href="http://dx.doi.org/10.1007/11496137_12">164-175</a>.</para>
    /// </remarks>
    public class MapLayer : IDisposable
    {
        #region Fields
        private short[][][] _coeffAlpha;
        private short[][][] _coeffBeta;
        private short[][] _coeffGamma;
        private short[] _coeffEta;
        private bool m_isDisposed = false;
        // number of oils in this layer
        private int _OI;
        // number of vinegars in this layer
        private int _VI; 
        // number of vinegars in next layer
        private int _viNext;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the number of vinegar variables of this layer
        /// </summary>
        public int VI
        {
            get { return _VI; }
        }

        /// <summary>
        /// Get: Returns the number of vinegar variables of the next layer
        /// </summary>
        public int ViNext
        {
            get { return _viNext; }
        }

        /// <summary>
        /// Get: Returns the number of Oil variables of this layer
        /// </summary>
        public int OI
        {
            get { return _OI; }
        }

        /// <summary>
        /// Get: Returns the alpha-coefficients of the polynomials in this layer
        /// </summary>
        public short[][][] CoeffAlpha
        {
            get { return _coeffAlpha; }
        }

        /// <summary>
        /// Get: Returns the beta-coefficients of the polynomials in this layer
        /// </summary>
        public short[][][] CoeffBeta
        {
            get { return _coeffBeta; }
        }

        /// <summary>
        /// Get: Returns the gamma-coefficients of the polynomials in this layer
        /// </summary>
        public short[][] CoeffGamma
        {
            get { return _coeffGamma; }
        }

        /// <summary>
        /// Get: Returns the eta-coefficients of the polynomials in this layer
        /// </summary>
        public short[] CoeffEta
        {
            get { return _coeffEta; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Vi">The number of vinegar variables of this layer</param>
        /// <param name="ViNext">The number of vinegar variables of next layer; the same as (num of oils) + (num of vinegars) of this layer</param>
        /// <param name="CoeffAlpha">The alpha-coefficients in the polynomials of this layer</param>
        /// <param name="CoeffBeta">The beta-coefficients in the polynomials of this layer</param>
        /// <param name="CoeffGamma">The gamma-coefficients in the polynomials of this layer</param>
        /// <param name="CoeffEta">The eta-coefficients in the polynomials of this layer</param>
        public MapLayer(byte Vi, byte ViNext, short[][][] CoeffAlpha, short[][][] CoeffBeta, short[][] CoeffGamma, short[] CoeffEta)
        {
            _VI = Vi & 0xff;
            _viNext = ViNext & 0xff;
            _OI = _viNext - _VI;
            // the secret coefficients of all polynomials in this layer
            _coeffAlpha = CoeffAlpha;
            _coeffBeta = CoeffBeta;
            _coeffGamma = CoeffGamma;
            _coeffEta = CoeffEta;
        }

        /// <summary>
        /// This function generates the coefficients of all polynomials in this layer at random using random generator
        /// </summary>
        /// <param name="Vi">The number of vinegar variables of this layer</param>
        /// <param name="ViNext">The number of vinegar variables of next layer</param>
        /// <param name="Rand">he random generator which is to be used</param>
        public MapLayer(int Vi, int ViNext, IRandom Rand)
        {
            _VI = Vi;
            _viNext = ViNext;
            _OI = ViNext - Vi;

            // the coefficients of all polynomials in this layer  
            _coeffAlpha = ArrayUtils.CreateJagged<short[][][]>(_OI, _OI, _VI);
            _coeffBeta = ArrayUtils.CreateJagged<short[][][]>(_OI, _VI, _VI);
            _coeffGamma = ArrayUtils.CreateJagged<short[][]>(_OI, _viNext);
            _coeffEta = new short[_OI];

            int numOfPoly = _OI; // number of polynomials per layer

            // Alpha coeffs
            for (int k = 0; k < numOfPoly; k++)
            {
                for (int i = 0; i < _OI; i++)
                {
                    for (int j = 0; j < _VI; j++)
                        _coeffAlpha[k][i][j] = (short)(Rand.Next() & GF2Field.MASK);
                }
            }
            // Beta coeffs
            for (int k = 0; k < numOfPoly; k++)
            {
                for (int i = 0; i < _VI; i++)
                {
                    for (int j = 0; j < _VI; j++)
                        _coeffBeta[k][i][j] = (short)(Rand.Next() & GF2Field.MASK);
                }
            }
            // Gamma coeffs
            for (int k = 0; k < numOfPoly; k++)
            {
                for (int i = 0; i < _viNext; i++)
                    _coeffGamma[k][i] = (short)(Rand.Next() & GF2Field.MASK);
            }

            // Eta
            for (int k = 0; k < numOfPoly; k++)
            {
                _coeffEta[k] = (short)(Rand.Next() & GF2Field.MASK);
            }
        }

        /// <summary>
        /// Reads a Layer from a Stream
        /// </summary>
        /// 
        /// <param name="LayerStream">An input stream containing an encoded Layer</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be loaded</exception>
        public MapLayer(Stream LayerStream)
        {
            try
            {
                BinaryReader reader = new BinaryReader(LayerStream);
                int len;
                byte[] data;

                _VI = reader.ReadInt32();
                _viNext = reader.ReadInt32();

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _coeffAlpha = ArrayUtils.ToArray3x16(data);

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _coeffBeta = ArrayUtils.ToArray3x16(data);

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _coeffGamma = ArrayUtils.ToArray2x16(data);

                len = reader.ReadInt32();
                data = reader.ReadBytes(len);
                _coeffEta = ArrayUtils.ToArray16(data);
                
            }
            catch (IOException ex)
            {
                throw new CryptoAsymmetricException("Layer:CTor", "The Layer could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Reads a Layer from a byte array
        /// </summary>
        /// 
        /// <param name="LayerArray">The encoded Layer</param>
        public MapLayer(byte[] LayerArray) :
            this(new MemoryStream(LayerArray))
        {
        }

        private MapLayer()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MapLayer()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// This method plugs in the vinegar variables into the polynomials of this layer and computes
        /// the coefficients of the Oil-variables as well as the free coefficient in each polynomial.
        /// </summary>
        /// 
        /// <param name="X">The vinegar variables of this layer that should be plugged into the polynomials</param>
        /// 
        /// <returns>Returns the coefficients of Oil variables and the free coeff in the polynomials of this layer</returns>
        public short[][] PlugInVinegars(short[] X)
        {
            // temporary variable needed for the multiplication
            short tmpMult = 0;
            // coeff: 1st index = which polynomial, 2nd index=which variable
            short[][] coeff = ArrayUtils.CreateJagged<short[][]>(_OI, _OI + 1);
            // free coefficient per polynomial
            short[] sum = new short[_OI];

            // evaluate the beta-part of the polynomials (it contains no oil variables)
            for (int k = 0; k < _OI; k++)
            {
                for (int i = 0; i < _VI; i++)
                {
                    for (int j = 0; j < _VI; j++)
                    {
                        // tmp = beta * xi (plug in)
                        tmpMult = GF2Field.MultElem(_coeffBeta[k][i][j], X[i]);
                        // tmp = tmp * xj
                        tmpMult = GF2Field.MultElem(tmpMult, X[j]);
                        // accumulate into the array for the free coefficients.
                        sum[k] = GF2Field.AddElem(sum[k], tmpMult);
                    }
                }
            }

            // evaluate the alpha-part (it contains oils)
            for (int k = 0; k < _OI; k++)
            {
                for (int i = 0; i < _OI; i++)
                {
                    for (int j = 0; j < _VI; j++)
                    {
                        // alpha * xj (plug in)
                        tmpMult = GF2Field.MultElem(_coeffAlpha[k][i][j], X[j]);
                        // accumulate
                        coeff[k][i] = GF2Field.AddElem(coeff[k][i], tmpMult);
                    }
                }
            }

            // evaluate the gama-part of the polynomial (containing no oils)
            for (int k = 0; k < _OI; k++)
            {
                for (int i = 0; i < _VI; i++)
                {
                    // gamma * xi (plug in)
                    tmpMult = GF2Field.MultElem(_coeffGamma[k][i], X[i]);
                    // accumulate in the array for the free coefficients (per polynomial)
                    sum[k] = GF2Field.AddElem(sum[k], tmpMult);
                }
            }

            // evaluate the gama-part of the polynomial (but containing oils)
            for (int k = 0; k < _OI; k++)
            {
                // accumulate the coefficients of the oil variables (per polynomial)
                for (int i = _VI; i < _viNext; i++)
                    coeff[k][i - _VI] = GF2Field.AddElem(_coeffGamma[k][i], coeff[k][i - _VI]);
            }

            // evaluate the eta-part of the polynomial
            for (int k = 0; k < _OI; k++)
            {
                // accumulate in the array for the free coefficients per polynomial.
                sum[k] = GF2Field.AddElem(sum[k], _coeffEta[k]);
            }

            /* put the free coefficients (sum) into the coeff-array as last column */
            for (int k = 0; k < _OI; k++)
            {
                coeff[k][_OI] = sum[k];
            }

            return coeff;
        }

        /// <summary>
        /// Read a Private key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the encoded key</param>
        /// 
        /// <returns>An initialized RNBWPrivateKey class</returns>
        public static MapLayer From(byte[] KeyArray)
        {
            return new MapLayer(KeyArray);
        }

        /// <summary>
        /// Read a Private key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized RNBWPrivateKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static MapLayer From(Stream KeyStream)
        {
            return new MapLayer(KeyStream);
        }

        /// <summary>
        /// Converts the Private key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded RNBWPrivateKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the RNBWPrivateKey to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Private Key encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] data;

            writer.Write(_VI);
            writer.Write(_viNext);

            data = ArrayUtils.ToBytes(_coeffAlpha);
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayUtils.ToBytes(_coeffBeta);
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayUtils.ToBytes(_coeffGamma);
            writer.Write(data.Length);
            writer.Write(data);

            data = ArrayUtils.ToBytes(_coeffEta);
            writer.Write(data.Length);
            writer.Write(data);

            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        #endregion

        #region Overrides
        /// <summary>
        /// This function compares this Layer with another object
        /// </summary>
        /// 
        /// <param name="Obj">The other object</param>
        /// 
        /// <returns>The result of the comparison</returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is MapLayer))
            {
                return false;
            }
            MapLayer otherLayer = (MapLayer)Obj;

            return  _VI == otherLayer.VI && 
                _viNext == otherLayer.ViNext && 
                _OI == otherLayer.OI && 
                RainbowUtil.Equals(_coeffAlpha, otherLayer.CoeffAlpha) && 
                RainbowUtil.Equals(_coeffBeta, otherLayer.CoeffBeta) && 
                RainbowUtil.Equals(_coeffGamma, otherLayer.CoeffGamma) && 
                RainbowUtil.Equals(_coeffEta, otherLayer.CoeffEta);
        }

        /// <summary>
        /// Get the hash code for this object
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int hash = 31 * _VI;
            hash += 31 * _viNext;
            hash += 31 * _OI;
            hash += ArrayUtils.GetHashCode(_coeffAlpha);
            hash += ArrayUtils.GetHashCode(_coeffBeta);
            hash += ArrayUtils.GetHashCode(_coeffGamma);
            hash += ArrayUtils.GetHashCode(_coeffEta);

            return hash;
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
                    if (_coeffAlpha != null)
                    {
                        Array.Clear(_coeffAlpha, 0, _coeffAlpha.Length);
                        _coeffAlpha = null;
                    }
                    if (_coeffBeta != null)
                    {
                        Array.Clear(_coeffBeta, 0, _coeffBeta.Length);
                        _coeffBeta = null;
                    }
                    if (_coeffGamma != null)
                    {
                        Array.Clear(_coeffGamma, 0, _coeffGamma.Length);
                        _coeffGamma = null;
                    }
                    if (_coeffEta != null)
                    {
                        Array.Clear(_coeffEta, 0, _coeffEta.Length);
                        _coeffEta = null;
                    }
                    if (_coeffEta != null)
                    {
                        Array.Clear(_coeffEta, 0, _coeffEta.Length);
                        _coeffEta = null;
                    }
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
