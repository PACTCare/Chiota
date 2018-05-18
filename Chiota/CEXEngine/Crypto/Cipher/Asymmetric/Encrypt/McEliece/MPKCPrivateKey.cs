#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra;
using VTDev.Libraries.CEXEngine.CryptoException;
using System.Runtime.Serialization.Formatters.Binary;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece
{
    /// <summary>
    /// A McEliece Private Key
    /// </summary>
    public sealed class MPKCPrivateKey : IAsymmetricKey
    {
        #region Constants
        private const int GF_LENGTH = 4;
        private const string ALG_NAME = "MPKCPrivateKey";
        #endregion

        #region Fields
        private GF2mField m_gField;
        private PolynomialGF2mSmallM m_goppaPoly;
        private bool m_isDisposed = false;
        private GF2Matrix m_H;
        private int m_K;
        private int m_N;
        private Permutation m_P1;
        private PolynomialGF2mSmallM[] m_qInv;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Private key name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }

        /// <summary>
        /// Get: Returns the finite field <c>GF(2^m)</c>
        /// </summary>
        internal GF2mField GF
        {
            get { return m_gField; }
        }

        /// <summary>
        /// Get: Returns the irreducible Goppa polynomial
        /// </summary>
        internal PolynomialGF2mSmallM GP
        {
            get { return m_goppaPoly; }
        }

        /// <summary>
        /// Get: Returns the canonical check matrix H
        /// </summary>
        internal GF2Matrix H
        {
            get { return m_H; }
        }

        /// <summary>
        /// Get: Returns the dimension of the code
        /// </summary>
        public int K
        {
            get { return m_K; }
        }

        /// <summary>
        /// Get: Returns the length of the code
        /// </summary>
        public int N
        {
            get { return m_N; }
        }

        /// <summary>
        /// Get: Returns the permutation used to generate the systematic check matrix
        /// </summary>
        internal Permutation P1
        {
            get { return m_P1; }
        }

        /// <summary>
        /// Get: Returns the matrix used to compute square roots in <c>(GF(2^m))^t</c>
        /// </summary>
        internal PolynomialGF2mSmallM[] QInv
        {
            get { return m_qInv; }
        }

        /// <summary>
        /// Get: Returns the degree of the Goppa polynomial (error correcting capability)
        /// </summary>
        public int T
        {
            get { return m_goppaPoly.Degree; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class for CCA2 MPKCS
        /// </summary>
        /// 
        /// <param name="N">Length of the code</param>
        /// <param name="K">The dimension of the code</param>
        /// <param name="Gf">The finite field <c>GF(2^m)</c></param>
        /// <param name="Gp">The irreducible Goppa polynomial</param>
        /// <param name="P">The permutation</param>
        /// <param name="H">The canonical check matrix</param>
        /// <param name="QInv">The matrix used to compute square roots in <c>(GF(2^m))^t</c></param>
        internal MPKCPrivateKey(int N, int K, GF2mField Gf, PolynomialGF2mSmallM Gp, Permutation P, GF2Matrix H, PolynomialGF2mSmallM[] QInv)
        {
            m_N = N;
            m_K = K;
            m_gField = Gf;
            m_goppaPoly = Gp;
            m_P1 = P;
            m_H = H;
            m_qInv = QInv;
        }
        
        /// <summary>
        /// Initialize this class CCA2 MPKCS using encoded byte arrays
        /// </summary>
        /// 
        /// <param name="N">Length of the code</param>
        /// <param name="K">The dimension of the code</param>
        /// <param name="Gf">Encoded field polynomial defining the finite field <c>GF(2^m)</c></param>
        /// <param name="Gp">Encoded irreducible Goppa polynomial</param>
        /// <param name="P">The encoded permutation</param>
        /// <param name="H">Encoded canonical check matrix</param>
        /// <param name="QInv">The encoded matrix used to compute square roots in <c>(GF(2^m))^t</c></param>
        public MPKCPrivateKey(int N, int K, byte[] Gf, byte[] Gp, byte[] P, byte[] H, byte[][] QInv)
        {
            m_N = N;
            m_K = K;
            m_gField = new GF2mField(Gf);
            m_goppaPoly = new PolynomialGF2mSmallM(m_gField, Gp);
            m_P1 = new Permutation(P);
            m_H = new GF2Matrix(H);
            m_qInv = new PolynomialGF2mSmallM[QInv.Length];

            for (int i = 0; i < QInv.Length; i++)
                m_qInv[i] = new PolynomialGF2mSmallM(m_gField, QInv[i]);
        }

        /// <summary>
        /// Reads a Private Key from a Stream
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be loaded</exception>
        public MPKCPrivateKey(Stream KeyStream)
        {
            try
            {
                int len;
                BinaryReader reader = new BinaryReader(KeyStream);

                // length
                m_N = reader.ReadInt32();
                // dimension
                m_K = reader.ReadInt32();

                // gf
                byte[] gf = reader.ReadBytes(GF_LENGTH);
                m_gField = new GF2mField(gf);

                // gp
                len = reader.ReadInt32();
                byte[] gp = reader.ReadBytes(len);
                m_goppaPoly = new PolynomialGF2mSmallM(m_gField, gp);

                // p1
                len = reader.ReadInt32();
                byte[] p1 = reader.ReadBytes(len);
                m_P1 = new Permutation(p1);

                // check matrix
                len = reader.ReadInt32();
                byte[] h = reader.ReadBytes(len);
                m_H = new GF2Matrix(h);

                // length of first dimension
                len = reader.ReadInt32();
                byte[][] qi = new byte[len][];

                // get the qinv encoded array
                for (int i = 0; i < qi.Length; i++)
                {
                    len = reader.ReadInt32();
                    qi[i] = reader.ReadBytes(len);
                }

                // assign qinv
                m_qInv = new PolynomialGF2mSmallM[qi.Length];

                for (int i = 0; i < QInv.Length; i++)
                    m_qInv[i] = new PolynomialGF2mSmallM(m_gField, qi[i]);
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("MPKCPrivateKey:CTor", "The Private key could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Reads a Private Key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The encoded key array</param>
        public MPKCPrivateKey(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private MPKCPrivateKey()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MPKCPrivateKey()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Read a Private key from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">The byte array containing the encoded key</param>
        /// 
        /// <returns>An initialized MPKCPrivateKey class</returns>
        public static MPKCPrivateKey From(byte[] KeyArray)
        {
            return new MPKCPrivateKey(KeyArray);
        }

        /// <summary>
        /// Read a Private key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the encoded key</param>
        /// 
        /// <returns>An initialized MPKCPrivateKey class</returns>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the stream can not be read</exception>
        public static MPKCPrivateKey From(Stream KeyStream)
        {
            return new MPKCPrivateKey(KeyStream);
        }

        /// <summary>
        /// Converts the Private key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded MPKCPrivateKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the MPKCPrivateKey to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Private Key encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            // length
            writer.Write(m_N);
            // dimension
            writer.Write(m_K);
            // gf
            writer.Write(m_gField.GetEncoded());
            // gp
            byte[] gp = m_goppaPoly.GetEncoded();
            writer.Write(gp.Length);
            writer.Write(gp);
            // p1
            byte[] p = m_P1.GetEncoded();
            writer.Write(p.Length);
            writer.Write(p);

            // check matrix
            byte[] h = m_H.GetEncoded();
            writer.Write(h.Length);
            writer.Write(h);

            // length of first dimension
            writer.Write(m_qInv.Length);
            for (int i = 0; i < m_qInv.Length; i++)
            {
                // roots
                byte[] qi = m_qInv[i].GetEncoded();
                writer.Write(qi.Length);
                writer.Write(qi);
            }
            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }

        /// <summary>
        /// Writes encoded the MPKCPrivateKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Private Key encoded as a byte array</param>
        public void WriteTo(byte[] Output)
        {
            byte[] data = ToBytes();
            Output = new byte[data.Length];
            Buffer.BlockCopy(data, 0, Output, 0, data.Length);
        }

        /// <summary>
        /// Writes the encoded MPKCPrivateKey to an output byte array
        /// </summary>
        /// 
        /// <param name="Output">The Private Key encoded to a byte array</param>
        /// <param name="Offset">The starting position within the Output array</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the output array is too small</exception>
        public void WriteTo(byte[] Output, int Offset)
        {
            byte[] data = ToBytes();
            if (Offset + data.Length > Output.Length - Offset)
                throw new CryptoAsymmetricException("MPKCPrivateKey:WriteTo", "The output array is too small!", new ArgumentOutOfRangeException());

            Buffer.BlockCopy(data, 0, Output, Offset, data.Length);
        }

        /// <summary>
        /// Writes the encoded MPKCPrivateKey to an output stream
        /// </summary>
        /// 
        /// <param name="Output">The Output Stream receiving the encoded Private Key</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if the key could not be written</exception>
        public void WriteTo(Stream Output)
        {
            try
            {
                using (MemoryStream stream = ToStream())
                    stream.WriteTo(Output);
            }
            catch (Exception ex)
            {
                throw new CryptoAsymmetricException("MPKCPrivateKey:WriteTo", "The key could not be written!", ex);
            }
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Decides whether the given object <c>other</c> is the same as this field
        /// </summary>
        /// 
        /// <param name="Obj">The object for comparison</param>
        /// 
        /// <returns>Returns <c>(this == other)</c></returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is MPKCPrivateKey))
                return false;

            MPKCPrivateKey key = (MPKCPrivateKey)Obj;


            if (!N.Equals(key.N))
                return false;
            if (!K.Equals(key.K))
                return false;
            if (!GF.Equals(key.GF))
                return false;
            if (!GP.Equals(key.GP))
                return false;
            if (!P1.Equals(key.P1))
                return false;
            if (!H.Equals(key.H))
                return false;
            if (QInv.Length != key.QInv.Length)
                return false;

            for (int i = 0; i < QInv.Length; i++)
            {
                if (!QInv[i].Equals(key.QInv[i]))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Returns the hash code of this field
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            int hash = N * 31;
            hash += K * 31;
            hash += GF.GetHashCode();
            hash += GP.GetHashCode();
            hash += P1.GetHashCode();

            return hash;
        }
        #endregion

        #region IClone
        /// <summary>
        /// Create a shallow copy of this MPKCPublicKey instance
        /// </summary>
        /// 
        /// <returns>The MPKCPublicKey copy</returns>
        public object Clone()
        {
            return new MPKCPrivateKey(m_N, m_K, m_gField, m_goppaPoly, m_P1, m_H, m_qInv);
        }

        /// <summary>
        /// Create a deep copy of this MPKCPublicKey instance
        /// </summary>
        /// 
        /// <returns>The MPKCPublicKey copy</returns>
        public object DeepCopy()
        {
            return new MPKCPrivateKey(ToStream());
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
                    if (m_gField != null)
                    {
                        m_gField.Clear();
                        m_gField = null;
                    }
                    if (m_goppaPoly != null)
                    {
                        m_goppaPoly.Clear();
                        m_goppaPoly = null;
                    }
                    if (m_H != null)
                    {
                        m_H.Clear();
                        m_H = null;
                    }
                    if (m_P1 != null)
                    {
                        m_P1.Clear();
                        m_P1 = null;
                    }
                    if (m_qInv != null)
                    {
                        for (int i = 0; i < m_qInv.Length; i++)
                        {
                            m_qInv[i].Clear();
                            m_qInv[i] = null;
                        }
                        m_qInv = null;
                    }
                    m_K = 0;
                    m_N = 0;
                }
                catch { }

                m_isDisposed = true;
            }
        }
        #endregion
    }
}
