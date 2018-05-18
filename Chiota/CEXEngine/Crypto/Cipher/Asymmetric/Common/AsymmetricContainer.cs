
#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using System.IO;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Common
{
    /// <summary>
    /// A class that can store an asymmetric key or key-pair, a parameters set, and an optional tag value.
    /// </summary>
    /// 
    /// <remarks>
    /// <para>Use this class to store a ciphers keys and settings.
    /// The optional Tag value can be any length, is stored at the start of a serialized structure 
    /// (int: tag size, byte[]: tag value), and can be used to uniquely identify a container.
    /// Use the ToBytes() or ToStream() methods to serialize a container, and the 
    /// corresponding constructors to deserialize a stream or byte array.</para>
    /// </remarks>
    public sealed class AsymmetricContainer : IDisposable
    {
        #region Fields
        private AsymmetricEngines m_asmEngine;
        private IAsymmetricParameters m_asmParameters;
        private byte[] m_idTag;
        private bool m_isDisposed = false;
        private IAsymmetricKey m_privateKey;
        private IAsymmetricKey m_publicKey;
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the asymmetric cipher family
        /// </summary>
        public AsymmetricEngines EngineType
        {
            get { return m_asmEngine; }
        }

        /// <summary>
        /// Get: Returns the parameters
        /// </summary>
        public IAsymmetricParameters Parameters
        {
            get { return m_asmParameters; }
        }

        /// <summary>
        /// Get: Returns the public key
        /// </summary>
        public IAsymmetricKey PublicKey
        {
            get { return m_publicKey; }
        }

        /// <summary>
        /// Get: Returns the private key
        /// </summary>
        public IAsymmetricKey PrivateKey
        {
            get { return m_privateKey; }
        }

        /// <summary>
        /// Get: Returns the identity tag
        /// </summary>
        public byte[] Tag
        {
            get { return m_idTag; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Parameters">The cipher Parameters</param>
        /// <param name="AsmKey">The Public or Private asymmetric key</param>
        /// <param name="Tag">An identity field</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid key is used</exception>
        public AsymmetricContainer(IAsymmetricParameters Parameters, IAsymmetricKey AsmKey, byte[] Tag = null)
        {
            m_asmParameters = Parameters;
            m_idTag = Tag;

            if (AsymmetricUtils.IsPublicKey(AsmKey))
                m_publicKey = AsmKey;
            else
                m_privateKey = AsmKey;
        }

        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Parameters">The cipher Parameters</param>
        /// <param name="KeyPair">The public or private key</param>
        /// <param name="Tag">An identity field</param>
        /// 
        /// <exception cref="CryptoAsymmetricException">Thrown if an invalid key is used</exception>
        public AsymmetricContainer(IAsymmetricParameters Parameters, IAsymmetricKeyPair KeyPair, byte[] Tag = null)
        {
            if (!(KeyPair is IAsymmetricKeyPair))
                throw new CryptoAsymmetricException("KeyContainer:Ctor", "Not a valid key-pair!", new InvalidDataException());

            m_publicKey = KeyPair.PublicKey;
            m_privateKey = KeyPair.PrivateKey;
            m_asmParameters = Parameters;
            m_idTag = Tag;
        }
        
        /// <summary>
        /// Reads the key container from an input stream
        /// </summary>
        /// 
        /// <param name="KeyStream">An input stream containing an encoded key container</param>
        public AsymmetricContainer(MemoryStream KeyStream)
        {
            BinaryReader reader = new BinaryReader(KeyStream);
            byte[] data;
            int len;

            m_idTag = null;
            m_publicKey = null;
            m_publicKey = null;

            // tag
            len = reader.ReadInt32();
            if (len > 0)
                m_idTag = reader.ReadBytes(len);

            // family
            m_asmEngine = (AsymmetricEngines)reader.ReadByte();

            // parameters
            len = reader.ReadInt32();
            data = reader.ReadBytes(len);
            m_asmParameters = ParamsFromBytes(data);

            // public key
            len = reader.ReadInt32();
            if (len > 0)
            {
                data = reader.ReadBytes(len);
                m_publicKey = PublicKeyFromBytes(data);
            }

            // private key
            len = reader.ReadInt32();
            if (len > 0)
            {
                data = reader.ReadBytes(len);
                m_privateKey = PrivateKeyFromBytes(data);
            }
        }

        /// <summary>
        /// Reads the key container from a byte array
        /// </summary>
        /// 
        /// <param name="KeyArray">An byte array containing an encoded key container</param>
        public AsymmetricContainer(byte[] KeyArray) :
            this(new MemoryStream(KeyArray))
        {
        }

        private AsymmetricContainer()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~AsymmetricContainer()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods

        /// <summary>
        /// Converts the Public key to an encoded byte array
        /// </summary>
        /// 
        /// <returns>The encoded RLWEPublicKey</returns>
        public byte[] ToBytes()
        {
            return ToStream().ToArray();
        }

        /// <summary>
        /// Converts the Public key to an encoded MemoryStream
        /// </summary>
        /// 
        /// <returns>The Public Key encoded as a MemoryStream</returns>
        public MemoryStream ToStream()
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] data;

            // tag
            if (m_idTag == null)
            {
                writer.Write((int)0);
            }
            else
            {
                writer.Write(m_idTag.Length);
                writer.Write(m_idTag);
            }

            // family
            writer.Write((byte)m_asmEngine);

            // parameters
            data = m_asmParameters.ToBytes();
            writer.Write(data.Length);
            writer.Write(data);

            // public key
            if (m_publicKey == null)
            {
                writer.Write((int)0);
            }
            else
            {
                data = m_publicKey.ToBytes();
                writer.Write(data.Length);
                writer.Write(data);
            }

            // private key
            if (m_privateKey == null)
            {
                writer.Write((int)0);
            }
            else
            {
                data = m_privateKey.ToBytes();
                writer.Write(data.Length);
                writer.Write(data);
            }
            writer.BaseStream.Seek(0, SeekOrigin.Begin);

            return (MemoryStream)writer.BaseStream;
        }
        #endregion

        #region Private Methods
        private IAsymmetricParameters ParamsFromBytes(byte[] ParameterArray)
        {
            if (m_asmEngine == AsymmetricEngines.GMSS)
                return new GMSSParameters(ParameterArray);
            else if (m_asmEngine == AsymmetricEngines.McEliece)
                return new MPKCParameters(ParameterArray);
            else if (m_asmEngine == AsymmetricEngines.NTRU)
                return new NTRUParameters(ParameterArray);
            else if (m_asmEngine == AsymmetricEngines.Rainbow)
                return new RNBWParameters(ParameterArray);
            else
                return new RLWEParameters(ParameterArray);
        }

        private IAsymmetricKey PublicKeyFromBytes(byte[] KeyArray)
        {
            if (m_asmEngine == AsymmetricEngines.GMSS)
                return new GMSSPublicKey(KeyArray);
            else if (m_asmEngine == AsymmetricEngines.McEliece)
                return new MPKCPublicKey(KeyArray);
            else if (m_asmEngine == AsymmetricEngines.NTRU)
                return new NTRUPublicKey(KeyArray);
            else if (m_asmEngine == AsymmetricEngines.Rainbow)
                return new RNBWPublicKey(KeyArray);
            else
                return new RLWEPublicKey(KeyArray);
        }

        private IAsymmetricKey PrivateKeyFromBytes(byte[] KeyArray)
        {
            if (m_asmEngine == AsymmetricEngines.GMSS)
                return new GMSSPrivateKey(KeyArray);
            else if (m_asmEngine == AsymmetricEngines.McEliece)
                return new MPKCPrivateKey(KeyArray);
            else if (m_asmEngine == AsymmetricEngines.NTRU)
                return new NTRUPrivateKey(KeyArray);
            else if (m_asmEngine == AsymmetricEngines.Rainbow)
                return new RNBWPrivateKey(KeyArray);
            else
                return new RLWEPrivateKey(KeyArray);
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
                    if (m_asmParameters != null)
                    {
                        m_asmParameters.Dispose();
                        m_asmParameters = null;
                    }
                    if (m_publicKey != null)
                    {
                        m_publicKey.Dispose();
                        m_publicKey = null;
                    }
                    if (m_privateKey != null)
                    {
                        m_privateKey.Dispose();
                        m_privateKey = null;
                    }
                    if (m_idTag != null)
                    {
                        Array.Clear(m_idTag, 0, m_idTag.Length);
                        m_idTag = null;
                    }
                }
                finally
                {
                    m_isDisposed = true;
                }
            }
        }
        #endregion
    }
}
