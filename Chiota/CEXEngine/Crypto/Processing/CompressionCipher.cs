#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Tools;
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
// Written by John Underhill, May 18, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing
{
    /// <summary>
    /// CompressionCipher: Used to compress and cryptographically transform a stream.
    /// <para>Extends the CipherStream class for encrypting a compressed directory of files.
    /// If the cipher is for encryption, files are compressed and encrypted to the output stream.
    /// If the cipher is for decryption, the input stream contains the compressed and encrypted directory, 
    /// and the directory path is the destination path for the decrypted and inflated files.</para>
    /// 
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example of archiving/encrypting and decrypting/inflating a Directory:</description>
    /// <code>
    /// public static void CompressionCipherTest(string InputDirectory, string OutputDirectory, string CompressedFilePath)
    /// {
    ///     KeyParams kp = new KeyGenerator().GetKeyParams(32, 16);
    ///     // Create an archive //
    ///     // create the cipher
    ///     using (ICipherMode cipher = new CTR(new RHX()))
    ///     {
    ///         // initialize the cipher for encryption
    ///         cipher.Initialize(true, kp);
    /// 
    ///         // create the archive file
    ///         using (FileStream fs = new FileStream(CompressedFilePath, FileMode.Create))
    ///         {
    ///             // compress and encrypt directory
    ///             using (CompressionCipher cc = new CompressionCipher(true, cipher))
    ///             {
    ///                 // set the input folder path and archive output stream
    ///                 cc.Initialize(InputDirectory, fs);
    ///                 // write the compressed and encrypted archive to file
    ///                 cc.Write();
    ///             }
    ///         }
    ///     }
    /// 
    ///     // Inflate an archive //
    ///     // create the cipher
    ///     using (ICipherMode cipher = new CTR(new RHX()))
    ///     {
    ///         // initialize the cipher for decryption
    ///         cipher.Initialize(false, kp);
    /// 
    ///         // open the archive
    ///         using (FileStream decmp = new FileStream(CompressedFilePath, FileMode.Open))
    ///         {
    ///             // decrypt and inflate to output directory
    ///             using (CompressionCipher cc = new CompressionCipher(false, cipher))
    ///             {
    ///                 // set the output folder path and archive path
    ///                 cc.Initialize(OutputDirectory, decmp);
    ///                 // decrypt and inflate the directory
    ///                 cc.Write();
    ///             }
    ///         }
    ///     }
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Uses any of the implemented <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode">Cipher Mode</see> wrapped <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Block Ciphers</see>, or any of the implemented <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream.IStreamCipher">Stream Ciphers</see>.</description></item>
    /// <item><description>Cipher Engine can be Disposed when this class is Disposed, set the DisposeEngine parameter in the class Constructor to true to dispose automatically.</description></item>
    /// <item><description>Streams can be Disposed when the class is Disposed, set the DisposeStream parameter in the Initialize(Stream, Stream, bool) call to true to dispose automatically.</description></item>
    /// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per any of the compress/decompress calls.</description></item>
    /// <item><description>Changes to the Cipher or CipherStream ParallelBlockSize must be set after initialization.</description></item>
    /// </list>
    /// </remarks>
    public class CompressionCipher : CipherStream
    {
        #region Fields
        private Compressor m_cmpEngine;
        private Compressor.CompressionFormats m_cmpFormat = Compressor.CompressionFormats.Deflate;
        private bool m_isInitialized =  false;
        #endregion

        #region Properties
        /// <summary>
        /// GetSet: The compression algorithm used to compress a file
        /// </summary>
        public Compressor.CompressionFormats CompressionFormat 
        {
            get { return m_cmpFormat; }
            set { m_cmpFormat = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class with a CipherDescription Structure; containing the cipher implementation details.
        /// <para>This constructor creates and configures cryptographic instances based on the cipher description contained in a CipherDescription. 
        /// Cipher modes, padding, and engine classes are destroyed automatically through this classes Dispose() method.</para>
        /// </summary>
        /// 
        /// <param name="Header">A <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/> containing the cipher description</param>
        /// 
        /// <exception cref="System.ArgumentException">Thrown if an invalid CipherDescription is used</exception>
        /// <exception cref="System.ArgumentNullException">Thrown if a null <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.KeyParams">KeyParams</see> is used</exception>
        public CompressionCipher(CipherDescription Header)
            : base(Header)
        {
        }

        /// <summary>
        /// Initialize the class with a Block Cipher wrapped in a <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode">Cipher Mode</see>, and optional <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding.IPadding">Padding</see> instances.
        /// <para>This constructor requires a fully initialized <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.CipherModes">CipherMode</see> instance.
        /// If the <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PaddingModes">PaddingMode</see> parameter is null, X9.23 padding will be used if required.</para>
        /// </summary>
        /// 
        /// <param name="Cipher">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Block Cipher</see> wrapped in a <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode">Cipher</see> mode</param>
        /// <param name="Padding">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding.IPadding">Padding</see> instance</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Cipher is used</exception>
        /// <exception cref="System.ArgumentException">Thrown if an uninitialized Cipher is used</exception>
        public CompressionCipher(ICipherMode Cipher, IPadding Padding = null) :
            base(Cipher, Padding)
        {
        }

        /// <summary>
        /// Initialize the class with a <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream.IStreamCipher">Stream Cipher</see> instance.
        /// <para>This constructor requires a fully initialized <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">CipherStream</see> instance.</para>
        /// </summary>
        /// 
        /// <param name="Cipher">The initialized <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream.IStreamCipher">Stream Cipher</see> instance</param>
        /// 
        /// <exception cref="System.ArgumentNullException">Thrown if a null Stream Cipher is used</exception>
        /// <exception cref="System.ArgumentException">Thrown if an uninitialized Cipher is used</exception>
        public CompressionCipher(IStreamCipher Cipher) :
            base(Cipher)
        {
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize the compression cipher
        /// </summary>
        /// 
        /// <param name="Encryption">Archive encryption or decryption</param>
        /// <param name="KeyParam">The class containing the cipher keying material</param>
        /// <param name="Format">The compression algorithm</param>
        public void Initialize(bool Encryption, KeyParams KeyParam, Compressor.CompressionFormats Format = Compressor.CompressionFormats.Deflate)
        {
            m_cmpEngine = new Compressor(Format);
            base.Initialize(Encryption, KeyParam);
            m_isInitialized = true;
        }

        /// <summary>
        /// Compress a stream
        /// </summary>
        /// 
        /// <param name="InStream">The stream to be processed</param>
        /// 
        /// <returns>The encrypted and compressed stream</returns>
        public Stream Compress(Stream InStream)
        {
            if (!m_isInitialized)
                throw new CryptoProcessingException("CompressionCipher:Compress", "The class is not be Initialized!", new ArgumentException());

            // compress
            MemoryStream inStream = m_cmpEngine.CompressStream(InStream);
            inStream.Seek(0, SeekOrigin.Begin);
            MemoryStream outStream =  new MemoryStream();
            // encrypt
            base.Write(inStream, outStream);
            outStream.Seek(0, SeekOrigin.Begin);

            return outStream;
        }

        /// <summary>
        /// Decompress a stream
        /// </summary>
        /// 
        /// <param name="InStream">The stream to be processed</param>
        /// 
        /// <returns>The decrypted and decompressed stream</returns>
        public Stream DeCompress(Stream InStream)
        {
            if (!m_isInitialized)
                throw new CryptoProcessingException("CompressionCipher:Compress", "The class is not be Initialized!", new ArgumentException());

            // decrypt
            MemoryStream outStream = new MemoryStream();
            base.Write(InStream, outStream);
            outStream.Seek(0, SeekOrigin.Begin);
            // decompress
            MemoryStream retStream = m_cmpEngine.DeCompressStream(outStream);
            retStream.Seek(0, SeekOrigin.Begin);

            return retStream;
        }

        /// <summary>
        /// Deflate (compress) an archive
        /// </summary>
        /// 
        /// <param name="DirectoryPath">The directory path to the files to be processed</param>
        /// <param name="OutStream">The stream receiving the compressed and encrypted archive</param>
        public void Deflate(string DirectoryPath, Stream OutStream)
        {
            if (!m_isInitialized)
                throw new CryptoProcessingException("CompressionCipher:Compress", "The class is not be Initialized!", new ArgumentException());
            if (!DirectoryTools.Exists(DirectoryPath))
                throw new CryptoProcessingException("CompressionCipher:Deflate", "The directory does not exist!", new ArgumentException());
            if (DirectoryTools.FileCount(DirectoryPath) < 1)
                throw new CryptoProcessingException("CompressionCipher:Deflate", "There are no files in this directory!", new ArgumentException());

            // compress
            MemoryStream inStream = m_cmpEngine.CompressArchive(DirectoryPath);
            inStream.Seek(0, SeekOrigin.Begin);
            // encrypt output
            base.Write(inStream, OutStream);
            OutStream.Seek(0, SeekOrigin.Begin);
        }

        /// <summary>
        /// Inflate (decompress) an archive
        /// </summary>
        /// 
        /// <param name="DirectoryPath">The directory path where files will be written</param>
        /// <param name="InStream">The stream containing the compressed archive</param>
        public void Inflate(string DirectoryPath, Stream InStream)
        {
            if (!m_isInitialized)
                throw new CryptoProcessingException("CompressionCipher:Compress", "The class is not be Initialized!", new ArgumentException());
            if (!DirectoryTools.Exists(DirectoryPath))
                Directory.CreateDirectory(DirectoryPath);
            if (!DirectoryTools.IsWritable(DirectoryPath))
                throw new CryptoProcessingException("CompressionCipher:InFlate", "Directory path is not writable! Check permissions.", new AccessViolationException());

            // decrypt stream
            MemoryStream outStream = new MemoryStream();
            base.Write(InStream, outStream);
            outStream.Seek(0, SeekOrigin.Begin);
            // decompress
            m_cmpEngine.DeCompressArchive(outStream, DirectoryPath);
        }
        #endregion
    }
}
