#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.Crypto.Processing.Structure;
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
// Written by John Underhill, January 21, 2015
// contact: develop@vtdev.com
#endregion

// ToDo:
// add a file to existing volume
// use headers to track files
// move keystream from ctor to initialize

namespace VTDev.Libraries.CEXEngine.Crypto.Processing
{
    /// <summary>
    /// VolumeCipher: Performs bulk file cryptographic transforms.
    /// <para>A helper class used to encrypt or decrypt a series of files on a directory or volume.</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example of encrypting a group of files:</description>
    /// <code>
    /// // key will be written to this stream
    /// MemoryStream keyStream = new MemoryStream();
    /// 
    /// // encrypt the files in the directory
    /// using (VolumeCipher vc = new VolumeCipher())
    /// {
    ///     keyStream = vc.CreateKey(CipherDescription.AES256CTR, FilePaths.Length);
    ///     vc.ProgressPercent += OnVolumeProgressPercent;
    ///     vc.Initialize(keyStream);
    ///     vc.Encrypt(FilePaths);
    /// }
    /// 
    /// // write the key
    /// keyStream.Seek(0, SeekOrigin.Begin);
    /// using (FileStream outStream = new FileStream(KeyPath, FileMode.Create, FileAccess.ReadWrite))
    ///     keyStream.CopyTo(outStream);
    /// </code>
    /// 
    /// <description>Example of decrypting a file:</description>
    /// <code>
    /// using (FileStream ks = new FileStream(KeyPath, FileMode.Open, FileAccess.ReadWrite))
    /// {
    ///     using (VolumeCipher vc = new VolumeCipher())
    ///     {
    ///         vc.Initialize(ks);
    ///         vc.Decrypt(paths);
    ///     }
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode.ICipherMode"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream.IStreamCipher"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Uses any of the implemented <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">Cipher Mode</see> wrapped <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription">Block Ciphers</see>, 
    /// or any of the implemented <see cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream.IStreamCipher">Stream Ciphers</see>.</description></item>
    /// <item><description>Cipher Engine can be Disposed when this class is Disposed, set the DisposeEngine parameter in the class Constructor to true to dispose automatically.</description></item>
    /// <item><description>Streams can be Disposed when the class is Disposed, set the DisposeStream parameter in the Initialize(Stream, Stream, bool) call to true to dispose automatically.</description></item>
    /// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per either of the 'Transform()' calls.</description></item>
    /// <item><description>Changes to the Cipher or CipherStream ParallelBlockSize must be set after initialization.</description></item>
    /// </list>
    /// </remarks>
    public class VolumeCipher : IDisposable
    {
        #region Events
        /// <summary>
        /// Progress indicator delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="args">Progress event arguments containing percentage and bytes processed as the UserState param</param>
        public delegate void ProgressDelegate(object sender, ProgressEventArgs args);

        /// <summary>
        /// Error notification delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="message">The bnature of the error</param>
        public delegate void NotificationDelegate(object sender, string message);

        /// <summary>
        /// Progress Percent Event; returns bytes processed as an integer percentage
        /// </summary>
        public event ProgressDelegate ProgressPercent;

        /// <summary>
        /// Error Notification; alerts the caller to an error condition that has not halted processing
        /// </summary>
        public event NotificationDelegate ErrorNotification;
        #endregion

        #region Event Args
        /// <summary>
        /// An event arguments class containing the decrypted message data.
        /// </summary>
        public class ProgressEventArgs : EventArgs
        {
            #region Fields
            /// <summary>
            /// Length of the stream
            /// </summary>
            public long Length = 0;
            /// <summary>
            /// The percentage of data processed
            /// </summary>
            public int Percent = 0;
            #endregion

            #region Constructor
            /// <summary>
            /// Initialize this class
            /// </summary>
            /// 
            /// <param name="Length">Length of the stream</param>
            /// <param name="Percent">The percentage of data processed</param>
            public ProgressEventArgs(long Length, int Percent)
            {
                this.Length = Length;
                this.Percent = Percent;
            }
        }
        #endregion
        #endregion

        #region Fields
        private CipherStream m_cipherStream;
        private bool m_isDisposed = false;
        private Stream m_keyStream;
        private long m_progressTotal = 0;
        private VolumeKey m_volumeKey;
        #endregion

        #region Properties
        /// <summary>
        /// Get/Set: Automatic processor parallelization
        /// </summary>
        public bool IsParallel
        {
            get { return m_cipherStream.IsParallel; }
            set { m_cipherStream.IsParallel = value; }
        }

        /// <summary>
        /// Get/Set: Determines how the size of a parallel block is calculated
        /// </summary>
        public CipherStream.BlockProfiles ParallelBlockProfile
        {
            get { return m_cipherStream.ParallelBlockProfile; }
            set { m_cipherStream.ParallelBlockProfile = value; }
        }

        /// <summary>
        /// Get/Set: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
        /// </summary>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a parallel block size is not evenly divisible by ParallelMinimumSize, 
        /// or the size is less than ParallelMinimumSize or more than ParallelMaximumSize values</exception>
        public int ParallelBlockSize
        {
            get { return m_cipherStream.ParallelBlockSize; }
            set
            {
                try
                {
                    m_cipherStream.ParallelBlockSize = value;
                }
                catch (Exception ex)
                {
                    throw new CryptoProcessingException("VolumeCipher:ParallelBlockSize", "The block size is invalid!", ex);
                }
            }
        }

        /// <summary>
        /// Get: Maximum input size with parallel processing
        /// </summary>
        public int ParallelMaximumSize
        {
            get { return m_cipherStream.ParallelMaximumSize; }
        }

        /// <summary>
        /// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
        /// </summary>
        public int ParallelMinimumSize
        {
            get { return m_cipherStream.ParallelMinimumSize; }
        }
        #endregion

        #region Constructor 
        /// <summary>
        /// Initialize this class
        /// </summary>
        public VolumeCipher()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~VolumeCipher()
        {
            Dispose(false);
        }
        #endregion

        #region Key Creation
        /// <summary>
        /// Create a volume key file using automatic key material generation.
        /// <para>The Key, and IV sets are generated automatically using the cipher description contained in the <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/>.
        /// This overload creates keying material using the seed and digest engines specified with the <see cref="KeyGenerator"/> class</para>
        /// </summary>
        /// 
        /// <param name="Key">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Processing.Structure.VolumeKey">VolumeKey</see> containing the cipher and key implementation details</param>
        /// <param name="SeedEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SeedGenerators">Random Generator</see> used to create the stage I seed material during key generation.</param>
        /// <param name="HashEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest Engine</see> used in the stage II phase of key generation.</param>
        /// 
        /// <returns>A populated VolumeKey</returns>
        public MemoryStream CreateKey(VolumeKey Key, SeedGenerators SeedEngine = SeedGenerators.CSPRsg, Digests HashEngine = Digests.SHA512)
        {
            int ksize = Key.Count * (Key.Description.KeySize + Key.Description.IvSize);
            byte[] kdata;

            using (KeyGenerator keyGen = new KeyGenerator(SeedEngine, HashEngine, null))
                kdata = keyGen.GetBytes(ksize);

            MemoryStream keyStream = new MemoryStream();
            byte[] hdr = Key.ToBytes();
            keyStream.Write(hdr, 0, hdr.Length);
            keyStream.Write(kdata, 0, kdata.Length);
            keyStream.Seek(0, SeekOrigin.Begin);

            return keyStream;
        }

        /// <summary>
        /// Create a volume key file using a <see cref="VTDev.Libraries.CEXEngine.Crypto.Common.CipherDescription"/> containing the cipher implementation details, and a key count size
        /// </summary>
        /// 
        /// <param name="Description">The >Cipher Description containing the cipher details</param>
        /// <param name="KeyCount">The number of key sets associated with this volume key</param>
        /// <param name="SeedEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SeedGenerators">Random Generator</see> used to create the stage I seed material during key generation.</param>
        /// <param name="HashEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest Engine</see> used in the stage II phase of key generation.</param>
        /// 
        /// <exception cref="System.IO.FileLoadException">A key file exists at the path specified</exception>
        /// <exception cref="System.UnauthorizedAccessException">The key file path is read only</exception>
        /// 
        /// <returns>A populated VolumeKey</returns>
        public MemoryStream CreateKey(CipherDescription Description, int KeyCount, SeedGenerators SeedEngine = SeedGenerators.CSPRsg, Digests HashEngine = Digests.SHA512)
        {
            return this.CreateKey(new VolumeKey(Description, KeyCount), SeedEngine, HashEngine);
        }

        /// <summary>
        /// Create a volume key file using a manual description of the cipher parameters.
        /// </summary>
        /// 
        /// <param name="KeyCount">The number of key sets associated with this volume key</param>
        /// <param name="EngineType">The Cryptographic <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.SymmetricEngines">Engine</see> type</param>
        /// <param name="KeySize">The cipher Key Size in bytes</param>
        /// <param name="IvSize">Size of the cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.IVSizes">Initialization Vector</see></param>
        /// <param name="CipherType">The type of <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.CipherModes">Cipher Mode</see></param>
        /// <param name="PaddingType">The type of cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.PaddingModes">Padding Mode</see></param>
        /// <param name="BlockSize">The cipher <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.BlockSizes">Block Size</see></param>
        /// <param name="Rounds">The number of diffusion <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.RoundCounts">Rounds</see></param>
        /// <param name="KdfEngine">The <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests">Digest</see> engine used to power the key schedule Key Derivation Function in HX and M series ciphers</param>
        /// 
        /// <returns>A populated VolumeKey</returns>
        public MemoryStream CreateKey(int KeyCount, SymmetricEngines EngineType, int KeySize, IVSizes IvSize, 
            CipherModes CipherType, PaddingModes PaddingType, BlockSizes BlockSize, RoundCounts Rounds, Digests KdfEngine)
        {
            CipherDescription dsc = new CipherDescription()
            {
                EngineType = (int)EngineType,
                KeySize = KeySize,
                IvSize = (int)IvSize,
                CipherType = (int)CipherType,
                PaddingType = (int)PaddingType,
                BlockSize = (int)BlockSize,
                RoundCount = (int)Rounds,
                KdfEngine = (int)KdfEngine,
            };

            return CreateKey(dsc, KeyCount);
        }

        /// <summary>
        /// Extract a KeyParams and CipherDescription from a VolumeKey stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The stream containing the VolumeKey</param>
        /// <param name="Index">The index of the key set to extract</param>
        /// <param name="Description">The <see cref="CipherDescription"/> that receives the cipher description</param>
        /// <param name="KeyParam">The <see cref="KeyParams"/> container that receives the key material from the file</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the key file could not be found</exception>
        public void ExtractKey(Stream KeyStream, int Index, out CipherDescription Description, out KeyParams KeyParam)
        {
            if (KeyStream == null || KeyStream.Length < 96)
                throw new CryptoProcessingException("VolumeFactory:Extract", "The key file could not be loaded! Check the stream.", new FileNotFoundException());

            VolumeKey vkey = new VolumeKey(KeyStream);
            Description = vkey.Description;
            KeyParam = VolumeKey.AtIndex(KeyStream, Index);
        }
        #endregion

        #region Transform
        /// <summary>
        /// Decrypt a single file in the volume
        /// </summary>
        /// 
        /// <param name="InputPath">The path to the encrypted file</param>
        /// <param name="OututPath">The path to the new decrypted file</param>
        public void Decrypt(string InputPath, string OututPath)
        {
            FileStream inpStream = GetStream(InputPath, true);
            VolumeHeader vh = GetHeader(inpStream);
            KeyParams key = VolumeKey.FromId(m_keyStream, vh.FileId);

            if (key == null)
            {
                if (ErrorNotification != null)
                    ErrorNotification(this, string.Format("The file {0}; has no key assigned", InputPath));
            }
            else
            {
                FileStream outStream = GetStream(OututPath, false);

                if (inpStream == null || outStream == null)
                {
                    if (ErrorNotification != null)
                        ErrorNotification(this, string.Format("The file {0}; could not be written to", OututPath));
                }
                else
                {
                    m_volumeKey.State[m_volumeKey.GetIndex(vh.FileId)] = (byte)VolumeKeyStates.Decrypted;
                    m_cipherStream.ProgressPercent += OnCipherProgress;
                    m_cipherStream.Initialize(false, key);
                    m_cipherStream.Write(inpStream, outStream);
                    m_cipherStream.ProgressPercent -= OnCipherProgress;
                    outStream.SetLength(outStream.Length - VolumeHeader.GetHeaderSize);
                    inpStream.Dispose();
                    outStream.Dispose();
                    UpdateKey();
                }
            }
        }

        /// <summary>
        /// Decrypt the files in the specified directory
        /// </summary>
        /// 
        /// <param name="FilePaths">A list of the files to be processed</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the VolumeKey does not contain enough keys to encrypt all the files in the directory</exception>
        public void Decrypt(string[] FilePaths)
        {
            if (FilePaths.Length < 1)
                throw new CryptoProcessingException("VolumeCipher:Transform", "The file paths list is empty!", new ArgumentException());

            InitializeProgress(FilePaths);

            if (m_progressTotal < 1)
                throw new CryptoProcessingException("VolumeCipher:Initialize", "The files are all zero bytes!", new ArgumentException());

            long prgCtr = 0;

            for (int i = 0; i < FilePaths.Length; ++i)
            {
                FileStream inpStream = GetStream(FilePaths[i], true);
                VolumeHeader vh = GetHeader(inpStream);
                KeyParams key = VolumeKey.FromId(m_keyStream, vh.FileId);

                // user dropped a file in, notify or log
                if (key == null)
                {
                    if (ErrorNotification != null)
                        ErrorNotification(this, string.Format("The file {0}; has no key assigned", FilePaths[i]));
                }
                else
                {
                    FileStream outStream = GetStream(FilePaths[i], false);

                    if (inpStream == null || outStream == null)
                    {
                        if (ErrorNotification != null)
                            ErrorNotification(this, string.Format("The file {0}; could not be written to", FilePaths[i]));
                    }
                    else
                    {
                        m_volumeKey.State[m_volumeKey.GetIndex(vh.FileId)] = (byte)VolumeKeyStates.Decrypted;
                        m_cipherStream.Initialize(false, key);
                        m_cipherStream.Write(inpStream, outStream);
                        outStream.SetLength(outStream.Length - VolumeHeader.GetHeaderSize);

                        prgCtr += inpStream.Position;
                        CalculateProgress(prgCtr);
                        inpStream.Dispose();
                        outStream.Dispose();
                        UpdateKey();
                    }
                }
            }
        }

        /// <summary>
        /// Encrypt the files in the specified directory
        /// </summary>
        /// 
        /// <param name="FilePaths">A list of the files to be processed</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the VolumeKey does not contain enough keys to encrypt all the files in the directory</exception>
        public void Encrypt(string[] FilePaths)
        {
            if (FilePaths.Length < 1)
                throw new CryptoProcessingException("VolumeCipher:Transform", "The file paths list is empty!", new ArgumentException());
            if (m_volumeKey.KeyCount() < FilePaths.Length)
                throw new CryptoProcessingException("VolumeCipher:Transform", "Not enough keys in the volume key to encrypt this directory!", new ArgumentException());
            
            InitializeProgress(FilePaths);

            if (m_progressTotal < 1)
                throw new CryptoProcessingException("VolumeCipher:Initialize", "The files are all zero bytes!", new ArgumentException());

            long prgCtr = 0;

            for (int i = 0; i < FilePaths.Length; ++i)
            {
                int index = m_volumeKey.NextSubKey();
                KeyParams key = VolumeKey.AtIndex(m_keyStream, index);

                if (key == null)
                {
                    if (ErrorNotification != null)
                        ErrorNotification(this, string.Format("The file {0}; has no key assigned", FilePaths[i]));
                }
                else
                {
                    FileStream inpStream = GetStream(FilePaths[i], true);
                    FileStream outStream = GetStream(FilePaths[i], false);

                    if (inpStream == null || outStream == null)
                    {
                        if (ErrorNotification != null)
                            ErrorNotification(this, string.Format("The file {0}; could not be written to", FilePaths[i]));
                    }
                    else
                    {
                        m_volumeKey.State[index] = (byte)VolumeKeyStates.Encrypted;
                        m_cipherStream.Initialize(true, key);
                        m_cipherStream.Write(inpStream, outStream);

                        // write the header
                        VolumeHeader vh = new VolumeHeader(m_volumeKey.Tag, m_volumeKey.FileId[index]);
                        outStream.Write(vh.ToBytes(), 0, VolumeHeader.GetHeaderSize);

                        prgCtr += inpStream.Position;
                        CalculateProgress(prgCtr);
                        inpStream.Dispose();
                        outStream.Dispose();
                        UpdateKey();
                    }
                }
            }
        }

        /// <summary>
        /// Encrypt a file with a specific key
        /// </summary>
        /// 
        /// <param name="FilePath">The full path to the file</param>
        /// <param name="FileId">The files key id</param>
        public void Encrypt(string FilePath, int FileId)
        {
            if (m_progressTotal < 1)
                throw new CryptoProcessingException("VolumeCipher:Initialize", "The files are all zero bytes!", new ArgumentException());

            KeyParams key = VolumeKey.FromId(m_keyStream, FileId);

            if (key == null)
            {
                if (ErrorNotification != null)
                    ErrorNotification(this, string.Format("The file {0}; has no key assigned", FilePath));
            }
            else
            {
                FileStream inpStream = GetStream(FilePath, true);
                FileStream outStream = GetStream(FilePath, false);

                if (inpStream == null || outStream == null)
                {
                    if (ErrorNotification != null)
                        ErrorNotification(this, string.Format("The file {0}; could not be written to", FilePath));
                }
                else
                {
                    int index = m_volumeKey.GetIndex(FileId);
                    m_volumeKey.State[index] = (byte)VolumeKeyStates.Encrypted;
                    m_cipherStream.Initialize(true, key);
                    m_cipherStream.ProgressPercent += OnCipherProgress;
                    m_cipherStream.Write(inpStream, outStream);
                    m_cipherStream.ProgressPercent -= OnCipherProgress;

                    // write the header
                    VolumeHeader vh = new VolumeHeader(m_volumeKey.Tag, m_volumeKey.FileId[index]);
                    outStream.Write(vh.ToBytes(), 0, VolumeHeader.GetHeaderSize);

                    inpStream.Dispose();
                    outStream.Dispose();
                    UpdateKey();
                }
            }
        }

        /// <summary>
        /// Initialize the cipher instance
        /// </summary>
        /// 
        /// <param name="KeyStream">A stream containing a volume key</param>
        public void Initialize(Stream KeyStream)
        {
            m_keyStream = KeyStream;
            m_volumeKey = new VolumeKey(KeyStream);

            if (!CipherDescription.IsValid(m_volumeKey.Description))
                throw new CryptoProcessingException("VolumeCipher:Initialize", "The key Header is invalid!", new ArgumentException());

            CipherDescription dsc = m_volumeKey.Description;

            try
            {
                m_cipherStream = new CipherStream(dsc);
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("VolumeCipher:Initialize", "The cipher could not be initialized!", ex);
            }
        }
        #endregion

        #region Helpers
        private void CalculateProgress(long Processed)
        {
            if (ProgressPercent == null)
                return;

            if (m_progressTotal != Processed)
            {
                double progress = 100.0 * ((double)Processed / m_progressTotal);
                if (progress > 100.0)
                    progress = 100.0;

                ProgressPercent(this, new ProgressEventArgs(m_progressTotal, (int)progress));
            }
            else
            {
                ProgressPercent(this, new ProgressEventArgs(m_progressTotal, 100));
            }
        }

        private VolumeHeader GetHeader(Stream InputStream)
        {
            InputStream.Seek(InputStream.Length - VolumeHeader.GetHeaderSize, SeekOrigin.Begin);
            VolumeHeader vh = new VolumeHeader(InputStream);
            InputStream.Seek(0, SeekOrigin.Begin);

            return vh;
        }

        private FileStream GetStream(string FilePath, bool Read)
        {
            try
            {
                if (Read)
                    return new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Write, 64000, FileOptions.WriteThrough);
                else
                    return new FileStream(FilePath, FileMode.Open, FileAccess.Write, FileShare.Read);
            }
            catch
            {
                return null;
            }
        }

        private void InitializeProgress(string[] FilePaths)
        {
            for (int i = 0; i < FilePaths.Length; i++)
                m_progressTotal += FileTools.GetSize(FilePaths[i]);
        }

        private void OnCipherProgress(object sender, CipherStream.ProgressEventArgs args)
        {
            if (ProgressPercent != null)
                ProgressPercent(this, new ProgressEventArgs(args.Length, args.Percent));
        }

        private void UpdateKey()
        {
            byte[] ks = m_volumeKey.ToBytes();
            m_keyStream.Seek(0, SeekOrigin.Begin);
            m_keyStream.Write(ks, 0, ks.Length);
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
                    m_progressTotal = 0;
                    m_volumeKey.Reset();
                    if (m_cipherStream != null)
                        m_cipherStream.Dispose();
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
