#region Directives
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
using VTDev.Libraries.CEXEngine.Crypto.Mac;
using VTDev.Libraries.CEXEngine.CryptoException;
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
// Written by John Underhill, January 22, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Processing
{
    /// <summary>
    /// MacStream: Wraps file and memory stream message authentication.
    /// <para>Wraps Message Authentication Code (MAC) stream functions in an easy to use interface.</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Example of hashing a Stream:</description>
    /// <code>
    /// byte[] hash;
    /// using (IMac mac = new HMAC(new SHA512()))
    /// {
    ///     mac.Initialize(new KeyParams(key));
    ///     
    ///     using (MacStream mstrm = new MacStream(mac, [false]))
    ///     {
    ///         // assign the input stream
    ///         mstrm.Initialize(InputStream, [true]);
    ///         // get the digest
    ///         hash = mstrm.ComputeMac([Length], [InOffset]);
    ///     }
    /// }
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Mac"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Macs"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.IDigest"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Digests"/>
    /// 
    /// <remarks>
    /// <description>Implementation Notes:</description>
    /// <list type="bullet">
    /// <item><description>Uses any of the implemented <see cref="VTDev.Libraries.CEXEngine.Crypto.Enumeration.Macs">Macs</see> using the <see cref="VTDev.Libraries.CEXEngine.Crypto.Mac.IMac">interface</see>.</description></item>
    /// <item><description>Mac must be fully initialized before passed to the constructor.</description></item>
    /// <item><description>Mac can be Disposed when this class is <see cref="Dispose()">Disposed</see>, set the DisposeEngine parameter in the class Constructor to true to dispose automatically.</description></item>
    /// <item><description>Input Stream can be Disposed when this class is Disposed, set the DisposeStream parameter in the <see cref="Initialize(Stream, bool)"/> call to true to dispose automatically.</description></item>
    /// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per either <see cref="ComputeMac(long, long)">ComputeMac([InOffset], [OutOffset])</see> calls.</description></item>
    /// </list>
    /// </remarks>
    public sealed class MacStream : IDisposable
    {
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
            #endregion
        }
        #endregion

        #region Events
        /// <summary>
        /// Progress indicator delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="args">Progress event arguments containing percentage and bytes processed as the UserState param</param>
        public delegate void ProgressDelegate(object sender, ProgressEventArgs args);

        /// <summary>
        /// Progress Percent Event; returns bytes processed as an integer percentage
        /// </summary>
        public event ProgressDelegate ProgressPercent;
        #endregion

        #region Constants
        private static int BUFFER_SIZE = 64 * 1024;
        #endregion

        #region Fields
        private int m_blockSize;
        private IMac _macEngine;
        private bool m_disposeEngine = false;
        private bool m_disposeStream = false;
        private Stream m_inStream;
        private bool m_isConcurrent = true;
        private bool m_isDisposed = false;
        private bool m_isInitialized = false;
        private long m_progressInterval;
        #endregion

        #region Properties
        /// <summary>
        /// Enable file reads and digest processing to run concurrently
        /// <para>The default is true, but will revert to false if the stream is not a FileStream, 
        /// or the file size is less that 65535 bytes in length.</para>
        /// </summary>
        public bool IsConcurrent
        {
            get { return m_isConcurrent; }
            set { m_isConcurrent = value; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class with a MacDescription structure and a Key
        /// </summary>
        /// 
        /// <param name="Description">A MacDescription structure containing details about the Mac generator</param>
        /// <param name="MacKey">A KeyParams containing the Mac key and Iv; note the Ikm parameter in KeyParams is not used</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called; default is false</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if the Mac key or parameters are invalid</exception>
        public MacStream(MacDescription Description, KeyParams MacKey, bool DisposeEngine = false)
        {
            try
            {
                _macEngine = MacFromDescription.GetInstance(Description);
                _macEngine.Initialize(MacKey.Key, MacKey.IV);
            }
            catch (Exception ex)
            {
                throw new CryptoProcessingException("MacStream:CTor", "The Mac parameters or key is invalid!", ex);
            }

            m_blockSize = _macEngine.BlockSize;
            m_disposeEngine = DisposeEngine;
        }

        /// <summary>
        /// Initialize the class with an initialized Mac instance
        /// </summary>
        /// 
        /// <param name="Mac">The initialized <see cref="VTDev.Libraries.CEXEngine.Crypto.Mac.IMac"/> instance</param>
        /// <param name="DisposeEngine">Dispose of digest engine when <see cref="Dispose()"/> on this class is called; default is false</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if an uninitialized Mac is used</exception>
        public MacStream(IMac Mac, bool DisposeEngine = false)
        {
            if (Mac == null)
                throw new CryptoProcessingException("MacStream:CTor", "The Mac can not be null!", new ArgumentNullException());
            if (!Mac.IsInitialized)
                throw new CryptoProcessingException("MacStream:CTor", "The Mac has not been initialized!", new ArgumentException());

            _macEngine = Mac;
            m_blockSize = _macEngine.BlockSize;
            m_disposeEngine = DisposeEngine;
        }

        private MacStream()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~MacStream()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Initialize internal state
        /// </summary>
        /// 
        /// <param name="InStream">The Source stream to be transformed</param>
        /// <param name="DisposeStream">Dispose of streams when <see cref="Dispose()"/> on this class is called</param>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if a null Input stream is used</exception>
        public void Initialize(Stream InStream, bool DisposeStream = false)
        {
            if (InStream == null)
                throw new CryptoProcessingException("MacStream:Initialize", "The Input stream can not be null!", new ArgumentNullException());

            m_disposeStream = DisposeStream;
            m_inStream = InStream;
            CalculateInterval(m_inStream.Length);
            m_isInitialized = true;
        }

        /// <summary>
        /// Process the entire length of the Input Stream
        /// </summary>
        /// 
        /// <returns>The Message Authentication Code</returns>
        ///  
        /// <exception cref="CryptoProcessingException">Thrown if ComputeMac is called before Initialize(), or Size + Offset is longer than Input stream</exception>
        public byte[] ComputeMac()
        {
            if (!m_isInitialized)
                throw new CryptoProcessingException("MacStream:ComputeMac", "Initialize() must be called before a write operation can be performed!", new InvalidOperationException());
            if (m_inStream.Length < 1)
                throw new CryptoProcessingException("MacStream:ComputeMac", "The Input stream is too short!", new ArgumentOutOfRangeException());

            if (m_inStream.Length < BUFFER_SIZE || !m_inStream.GetType().Equals(typeof(FileStream)))
                m_isConcurrent = false;

            long dataLen = m_inStream.Length - m_inStream.Position;
            CalculateInterval(dataLen);

            return Compute(dataLen);
        }

        /// <summary>
        /// Process a length within the Input stream using an Offset
        /// </summary>
        /// 
        /// <param name="Length">The number of bytes to process</param>
        /// <param name="Offset">The Input Stream positional offset</param>
        /// 
        /// <returns>The Message Authentication Code</returns>
        /// 
        /// <exception cref="CryptoProcessingException">Thrown if ComputeHash is called before Initialize(), or if Size + Offset is longer than Input stream</exception>
        public byte[] ComputeMac(long Length, long Offset)
        {
            if (!m_isInitialized)
                throw new CryptoProcessingException("MacStream:ComputeMac", "Initialize() must be called before a ComputeMac operation can be performed!", new InvalidOperationException());
            if (Length - Offset < 1)
                throw new CryptoProcessingException("MacStream:ComputeMac", "The Input stream is too short!", new ArgumentOutOfRangeException());
            if (Length - Offset > m_inStream.Length)
                throw new CryptoProcessingException("MacStream:ComputeMac", "The Input stream is too short!", new ArgumentOutOfRangeException());

            if (m_inStream.Length - Offset < BUFFER_SIZE || !m_inStream.GetType().Equals(typeof(FileStream)))
                m_isConcurrent = false;

            long dataLen = Length - Offset;
            CalculateInterval(Length - Offset);
            m_inStream.Position = Offset;

            return Compute(dataLen);
        }
        #endregion

        #region Private Methods
        private void CalculateInterval(long Offset)
        {
            long interval = (m_inStream.Length - Offset) / 100;

            if (interval < m_blockSize)
                m_progressInterval = m_blockSize;
            else
                m_progressInterval = interval - (interval % m_blockSize);

            if (m_progressInterval == 0)
                m_progressInterval = m_blockSize;
        }

        private void CalculateProgress(long Size)
        {
            if (ProgressPercent == null)
                return;

            if (Size == m_inStream.Length)
            {
                ProgressPercent(this, new ProgressEventArgs(Size, 100));
            }
            else if (Size % m_progressInterval == 0)
            {
                double progress = 100.0 * (double)Size / m_inStream.Length;
                ProgressPercent(this, new ProgressEventArgs(Size, (int)progress));
            }
        }

        private byte[] Compute(long Length)
        {
            long bytesTotal = 0;
            byte[] chkSum = new byte[_macEngine.MacSize];

            if (!m_isConcurrent)
            {
                byte[] buffer = new byte[m_blockSize];
                int bytesRead = 0;
                long maxBlocks = Length / m_blockSize;

                for (int i = 0; i < maxBlocks; i++)
                {
                    bytesRead = m_inStream.Read(buffer, 0, m_blockSize);
                    _macEngine.BlockUpdate(buffer, 0, bytesRead);
                    bytesTotal += bytesRead;
                    CalculateProgress(bytesTotal);
                }

                // last block
                if (bytesTotal < Length)
                {
                    buffer = new byte[Length - bytesTotal];
                    bytesRead = m_inStream.Read(buffer, 0, buffer.Length);
                    _macEngine.BlockUpdate(buffer, 0, bytesRead);
                    bytesTotal += bytesRead;
                }
            }
            else
            {
                bytesTotal = ConcurrentStream(m_inStream, Length);
            }

            // get the hash
            _macEngine.DoFinal(chkSum, 0);
            CalculateProgress(bytesTotal);

            return chkSum;
        }

        private long ConcurrentStream(Stream Input, long Length = -1)
        {
            long bytesTotal = 0;
            if (Input.CanSeek)
            {
                if (Length > -1)
                {
                    if (Input.Position + Length > Input.Length)
                        throw new IndexOutOfRangeException();
                }

                if (Input.Position >= Input.Length)
                    return 0;
            }

            ConcurrentQueue<byte[]> queue = new ConcurrentQueue<byte[]>();
            AutoResetEvent dataReady = new AutoResetEvent(false);
            AutoResetEvent prepareData = new AutoResetEvent(false);

            Task reader = Task.Factory.StartNew(() =>
            {
                long total = 0;

                for (; ; )
                {
                    byte[] data = new byte[BUFFER_SIZE];
                    int bytesRead = Input.Read(data, 0, data.Length);

                    if ((Length == -1) && (bytesRead != BUFFER_SIZE))
                        data = data.SubArray(0, bytesRead);
                    else if ((Length != -1) && (total + bytesRead >= Length))
                        data = data.SubArray(0, (int)(Length - total));

                    total += data.Length;
                    queue.Enqueue(data);
                    dataReady.Set();

                    if (Length == -1)
                    {
                        if (bytesRead != BUFFER_SIZE)
                            break;
                    }
                    else if (Length == total)
                    {
                        break;
                    }
                    else if (bytesRead != BUFFER_SIZE)
                    {
                        throw new EndOfStreamException();
                    }

                    prepareData.WaitOne();
                }
            });

            Task hasher = Task.Factory.StartNew(() =>
            {
                IMac h = (IMac)_macEngine;
                long total = 0;

                for (; ; )
                {
                    dataReady.WaitOne();
                    byte[] data;
                    queue.TryDequeue(out data);
                    prepareData.Set();
                    total += data.Length;

                    if ((Length == -1) || (total < Length))
                    {
                        h.BlockUpdate(data, 0, data.Length);
                        CalculateProgress(total);
                    }
                    else
                    {
                        int bytesRead = data.Length;
                        bytesRead = bytesRead - (int)(total - Length);
                        h.BlockUpdate(data, 0, data.Length);
                        CalculateProgress(total);
                    }

                    if (Length == -1)
                    {
                        if (data.Length != BUFFER_SIZE)
                            break;
                    }
                    else if (Length == total)
                    {
                        break;
                    }
                    else if (data.Length != BUFFER_SIZE)
                    {
                        throw new EndOfStreamException();
                    }
                    bytesTotal = total;
                }
            });

            reader.Wait();
            hasher.Wait();

            return bytesTotal;
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
                    if (m_disposeEngine)
                    {
                        if (_macEngine != null)
                        {
                            _macEngine.Dispose();
                            _macEngine = null;
                        }
                    }
                    if (m_disposeStream)
                    {
                        if (m_inStream != null)
                        {
                            m_inStream.Dispose();
                            m_inStream = null;
                        }
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
