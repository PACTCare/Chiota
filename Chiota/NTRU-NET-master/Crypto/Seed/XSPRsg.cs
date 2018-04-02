#region Directives
using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using VTDev.Libraries.CEXEngine.Exceptions;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// The MIT License (MIT)
// 
// Copyright (c) 2015 John Underhill
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
// Implementation Details:
// An implementation of a pseudo random generator.
// XSPRsg:  XorShift+random seed generator
// Written by John Underhill, June 1, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Seed
{
    /// <summary>
    /// Generates seed material for a CSPrng using various processed system counters passed through an XorShift+ generator.
    /// <para>An original construct (experimental) meant to provide an alternative to the RNGCryptoServiceProvider as a source of pseudo random seeding material.
    /// This class is suitable for generating seeds for a Prng or Drbg implementation.</para>
    /// </summary>
    /// 
    /// 
    /// <example>
    /// <description>Example of getting a seed value:</description>
    /// <code>
    /// byte[] seed;
    /// using (XSPRsg rnd = new XSPRsg())
    ///     seed = rnd.GetSeed(48);
    /// </code>
    /// </example>
    /// 
    /// <revisionHistory>
    /// <revision date="2015/06/09" version="1.4.0.0">Initial release</revision>
    /// <revision date="2015/07/01" version="1.4.0.0">Added library exceptions</revision>
    /// </revisionHistory>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng">VTDev.Libraries.CEXEngine.Crypto Prng Classes</seealso>
    /// 
    /// <remarks>
    /// <description><h4>Implementation Notes:</h4></description>
    /// <para>The seed generator uses system counters and state information, that are pre-processed via modular arithmetic, 
    /// converted to a byte array, and then processed with an XorShift+ random generator.
    /// The maximum allocation size is 1024 bytes.</para>
    /// 
    /// <description>XSPGenerator uses the following state values as initial entropy sources:</description>
    /// <list type="bullet">
    /// <item><description>Network: Combined interface values for the BytesSent, UnicastPacketsSent, NonUnicastPacketsSent, BytesReceived, UnicastPacketsReceived and NonUnicastPacketsReceived values.</description></item>
    /// <item><description>Current Process: Handle, StartTime ticks, PeakWorkingSet64, NonpagedSystemMemorySize64, PagedSystemMemorySize64, HandleCount, and Id.</description></item>
    /// <item><description>Combined running processes and threads: WorkingSet64, VirtualMemorySize64, StartAddress, Id, and CurrentPriority.</description></item>
    /// <item><description>Environment: Ticks since startup, the Time in Ticks.</description></item>
    /// <item><description>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class XSPRsg : ISeed
    {
        #region Constants
        private const string ALG_NAME = "XSPRsg";
        #endregion

        #region Fields
        private bool _isDisposed = false;
        private byte[] _stateSeed;
        private int _stateOffset = 0;
        private readonly int MAX_ALLOC = 1024;
        #endregion

        #region Properties
        /// <summary>
        /// Algorithm name
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
        public XSPRsg()
        {
            Initialize();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Re-initializes the generator with new state
        /// </summary>
        public void Initialize()
        {
            _stateSeed = XorShift3(ArrayUtils.Concat(NetStats(), ProcessStats(), ThreadStats(), TimeStats()), MAX_ALLOC);
            _stateOffset = 0;
        }

        /// <summary>
        /// Get a pseudo random seed byte array
        /// </summary>
        /// 
        /// <param name="Size">The size of the seed returned; up to a maximum of 1024 bytes</param>
        /// 
        /// <returns>A pseudo random seed</returns>
        /// 
        /// <exception cref="CryptoRandomException">Thrown if the requested size exceeds maximum allowable allocation (1024 bytes)</exception>
        public byte[] GetSeed(int Size)
        {
            if (Size > MAX_ALLOC)
                throw new CryptoRandomException("XSPRsg:GetSeed", String.Format("Size requested exceeds maximum seed allocation size of {0} bytes!", MAX_ALLOC), new ArgumentException());

            byte[] data = new byte[Size];

            if (Size + _stateOffset > MAX_ALLOC)
            {
                int len = MAX_ALLOC - _stateOffset;
                Buffer.BlockCopy(_stateSeed, _stateOffset, data, 0, len);
                Initialize();
                int diff = Size - len;
                Buffer.BlockCopy(_stateSeed, _stateOffset, data, len, diff);
                _stateOffset += diff;
            }
            else
            {
                Buffer.BlockCopy(_stateSeed, _stateOffset, data, 0, data.Length);
                _stateOffset += data.Length;
            }

            return data;
        }
        #endregion

        #region Private Methods
        private static byte[] NetStats()
        {
            if (!NetworkInterface.GetIsNetworkAvailable())
                return new byte[0];

            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
            long[] state = new long[2];

            foreach (NetworkInterface ni in interfaces)
            {
                if (ni.OperationalStatus == OperationalStatus.Up)
                {
                    try
                    {
                        IPv4InterfaceStatistics stats = ni.GetIPv4Statistics();
                        if (stats.BytesSent + stats.BytesReceived > 0)
                        {
                            state[0] += (RotateLeft(stats.BytesSent, 24) ^ stats.UnicastPacketsReceived) + stats.UnicastPacketsSent;
                            state[1] += (RotateRight(ni.GetIPv4Statistics().BytesReceived, 31) ^ stats.NonUnicastPacketsReceived) + stats.NonUnicastPacketsSent;
                        }
                    }
                    catch { continue; }
                }
            }

            if (state[0] == 0 || state[1] == 0)
                return new byte[0];

            byte[] data = new byte[state.Length * 8];
            Buffer.BlockCopy(state, 0, data, 0, data.Length);

            return data;
        }

        private static byte[] ProcessStats()
        {
            long[] state = new long[3];

            try
            {
                Process localPrc = Process.GetCurrentProcess();

                state[0] = RotateRight(localPrc.StartTime.Ticks, 22) ^ localPrc.PeakWorkingSet64;
                state[1] = RotateLeft(localPrc.NonpagedSystemMemorySize64, 34) ^ localPrc.PagedSystemMemorySize64;
                state[2] = (long)localPrc.Handle * localPrc.HandleCount * RotateLeft(localPrc.Id, 25) ^ RotateRight(localPrc.PeakWorkingSet64, 4);

                byte[] data = new byte[state.Length * 8];
                Buffer.BlockCopy(state, 0, data, 0, data.Length);
                return data;
            }
            catch
            {
                return new byte[0];
            }

        }

        private static Int64 RotateLeft(Int64 X, Int32 Bits)
        {
            return (X << Bits) | ((Int64)((UInt64)X >> -Bits));
        }

        private static Int64 RotateRight(Int64 X, Int32 Bits)
        {
            return ((Int64)((UInt64)X >> Bits) | (X << (64 - Bits)));
        }

        private static byte[] ThreadStats()
        {
            Process[] processes = Process.GetProcesses();
            long[] state = new long[processes.Length];
            int bits = 48;

            for (int i = 0; i < processes.Length; i++)
            {
                try
                {
                    state[i] = processes[i].WorkingSet64 * RotateRight(processes[i].VirtualMemorySize64, 13);

                    for (int j = 0; j < processes[i].Threads.Count; j++)
                    {
                        if (bits - j < 1)
                            bits = 48;
                        state[i] += RotateLeft((long)processes[i].Threads[j].StartAddress, bits - j) ^ processes[i].Threads[j].Id * processes[i].Threads[j].CurrentPriority;
                        bits--;
                    }
                }
                catch { continue; }
            }

            byte[] data = new byte[state.Length * 8];
            Buffer.BlockCopy(state, 0, data, 0, data.Length);

            return data;
        }

        private static byte[] TimeStats()
        {
            long[] state = new long[2];

            state[0] = RotateLeft(TimeSpan.FromMilliseconds(System.Environment.TickCount).Ticks, 33) ^ RotateRight(~DateTime.Now.Ticks, 1);
            state[1] = RotateLeft(DateTime.Now.Ticks, 31) ^ RotateRight(~TimeSpan.FromMilliseconds(System.Environment.TickCount).Ticks, 3);

            byte[] data = new byte[state.Length * 8];
            Buffer.BlockCopy(state, 0, data, 0, data.Length);

            return data;
        }

        private static byte[] XorShift3(byte[] Seed, int Size)
        {
            int offset = 0;
            int stateLen = Seed.Length / 8;
            ulong[] X = new ulong[stateLen];
            ulong[] S = new ulong[stateLen];
            byte[] buffer = new byte[Size];

            Buffer.BlockCopy(Seed, 0, S, 0, stateLen * 8);

            while (offset < Size)
            {
                for (int i = 0; i < stateLen - 1; i += 2)
                {
                    if (offset >= buffer.Length)
                        break;

                    X[i] = S[i];
                    X[i + 1] = S[i + 1];
                    S[i] = X[i + 1];
                    X[i] ^= X[i] << 23;                     // a
                    X[i] ^= X[i] >> 17;                     // b
                    X[i] ^= X[i + 1] ^ (X[i + 1] >> 26);    // c
                    S[1] = X[i];
                    X[i] += X[i + 1];                       // +

                    buffer[offset++] = (byte)(X[i] & 0xFF);
                    buffer[offset++] = (byte)((X[i] >> 8) & 0xFF);
                    buffer[offset++] = (byte)((X[i] >> 16) & 0xFF);
                    buffer[offset++] = (byte)((X[i] >> 24) & 0xFF);
                }
            }

            return buffer;
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
            if (!_isDisposed && Disposing)
            {
                try
                {
                    if (_stateSeed != null)
                    {
                        Array.Clear(_stateSeed, 0, _stateSeed.Length);
                        _stateSeed = null;
                    }
                    _stateOffset = 0;
                }
                catch { }

                _isDisposed = true;
            }
        }
        #endregion
    }
}
