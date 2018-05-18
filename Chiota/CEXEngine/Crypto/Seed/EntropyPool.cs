#region Directives
using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Security.Principal;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
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
// Implementation Details:
// An implementation of a pseudo random generator.
// XSPRsg:  XorShift+random seed generator
// Written by John Underhill, June 1, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Seed
{
    /// <summary>
    /// EntropyPool: Provides a source of system entropy for pseudo random generators.
    /// <para>Uses various system state, timers, and counters, which are compressed into an entropy pool.</para>
    /// </summary> 
    /// 
    /// <example>
    /// <description>Extracting entropy from the pool:</description>
    /// <code>
    /// EntropyPool pool = new EntropyPool();
    /// byte[] rnd = pool.GetBytes(256);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Digest.Keccak512"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Generator.IDrbg"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Prng.IRandom"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Seed.ISeed"/>
    /// 
    /// <remarks>
    ///
    /// <para>The maximum single size of a request from the entropy pool (GetBytes()) is 1024 bytes. When the pool is exausted, the state is automatically refreshed, 
    /// this can be done manually by calling the Reset() method.</para> 
    /// 
    /// <para>There are 8 state pools and their corresponding post-processed entropy pool members. 
    /// Each entropy pool has a corresponding state pool, bytes are added to each of the state pools through a round robin per-byte queing method, 
    /// with a conditional (first byte ? even/odd) array reversal. 
    /// </para>
    /// 
    /// <para>The minimum state pool member size is 100 * the keccak 512 block size, (7200 bytes).
    /// If the state size is less than the minimum, the bytes are added with the system default random provider interface; CSPRsg. 
    /// A minimum of 2 * block size is added with the default provider.</para>
    /// 
    /// <para>Once the state sizes are obtained, the state is compressed into an entropy pool member (64 bytes) using Keccak 512.
    /// The entropy pool members are treated as columns, with each column emptying completely before moving up to the next queue member.</para>
    /// 
    /// <description>State Information:</description>
    /// <list type="table">
    ///     <listheader>
    ///         <term>Group</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description>Drive Statistics</description>
    ///         <description>Collects the AvailableFreeSpace, TotalSize, and VolumeLabel of each drive on the system</description>
    ///     </item>
    ///     <item>
    ///         <description>Machine Info</description>
    ///         <description>Uses the UserDomainName, MachineName, SystemPageSize, and CurrentDirectory properties from the system</description>
    ///     </item>
    ///     <item>
    ///         <description>Network Statistics</description>
    ///         <description>Collects the interface id, MAC address, IP address, BytesReceived, BytesSent, UnicastPacketsReceived, UnicastPacketsSent, 
    ///         NonUnicastPacketsReceived, NonUnicastPacketsSent, and IncomingPacketsDiscarded information from each available network interface.</description>
    ///     </item>
    ///     <item>
    ///         <description>Registry Info</description>
    ///         <description>>Adds all of the systems application Clsid's from the registry.</description>
    ///     </item>
    ///     <item>
    ///         <description>Time Stamps</description>
    ///         <description>Adds the DateTime.Now.Ticks, DateTime.Now.ToFileTimeUtc, and TickCount timer values.</description>
    ///     </item>
    ///     <item>
    ///         <description>User Info</description>
    ///         <description>Collects the hash values of the local users identity name, owner, and SID values, as well as the hashes for each group id the user belongs to.</description>
    ///     </item>
    ///     <item>
    ///         <description>Crypto Provider</description>
    ///         <description>A minimum of two digest input blocks (144 bytes) per pool member is taken from the local random provider; RNGCryptoServiceProvider.</description>
    ///     </item>
    ///     <item>
    ///         <description>Process Statistics</description>
    ///         <description>Collects statistics from all running processes for HandleCount, Id, NonpagedSystemMemorySize64, PagedMemorySize64, 
    ///         PeakPagedMemorySize64, PeakVirtualMemorySize64, PeakWorkingSet64, PrivateMemorySize64, VirtualMemorySize64, WorkingSet64. 
    ///         From each running thread, collects the CurrentPriority, Id, and StartAddress. The local process contributes each thread Handle, StartAddress, 
    ///         StartTime, TotalProcessorTime and UserProcessorTime statistics.</description>
    ///     </item>
    /// </list>
    /// </remarks>
    public sealed class EntropyPool
    {
        #region Constants
        // number of state and entropy pools
        private const int POOLCOUNT = 16;
        // initial state size
        private const int STATESIZE = 1024;
        // size of entropy queue member
        private const int POOLSIZE = 64;
        // compressor input size (keccak 512)
        private const int BLOCKSIZE = 72;
        // maximum number of bytes allowed per request
        private const int MAXPULL = 1024;
        // the min state member size, remainder is filled by CSPRsg
        private const int MINSTATE = BLOCKSIZE * 200;
        #endregion

        #region Struct
        private struct PoolItem
        {
            public int Length;
            public int Position;
            public byte[] State;

            public PoolItem(int BufferSize)
            {
                Length = BufferSize;
                Position = 0;
                State = new byte[0];
            }

            public byte[] Read(int Size)
            {
                byte[] data = new byte[Size];
                Array.Copy(State, Position, data, 0, Size);
                Position += Size;
                return data;
            }

            public void Reset()
            {
                Array.Clear(State, 0, State.Length);
                Array.Resize(ref State, 0);
                Length = 0;
                Position = 0;
            }

            public void Write(byte Element)
            {
                if (Position == State.Length)
                {
                    Length *= 2;
                    Array.Resize(ref State, Length);
                }
                State[Position] = Element;
                ++Position;
            }

            public void Write(byte[] Data)
            {
                if (Data.Length > State.Length - Position)
                {
                    State = ArrayUtils.Concat(State, Data);
                    Position += Data.Length;
                    Length = Position;
                }
                else
                {
                    Buffer.BlockCopy(Data, 0, State, Position, Data.Length);
                    Position += Data.Length;
                }
            }
        };
        #endregion

        #region Fields
        private bool m_isDestroyed = false;
        private PoolItem[] m_entropyQueue;
        private PoolItem[] m_statePool;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        public EntropyPool()
        {
            m_entropyQueue = new PoolItem[POOLCOUNT];
            m_statePool = new PoolItem[POOLCOUNT];

            for (int i = 0; i < POOLCOUNT; ++i)
                m_entropyQueue[i] = new PoolItem(POOLSIZE);
            for (int i = 0; i < POOLCOUNT; ++i)
                m_statePool[i] = new PoolItem(STATESIZE);

            Reset();
        }

        /// <summary>
        /// Class Finalizer
        /// </summary>
        ~EntropyPool()
        {
            Destroy();
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Clear and reset internal state
        /// </summary>
        public void Destroy()
        {
            if (!m_isDestroyed)
            {
                if (m_entropyQueue.Length != 0)
                {
                    for (int i = 0; i < m_entropyQueue.Length; ++i)
                        m_entropyQueue[i].Reset();
                }
                if (m_statePool.Length != 0)
                {
                    for (int i = 0; i < m_statePool.Length; ++i)
                        m_statePool[i].Reset();
                }
            }
        }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Output">Array to fill with random bytes</param>
        public void GetBytes(byte[] Output)
        {
            if (Output.Length > MAXPULL)
                throw new CryptoProcessingException("EntropyPool:GetBytes", string.Format("The maximum output size is [0] bytes!", MAXPULL), new ArgumentOutOfRangeException());

            int len = Output.Length;
            int offset = 0;
            int index = 0;

            while (len > 0)
            {
                if (index == POOLCOUNT)
                    index = 0;

                // fulfill request by rotating through queues, consuming each member
                if (m_entropyQueue[index].Position != m_entropyQueue[index].Length)
                {
                    int sze = m_entropyQueue[index].Length - m_entropyQueue[index].Position;
                    if (sze > len)
                        sze = len;

                    Buffer.BlockCopy(m_entropyQueue[index].Read(sze), 0, Output, offset, sze);
                    offset += sze;
                    len -= sze;
                    ++index;
                }
                else
                {
                    // check for empty queue
                    for (int i = 0; i < m_entropyQueue.Length; ++i)
                    {
                        if (m_entropyQueue[i].Position != m_entropyQueue[i].Length)
                        {
                            break;
                        }
                        else if (i == m_entropyQueue.Length - 1)
                        {
                            // need more state
                            Reset();
                            index = 0;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Fill an array with pseudo random bytes
        /// </summary>
        /// 
        /// <param name="Size">Size of requested byte array</param>
        /// 
        /// <returns>Random byte array</returns>
        public byte[] GetBytes(int Size)
        {
            byte[] data = new byte[Size];
            GetBytes(data);
            return data;
        }

        /// <summary>
        /// Resets the internal state
        /// </summary>
        public void Reset()
        {
            byte[] state = ArrayUtils.Concat(
                GetDriveStatistics(), 
                GetMachineInfo(),
                GetNetworkStatistics(), 
                GetProcessStatistics(),
                GetRegistryInfo(),
                GetTimeStamps(),
                GetUserInfo());

            // distribute bytes round robin across 8 pools
            Distribute(state);

            for (int i = 0; i < m_entropyQueue.Length; ++i)
            {
                int len = 0;
                // length diff from min input block
                if (m_statePool[i].Position < MINSTATE)
                    len = (MINSTATE - m_statePool[i].Position);
                else // block align + 2
                    len = (m_statePool[i].Position % BLOCKSIZE) + (2 * BLOCKSIZE);

                // add csp random fill
                byte[] rnd = new byte[len];
                using (CSPRsg gen = new CSPRsg())
                    gen.GetBytes(rnd);

                m_statePool[i].Write(rnd);

                // compress the state with keccak and add member to entropy queue
                m_entropyQueue[i].Write(Compress(m_statePool[i].State, m_statePool[i].Position));
                // reset queue position
                m_entropyQueue[i].Position = 0;
            }
        }
        #endregion

        #region Private Methods
        private byte[] Compress(byte[] State, int Length)
        {
            using (Keccak512 dgt = new Keccak512())
            {
                byte[] hash = new byte[dgt.DigestSize];
                dgt.BlockUpdate(State, 0, Length);
                dgt.DoFinal(hash, 0);

                return hash;
            }
        }

        private void Distribute(byte[] State)
        {
            int len = State.Length;
            int ctr = 0;
            int index = 0;

            while (true)
            {
                if (ctr != len)
                {
                    if (index == POOLCOUNT)
                        index = 0;

                    // add 1 byte
                    m_statePool[index].Write(State[ctr]);
                    ++index;
                    ++ctr;
                }
                else
                {
                    break;
                }
            }
        }

        private byte[] Filter(byte[] State)
        {
            // filter zero bytes and conditionally reverse array
            if (State.Length == 0)
                return new byte[0];

            int ctr = State.Length;
            int ind = -1;
            byte[] data = new byte[ctr];

            if (State[0] % 2 != 0)
            {
                int len = State.Length - 1;
                ctr = -1;

                do
                {
                    if (State[++ctr] != 0)
                        data[++ind] = State[ctr];
                }
                while (ctr != len);

                if (ind > 0)
                    ++ind;
            }
            else
            {
                // reverse
                do
                {
                    --ctr;
                    if (State[ctr] != 0)
                        data[++ind] = State[ctr];
                } 
                while (ctr != 0);

                if (ind > 0)
                    ++ind;
            }

            Array.Resize(ref data, ind);
            return data;
        }

        private byte[] GetDriveStatistics()
        {
            // drive details
            byte[] state = new byte[0];

            foreach (System.IO.DriveInfo di in System.IO.DriveInfo.GetDrives())
            {
                try
                {
                    state = ArrayUtils.Concat( 
                        state,
                        BitConverter.GetBytes(di.AvailableFreeSpace),
                        System.Text.Encoding.ASCII.GetBytes(di.VolumeLabel),
                        BitConverter.GetBytes(di.TotalSize)
                    );
                }
                catch { continue; }
            }

            if (state.Length > 0)
                return Filter(state);

            return new byte[0];
        }

        private byte[] GetMachineInfo()
        {
            // machine specific info
            string info = Environment.UserDomainName + Environment.MachineName + Environment.SystemPageSize + Environment.CurrentDirectory;
            byte[] state =  System.Text.Encoding.ASCII.GetBytes(info);

            return Filter(state);
        }

        private byte[] GetNetworkStatistics()
        {
            // network interface statistics
            if (!NetworkInterface.GetIsNetworkAvailable())
                return new byte[0];

            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
            byte[] state = new byte[0];

            foreach (NetworkInterface ni in interfaces)
            {
                if (ni.OperationalStatus == OperationalStatus.Up)
                {
                    try
                    {
                        IPv4InterfaceStatistics stats = ni.GetIPv4Statistics();

                        if (stats.BytesSent + stats.BytesReceived > 0)
                        {
                            state = ArrayUtils.Concat(
                                state,
                                System.Text.Encoding.ASCII.GetBytes(ni.Id),
                                ni.GetPhysicalAddress().GetAddressBytes(),
                                BitConverter.GetBytes(stats.BytesReceived),
                                BitConverter.GetBytes(stats.BytesSent),
                                BitConverter.GetBytes(stats.UnicastPacketsReceived),
                                BitConverter.GetBytes(stats.UnicastPacketsSent),
                                BitConverter.GetBytes(stats.NonUnicastPacketsReceived),
                                BitConverter.GetBytes(stats.NonUnicastPacketsSent),
                                BitConverter.GetBytes(stats.IncomingPacketsDiscarded)
                            );
                        }
                    }
                    catch { continue; }
                }
            }

            if (state.Length > 0)
                return Filter(state);

            return new byte[0];
        }

        private byte[] GetProcessStatistics()
        {
            // info from running processes and threads
            Process lprc = Process.GetCurrentProcess();
            Process[] processes = Process.GetProcesses();
            byte[] state = new byte[0];

            for (int i = 0; i < processes.Length; i++)
            {
                try
                {
                    state = ArrayUtils.Concat(
                        state,
                        BitConverter.GetBytes(processes[i].HandleCount),
                        BitConverter.GetBytes(processes[i].Id),
                        BitConverter.GetBytes(processes[i].NonpagedSystemMemorySize64),
                        BitConverter.GetBytes(processes[i].PagedMemorySize64),
                        BitConverter.GetBytes(processes[i].PeakPagedMemorySize64),
                        BitConverter.GetBytes(processes[i].PeakVirtualMemorySize64),
                        BitConverter.GetBytes(processes[i].PeakWorkingSet64),
                        BitConverter.GetBytes(processes[i].PrivateMemorySize64),
                        BitConverter.GetBytes(processes[i].VirtualMemorySize64),
                        BitConverter.GetBytes(processes[i].WorkingSet64)
                    );

                    for (int j = 0; j < processes[i].Threads.Count; j++)
                    {
                        if (processes[i].Id != lprc.Id)
                        {
                            state = ArrayUtils.Concat(
                                state,
                                BitConverter.GetBytes((long)processes[i].Threads[j].CurrentPriority),
                                BitConverter.GetBytes((long)processes[i].Threads[j].Id),
                                BitConverter.GetBytes((long)processes[i].Threads[j].StartAddress)
                            );
                        }
                        else
                        {
                            state = ArrayUtils.Concat(
                                state,
                                BitConverter.GetBytes((long)processes[i].Handle),
                                BitConverter.GetBytes((long)processes[i].Threads[j].CurrentPriority),
                                BitConverter.GetBytes((long)processes[i].Threads[j].Id),
                                BitConverter.GetBytes((long)processes[i].Threads[j].StartAddress),
                                BitConverter.GetBytes(processes[i].Threads[j].StartTime.Ticks),
                                BitConverter.GetBytes(processes[i].Threads[j].TotalProcessorTime.Ticks),
                                BitConverter.GetBytes(processes[i].Threads[j].UserProcessorTime.Ticks)
                            );
                        }
                    }
                }
                catch 
                { 
                    continue; 
                }
            }

            if (state.Length > 0)
                return Filter(state);

            return new byte[0];
        }

        private byte[] GetRegistryInfo()
        {
            // add clsid strings
            byte[] buffer =  new byte[0];
            const string subkey = "CLSID";

            RegistryUtils rtl = new RegistryUtils();
            if (!rtl.AccessTest(RegistryUtils.RootKey.HKEY_CLASSES_ROOT, subkey))
                return new byte[0];

            if (rtl.KeyExists(RegistryUtils.RootKey.HKEY_CLASSES_ROOT, subkey))
            {
                string[] data = (string[])rtl.EnumKeys(RegistryUtils.RootKey.HKEY_CLASSES_ROOT, subkey).ToArray(typeof(string));
                int len = 0;
                for (int i = 0; i < data.Length; ++i)
                    len += data[i].Length;

                buffer = new byte[len];
                for (int i = 0, j = 0; i < data.Length; ++i)
                {
                    Guid res = Guid.Empty;
                    if (Guid.TryParse((string)data[i], out res))
                    {
                        if (!res.Equals(Guid.Empty))
                        {
                            byte[] gb = res.ToByteArray();
                            Buffer.BlockCopy(gb, 0, buffer, j, gb.Length);
                            j += gb.Length;
                        }
                    }
                }
            }
            
            return Filter(buffer);
        }

        private byte[] GetTimeStamps()
        {
            // various timers
            byte[] state = ArrayUtils.Concat(
                BitConverter.GetBytes(DateTime.Now.Ticks),
                BitConverter.GetBytes(DateTime.Now.ToFileTimeUtc()),
                BitConverter.GetBytes(Environment.TickCount)
            );

            return Filter(state);
        }

        private byte[] GetUserInfo()
        {
            // user credential hashes
            try
            {
                WindowsIdentity id = WindowsIdentity.GetCurrent();

                byte[] state = ArrayUtils.Concat(
                    BitConverter.GetBytes(id.Name.GetHashCode()),
                    BitConverter.GetBytes(id.Owner.GetHashCode()),
                    BitConverter.GetBytes(id.User.GetHashCode())
                );

                foreach (IdentityReference ir in id.Groups)
                {
                    state = ArrayUtils.Concat(
                        state,
                        BitConverter.GetBytes(ir.Value.GetHashCode())
                    );
                }
                return Filter(state);
            }
            catch
            {
                return new byte[0];
            }
        }
        #endregion
    }
}
