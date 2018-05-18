#region Directives
using System;
using System.Diagnostics;
using System.Threading;
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
// An implementation of a delayed Wait Queue.
// Written by John Underhill, December 3, 2014
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Queue
{
    /// <summary>
    /// WaitQueue: An implementation of a delayed Wait Queue.
    /// </summary>
    public class WaitQueue : IDisposable
    {
        #region Structs
        /// <summary>
        /// Contains high and low processing times
        /// </summary>
        public struct ProcessingTimes
        {
            /// <summary>
            /// Low order time
            /// </summary>
            public double Low;
            /// <summary>
            /// Maximum time
            /// </summary>
            public double High;
        }
        #endregion

        #region Fields
        private int m_Count = 0;
        private double m_Delay = 0.0;
        private double m_Elapsed = 0;
        private bool m_isDisposed = false;
        private byte[] m_Queue;
        private int m_Size = 0;
        private byte[] m_Temp;
        private Stopwatch m_stpWatch;
        private EventWaitHandle m_evtWait;
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize the class
        /// </summary>
        /// 
        /// <param name="Size">Queue size, should be a multible of cipher block size, e.g. 16 block = 1440 queue</param>
        /// <param name="CTime">Constant time value for each queue processed</param>
        public WaitQueue(int Size, double CTime)
        {
            m_Size = Size;
            m_Delay = CTime;
            m_Queue = new byte[Size];
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~ WaitQueue()
        {
            Dispose(false);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Empty the queue
        /// </summary>
        /// 
        /// <returns>Queued values</returns>
        public byte[] DeQueue()
        {
            m_Count = 0;
            return m_Queue;
        }

        /// <summary>
        /// Process a partial queue size, then trigger wait
        /// </summary>
        /// 
        /// <param name="Data">Queue input</param>
        public void Final(byte[] Data)
        {
            Array.Resize<byte>(ref m_Queue, m_Count + Data.Length);
            Buffer.BlockCopy(Data, Data.Length, m_Queue, m_Count, Data.Length);
            m_Count = m_Size;
            Wait();

            m_stpWatch.Stop();
            m_stpWatch.Reset();
            m_Count = 0;
        }

        /// <summary>
        /// Initialize the queue
        /// </summary>
        public virtual void Initialize()
        {
            m_stpWatch = new Stopwatch();
            m_evtWait = new AutoResetEvent(true);
            m_stpWatch.Start();
        }

        /// <summary>
        /// Add data to the queue
        /// </summary>
        /// 
        /// <param name="Data">Queue input</param>
        /// 
        /// <returns>Returns true if queue is full</returns>
        public bool Queue(byte[] Data)
        {
            int len = Data.Length;

            if (m_Temp != null)
            {
                Buffer.BlockCopy(m_Temp, 0, m_Queue, 0, m_Temp.Length);
                m_Count += m_Temp.Length;
                m_Temp = null;
                Wait();
            }

            if (len + m_Count > m_Size)
            {
                len = m_Size - m_Count;
                int tlen = Data.Length - len;
                m_Temp = new byte[tlen];
                Buffer.BlockCopy(Data, len, m_Temp, 0, tlen);
            }

            Buffer.BlockCopy(Data, 0, m_Queue, m_Count, len);
            m_Count += len;

            return Wait();
        }
        #endregion

        #region Private Methods
        private double GetElapsed()
        {
            double tms = m_stpWatch.Elapsed.TotalMilliseconds;
            double cms = tms - m_Elapsed;
            m_Elapsed = tms;

            return cms;
        }

        private bool Wait()
        {
            if (m_Count >= m_Size)
            {
                int cms = (int)GetElapsed();
                if (cms > 0)
                    m_evtWait.WaitOne(cms);
                m_Count = 0;

                return true;
            }

            return false;
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class, and dependant resources
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
                    if (m_Queue != null)
                    {
                        Array.Clear(m_Queue, 0, m_Queue.Length);
                        m_Queue = null;
                    }
                    if (m_Temp != null)
                    {
                        Array.Clear(m_Temp, 0, m_Temp.Length);
                        m_Temp = null;
                    }
                    if (m_stpWatch != null)
                    {
                        if (m_stpWatch.IsRunning)
                            m_stpWatch.Stop();
                        m_stpWatch = null;
                    }
                    if (m_evtWait != null)
                    {
                        m_evtWait.Dispose();
                        m_evtWait = null;
                    }
                }
                finally
                {
                    m_isDisposed = true;
                }
            }
        }
        #endregion

        /// <summary>
        /// Test WaitQueue to calculate time threshhold measurements.
        /// </summary>
        public class SampleQueue : WaitQueue
        {
            #region Public Methods
            /// <summary>
            /// Timing samples, maximum and minimum times
            /// </summary>
            public ProcessingTimes Samples;
            #endregion

            #region Public Methods
            /// <summary>
            /// Initialize the class
            /// </summary>
            /// 
            /// <param name="Size">Size of queue</param>
            /// <param name="CTime">Not used</param>
            public SampleQueue(int Size, double CTime)
                : base(Size, CTime)
            {
                m_Size = Size;
                m_Delay = CTime;
                m_Queue = new byte[Size];
            }
            #endregion

            #region Public Methods
            /// <summary>
            /// Initialize the queue
            /// </summary>
            public override void Initialize()
            {
                base.Initialize();
                Samples = new ProcessingTimes();
            }

            /// <summary>
            /// Add data to the queue
            /// </summary>
            /// 
            /// <param name="Data">Queue input</param>
            public void SQueue(byte[] Data)
            {
                int len = Data.Length;

                if (m_Temp != null)
                {
                    Buffer.BlockCopy(m_Temp, 0, m_Queue, 0, m_Temp.Length);
                    m_Count += m_Temp.Length;
                    m_Temp = null;
                    if (m_Count >= m_Size)
                        SampleTime();
                }

                if (len + m_Count > m_Size)
                {
                    len = m_Size - m_Count;
                    int tlen = Data.Length - len;
                    m_Temp = new byte[tlen];
                    Buffer.BlockCopy(Data, len, m_Temp, 0, tlen);
                }

                Buffer.BlockCopy(Data, 0, m_Queue, m_Count, len);
                m_Count += len;

                SampleTime();
            }
            #endregion

            #region Private Methods
            private void SampleTime()
            {
                if (m_Count >= m_Size)
                {
                    double ms = GetElapsed();

                    if (Samples.Low == 0 || Samples.Low > ms)
                        Samples.Low = ms;
                    if (Samples.High == 0 || Samples.High < ms)
                        Samples.High = ms;

                    m_Count = 0;
                }
            }
            #endregion
        }
    }
}
