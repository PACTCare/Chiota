#region Directives
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Networking;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// The GPL Version 3 License
// 
// Copyright (C) 2015 John Underhill
// This file is part of the CEX Cryptographic library.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
// 
// Written by John Underhill, August 21, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Support
{
    internal class DtmFileTransfer : IDisposable
    {
        #region Constants
        private const int MAXRCVBUFFER = 1024 * 1000 * 10;
        private const int MAXSNDATTEMPT = 4;
        private const int WAITMULT = 20;
        #endregion

        #region Fields
        private ManualResetEvent _evtSendWait;              // transmission delay event
        private int _rcvSequence = 0;                       // the file transfer receive sequence register
        private int _sndSequence = 0;                       // the file transfer send sequence register
        private TcpSocket _clientSocket;                    // the client/server file socket instance
        private ICipherMode _fileSymProcessor;              // the file transfer symmetric cipher
        private PacketBuffer _rcvBuffer;                    // the receive processing packet buffer
        private PacketBuffer _sndBuffer;                    // the send processing packet buffer
        private string _filePath = "";                      // full file path
        private string _tempPath = "";                      // temp file path
        private bool _isConnected = false;                  // connected flag
        private bool m_isDisposed = false;                   // dispose flag
        private long _bytesSent = 0;                        // total bytes sent
        private long _fileId = 0;                           // unique file id
        private int m_bufferSize = 0;                        // each buffers size
        private int _bufferCount = 0;                       // the number of buffer segments
        private long _seqCounter = 0;                       // tracks high sequence
        private object _sndLock = new object();             // locks the send transmission queue
        private object _rcvLock = new object();             // locks the receive queue
        #endregion

        #region Delegates/Events
        /// <summary>
        /// The Packet Received delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmDataReceivedArgs"/> class</param>
        public delegate void DataReceivedDelegate(object owner, DtmDataReceivedArgs args);
        /// <summary>
        /// The Data Received event; fires each time data has been received through the post-exchange encrypted channel
        /// </summary>
        public event DataReceivedDelegate DataReceived;

        /// <summary>
        /// The File Transferred delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmFileRequestArgs"/> class</param>
        public delegate void FileTransferredDelegate(object owner, DtmPacketArgs args);
        /// <summary>
        /// The File Transferred event; fires when the file transfer operation has completed
        /// </summary>
        public event FileTransferredDelegate FileTransferred;

        /// <summary>
        /// The Packet Received delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmPacketArgs"/> class</param>
        public delegate void PacketReceivedDelegate(object owner, DtmPacketArgs args);
        /// <summary>
        /// The Packet Received event; fires each time a valid packet has been received
        /// </summary>
        public event PacketReceivedDelegate PacketReceived;

        /// <summary>
        /// The Packet Sent delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmPacketArgs"/> class</param>
        public delegate void PacketSentDelegate(object owner, DtmPacketArgs args);
        /// <summary>
        /// The Packet Sent event; fires each time a valid packet has been sent
        /// </summary>
        public event PacketReceivedDelegate PacketSent;

        /// <summary>
        /// Progress indicator delegate
        /// </summary>
        /// 
        /// <param name="sender">Event owner object</param>
        /// <param name="e">Progress event arguments containing percentage and bytes processed as the UserState param</param>
        public delegate void ProgressDelegate(object sender, System.ComponentModel.ProgressChangedEventArgs e);

        /// <summary>
        /// Progress Percent Event; returns bytes processed as an integer percentage
        /// </summary>
        public event ProgressDelegate ProgressPercent;

        /// <summary>
        /// The Session Error delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmErrorArgs"/> class</param>
        public delegate void SessionErrorDelegate(object owner, DtmErrorArgs args);
        /// <summary>
        /// The Session Error event; fires when an error has occured
        /// </summary>
        public event SessionErrorDelegate SessionError;

        #endregion

        #region Properties
        public bool IsConnected
        {
            get { return _isConnected; }
        }

        public TcpSocket Socket
        {
            get { return _clientSocket; }
        }
        #endregion

        #region Constructor
        public DtmFileTransfer(ICipherMode Cipher, long FileId = 0, int BufferCount = 1024, int BufferSize = 262144)
        {
            _fileSymProcessor = Cipher;
            _fileId = FileId;
            _rcvBuffer = new PacketBuffer(BufferCount);
            _sndBuffer = new PacketBuffer(BufferCount);
            m_bufferSize = BufferSize;
            _bufferCount = BufferCount;
        }

        private DtmFileTransfer()
        {
        }

        ~DtmFileTransfer()
        {
            Dispose(false);
        }
        #endregion

        #region Receive
        public void StartReceive(IPAddress Address, int Port, string FilePath)
        {
            // store destination path
            _filePath = FilePath;
            // initialize the file socket
            _clientSocket = new TcpSocket();
            // use the FileDataReceived callback
            _clientSocket.DataReceived += new TcpSocket.DataReceivedDelegate(OnDataReceived);
            _clientSocket.Connected += new TcpSocket.ConnectedDelegate(OnConnected);
            _clientSocket.DisConnected += new TcpSocket.DisConnectedDelegate(OnDisConnected);
            _clientSocket.Connect(Address, Port);

            if (!_clientSocket.IsConnected)
            {
                // connect attempt failed
                throw new CryptoSocketException("DtmFileTransfer:StartReceive", "Could not connect to the remote host!", new SocketException((int)SocketError.ConnectionAborted));
            }
            else
            {
                // create the temp file  note: is WriteThrough more secure here?
                _tempPath = Path.Combine(Path.GetDirectoryName(_filePath), Path.GetFileNameWithoutExtension(Path.GetRandomFileName()) + ".tmp");
                using (new FileStream(_tempPath, FileMode.Create, FileAccess.Write, FileShare.Read)) { }
                // set to hidden to avoid cross process errors
                File.SetAttributes(_tempPath, File.GetAttributes(_tempPath) | FileAttributes.Hidden);
                _clientSocket.ReceiveBufferSize = m_bufferSize;
                _clientSocket.SendBufferSize = m_bufferSize;
                // start receiving
                _clientSocket.ReceiveAsync();
                _clientSocket.ReceiveTimeout = -1;
                // connection established
                _isConnected = true;
            }
        }

        private void Receive(Stream PacketStream)
        {
            // get the packet header
            DtmPacketStruct prcPacket = new DtmPacketStruct(PacketStream);
            // read the packet
            byte[] enc = new byte[prcPacket.PayloadLength];
            // get the encrypted data
            PacketStream.Read(enc, 0, enc.Length);
            // decrypt it using file crypto processor
            byte[] dec = SymmetricTransform(_fileSymProcessor, enc);
            // get file info header
            DtmFileInfoSruct pktFi = new DtmFileInfoSruct(dec);
            // store file name and size
            string fileName = pktFi.FileName;
            long fileSize = pktFi.FileSize;
            long streamLen = 0;

            try
            {
                using (FileStream outStream = new FileStream(_tempPath, FileMode.Append, FileAccess.Write, FileShare.Read))
                {
                    // calculate offsets
                    int hdrSize = pktFi.GetHeaderSize();
                    int len = dec.Length - hdrSize;
                    // write to file
                    outStream.Write(ArrayUtils.GetRange(dec, hdrSize, len), 0, len);
                    // store length
                    streamLen = outStream.Length;

                    // progress
                    if (ProgressPercent != null)
                    {
                        double progress = 100.0 * (double)pktFi.OptionsFlag / fileSize;
                        ProgressPercent(this, new System.ComponentModel.ProgressChangedEventArgs((int)progress, (object)fileSize));
                    }
                }

                // transfer completed
                if (streamLen == fileSize)
                {
                    // reset attributes
                    File.SetAttributes(_tempPath, File.GetAttributes(_tempPath) & ~FileAttributes.Hidden);
                    // rename the file
                    File.Move(_tempPath, VTDev.Libraries.CEXEngine.Tools.FileTools.GetUniqueName(_filePath));

                    // notify app
                    if (FileTransferred != null)
                        FileTransferred(this, new DtmPacketArgs((short)DtmTransferFlags.Received, prcPacket.OptionFlag));

                    // flush and close
                    ReceiveClose();
                }
            }
            catch (Exception ex)
            {
                throw new CryptoFileTransferException("DtmFileTransfer:Receive", "The file transfer did not complete!", ex);
            }
        }

        private void ReceiveClose()
        {
            try
            {
                // close the socket
                if (_clientSocket != null)
                {
                    // flush the data
                    if (_clientSocket.IsConnected)
                        _clientSocket.TcpStream.Close(5000);
                }
            }
            catch (SocketException)
            {
            }
            catch (Exception ex)
            {
                throw new CryptoSocketException("DtmFileTransfer:ReceiveClose", "The socket stream close operation threw an error!", ex);
            }
        }
        #endregion
        
        #region Send
        public void StartSend(IPAddress Address, int Port, string FilePath)
        {
            // store the path
            _filePath = FilePath;
            // start listening on the port 
            _clientSocket = new TcpSocket();
            // use the DataReceived callback
            _clientSocket.DataReceived += new TcpSocket.DataReceivedDelegate(OnDataReceived);
            _clientSocket.Connected += new TcpSocket.ConnectedDelegate(OnConnected);
            // non blocking listen
            _clientSocket.ListenAsync(Address, Port);

            if (!_clientSocket.IsConnected)
            {
                // connect attempt failed
                throw new CryptoSocketException("DtmFileTransfer:BeginSendFile", "Could not connect to the remote host!", new SocketException((int)SocketError.ConnectionAborted));
            }
            else
            {
                // connection established
                _clientSocket.ReceiveBufferSize = m_bufferSize;
                _clientSocket.SendBufferSize = m_bufferSize;
                _isConnected = true;
            }
        }

        public void SendFile()
        {
            int bytesRead = 0;
            long len = new FileInfo(_filePath).Length;
            DtmFileInfoSruct flHdr = new DtmFileInfoSruct(_filePath, len, 0);
            int ckSize = _clientSocket.SendBufferSize - (flHdr.GetHeaderSize() + DtmPacketStruct.GetHeaderSize());
            byte[] inputBuffer = new byte[ckSize];

            try
            {
                using (FileStream inStream = new FileStream(_filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    // loop through file
                    while ((bytesRead = inStream.Read(inputBuffer, 0, ckSize)) > 0)
                    {
                        // wrap in a file info; option flag is used for payload length
                        flHdr.OptionsFlag = bytesRead;
                        byte[] hdrArr = flHdr.ToBytes();

                        // add data
                        if (bytesRead == ckSize)
                            hdrArr = ArrayUtils.Concat(hdrArr, inputBuffer);
                        else
                            hdrArr = ArrayUtils.Concat(hdrArr, ArrayUtils.GetRange(inputBuffer, 0, bytesRead));

                        // encrypt the header and data
                        byte[] enc = SymmetricTransform(_fileSymProcessor, hdrArr);
                        // send to the remote host
                        Transmit(DtmPacketFlags.Transfer, (short)DtmTransferFlags.DataChunk, _fileId, new MemoryStream(enc));
                        // increment counter
                        _bytesSent += bytesRead;

                        // progress
                        if (ProgressPercent != null)
                        {
                            double progress = 100.0 * (double)_bytesSent / inStream.Length;
                            ProgressPercent(this, new System.ComponentModel.ProgressChangedEventArgs((int)progress, (object)inStream.Length));
                        }
                    }
                }
                // notify app
                if (FileTransferred != null)
                    FileTransferred(this, new DtmPacketArgs((short)DtmTransferFlags.Sent, _fileId));
            }
            catch (Exception ex)
            {
                throw new CryptoFileTransferException("DtmFileTransfer:SendFile", "The file transfer did not complete!", ex);
            }
            finally
            {
                // flush
                SendFlush();
            }
        }

        private void SendFlush()
        {
            try
            {
                // close the stream
                if (_clientSocket != null)
                {
                    if (_clientSocket.IsConnected)
                        _clientSocket.TcpStream.Flush();
                }
            }
            catch (SocketException)
            {
            }
            catch (Exception ex)
            {
                throw new CryptoSocketException("DtmFileTransfer:SendFlush", "The socket stream flush operation threw an error!", ex);
            }
        }
        #endregion

        #region Helpers
        private void Process(MemoryStream PacketStream)
        {
            // increment rcv sequence
            _rcvSequence++;
            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            PacketStream.Seek(0, SeekOrigin.Begin);

            switch (pktHdr.PacketType)
            {
                // file transfer
                case DtmPacketFlags.Transfer:
                    {
                        switch ((DtmTransferFlags)pktHdr.PacketFlag)
                        {
                            case DtmTransferFlags.DataChunk:
                                {
                                    try
                                    {
                                        lock (_rcvLock)
                                        {
                                            // received file data
                                            Receive(PacketStream);
                                        }
                                    }
                                    catch (Exception)
                                    {
                                        // packet corrupted, request a retransmission and exit
                                        Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Resend, pktHdr.Sequence);
                                        return;
                                    }

                                    // echo the packet to remove it from remote buffer
                                    Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Echo, pktHdr.Sequence);
                                    break;
                                }
                        }
                        break;
                    }
                // service messages
                case DtmPacketFlags.Service:
                    {
                        switch ((DtmServiceFlags)pktHdr.PacketFlag)
                        {
                            case DtmServiceFlags.Resend:
                                {
                                    // resend the packet
                                    Resend(pktHdr);
                                    break;
                                }
                            case DtmServiceFlags.Echo:
                                {
                                    // remove from local buffer
                                    if (_sndBuffer.Exists(pktHdr.OptionFlag))
                                        _sndBuffer.Destroy(pktHdr.OptionFlag);

                                    break;
                                }
                        }
                        break;
                    }
                default:
                    {
                        throw new CryptoKeyExchangeException("DtmFileTransfer:Process", "The packet type is unknown!", new InvalidDataException());
                    }
            }

            // notify parent
            if (PacketReceived != null)
                PacketReceived(this, new DtmPacketArgs(pktHdr.PacketFlag, pktHdr.PayloadLength));
        }
        
        private void ProcessAndPush(PacketBuffer Buffer, MemoryStream PacketStream)
        {
            int hdrLen = DtmPacketStruct.GetHeaderSize();
            int pktLen = 0;
            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            PacketStream.Seek(0, SeekOrigin.Begin);

            // track high sequence number
            if (pktHdr.Sequence > _seqCounter)
                _seqCounter = pktHdr.Sequence;

            // out of sync, possible packet loss
            if (_seqCounter - _rcvSequence > _bufferCount / 4)
            {
                // request a retransmission
                Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Resend, _rcvSequence + 1);
            }

            // packet aligned
            if (pktHdr.PayloadLength + hdrLen == PacketStream.Length)
            {
                // resend was already processed
                if (pktHdr.Sequence < _rcvSequence)
                    return;

                // push onto buffer
                Buffer.Push(pktHdr.Sequence, PacketStream);
            }
            // more than one packet
            else if (pktHdr.PayloadLength + hdrLen < PacketStream.Length)
            {
                byte[] buffer;
                long pos = 0;

                do
                {
                    // get packet position and size
                    pos = PacketStream.Position;

                    if (PacketStream.Length - pos < DtmPacketStruct.GetHeaderSize())
                    {
                        // next packet corrupted, request a retransmission and exit
                        Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Resend, Buffer.GetHighKey() + 1);
                        return;
                    }

                    pktHdr = new DtmPacketStruct(PacketStream);
                    pktLen = (int)(hdrLen + pktHdr.PayloadLength);

                    if (pktLen > MAXRCVBUFFER || pktLen < 0 || PacketStream.Length - pos < pktLen)
                    {
                        // packet corrupted, request a retransmission and exit
                        Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Resend, Buffer.GetHighKey() + 1);
                        return;
                    }
                    else
                    {
                        // create the buffer
                        buffer = new byte[pktLen];
                        PacketStream.Seek(pos, SeekOrigin.Begin);
                        PacketStream.Read(buffer, 0, (int)pktLen);
                        // push onto buffer
                        Buffer.Push(pktHdr.Sequence, new MemoryStream(buffer));
                    }

                } while (PacketStream.Position < PacketStream.Length);
            }
            // malformed packet, send retransmit request
            else if (pktHdr.PayloadLength > MAXRCVBUFFER || pktHdr.PayloadLength < 0 || pktHdr.PayloadLength + hdrLen > PacketStream.Length)
            {
                // packet corrupted, request a retransmission of last in queue + 1
                Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Resend, Buffer.GetHighKey() + 1);
            }
        }

        private void Resend(DtmPacketStruct PacketHeader)
        {
            if (_sndBuffer.Exists(PacketHeader.Sequence))
            {
                MemoryStream pktStm = _sndBuffer.Peek(PacketHeader.Sequence);
                if (pktStm != null)
                {
                    if (pktStm.Length > 0)
                        pktStm.WriteTo(_clientSocket.TcpStream);
                }
            }
        }

        private byte[] SymmetricTransform(ICipherMode Cipher, byte[] Data)
        {
            byte[] ptext = new byte[Data.Length];
            Cipher.Transform(Data, ptext);

            return ptext;
        }

        /// <summary>
        /// Sends a packet with increasing wait times. 
        /// <para>After 4 attempts fires a SessionError.</para>
        /// </summary>
        /// 
        /// <param name="PacketStream">The packet to send</param>
        private void Throttle(MemoryStream PacketStream)
        {
            int maxwait = 10;

            for (int i = 0; i < 4; i++)
            {
                try
                {
                    Wait(maxwait);
                    _clientSocket.SendAsync(PacketStream);

                    break;
                }
                catch (CryptoSocketException ce)
                {
                    SocketException se = ce.InnerException as SocketException;

                    if (se.SocketErrorCode == SocketError.WouldBlock ||
                        se.SocketErrorCode == SocketError.IOPending ||
                        se.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                    {
                        // buffer is full
                        maxwait *= 2;
                    }
                    else
                    {
                        // possible connection dropped, alert app
                        if (SessionError != null)
                        {
                            DtmErrorArgs args = new DtmErrorArgs(ce, DtmErrorSeverityFlags.Connection);
                            SessionError(this, args);
                        }
                    }
                }
            }

            // all attempts have failed
            if (maxwait > 160)
            {
                // possible connection dropped, alert app
                if (SessionError != null)
                {
                    DtmErrorArgs args = new DtmErrorArgs(new SocketException((int)SocketError.HostUnreachable), DtmErrorSeverityFlags.Connection);
                    SessionError(this, args);
                }
            }
        }

        private void Transmit(DtmPacketFlags PacketType, short PacketFlag, long OptionFlag = 0, MemoryStream Payload = null)
        {
            lock (_sndLock)
            {
                long pldLen = Payload == null ? 0 : Payload.Length;
                // create a new packet: packet flag, payload size, sequence, and state flag
                MemoryStream pktStm = new DtmPacketStruct(PacketType, pldLen, _sndSequence, PacketFlag, OptionFlag).ToStream();

                // add payload
                if (Payload != null)
                {
                    // copy to output
                    pktStm.Seek(0, SeekOrigin.End);
                    Payload.WriteTo(pktStm);
                    pktStm.Seek(0, SeekOrigin.Begin);
                }

                // store in the file packet buffer
                _sndBuffer.Push(_sndSequence, pktStm);
                // increment file send counter
                _sndSequence++;

                // transmit to remote client
                if (_clientSocket.IsConnected)
                {
                    try
                    {
                        _clientSocket.SendAsync(pktStm);
                    }
                    catch (CryptoSocketException ce)
                    {
                        SocketException se = ce.InnerException as SocketException;

                        if (se.SocketErrorCode == SocketError.WouldBlock ||
                            se.SocketErrorCode == SocketError.IOPending ||
                            se.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                        {
                            // buffer is full, throttle down
                            Throttle(pktStm);
                        }
                        else
                        {
                            // possible connection dropped, alert app
                            if (SessionError != null)
                            {
                                DtmErrorArgs args = new DtmErrorArgs(ce, DtmErrorSeverityFlags.Connection);
                                SessionError(this, args);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // possible connection dropped, alert app
                        if (SessionError != null)
                        {
                            DtmErrorArgs args = new DtmErrorArgs(ex, DtmErrorSeverityFlags.Connection);
                            SessionError(this, args);
                        }
                    }

                    // notify app
                    if (PacketSent != null)
                        PacketSent(this, new DtmPacketArgs((short)DtmTransferFlags.DataChunk, pldLen));
                }
            }
        }

        private void TearDown()
        {
            if (_clientSocket != null)
            {
                if (_clientSocket.IsConnected)
                    _clientSocket.Close();
                _clientSocket.Dispose();
            }
            if (_evtSendWait != null)
                _evtSendWait.Dispose();
            if (_fileSymProcessor != null)
                _fileSymProcessor.Dispose();
            if (_rcvBuffer != null)
                _rcvBuffer.Dispose();
            if (_sndBuffer != null)
                _sndBuffer.Dispose();
            if (_filePath != null)
                _filePath = null;
        }

        private void Wait(int WaitMs)
        {
            if (_evtSendWait == null)
                _evtSendWait = new ManualResetEvent(false);

            if (WaitMs < 1)
            {
                // manual reset
                _evtSendWait.WaitOne();
            }
            else
            {
                _evtSendWait.WaitOne(WaitMs);
                _evtSendWait.Set();
            }
        }
        #endregion

        #region Event Handlers
        private void OnDataReceived(DataReceivedEventArgs args)
        {
            if (args.Owner.Client.Equals(_clientSocket.Client))
            {
                // retrieve the packet
                ProcessAndPush(_rcvBuffer, args.Owner.Data);

                // check for sequenced packets in the queue
                if (_rcvBuffer.Count > 0)
                {
                    do
                    {
                        // process if in sequence or break
                        if (!_rcvBuffer.Exists(_rcvSequence))
                            break;
                        else
                            Process(_rcvBuffer.Pop(_rcvSequence));
                    }
                    while (true);
                }
            }
        }

        private void OnConnected(object owner, SocketAsyncEventArgs args)
        {
            // reset the wait event
            if (_evtSendWait != null)
                _evtSendWait.Set();
            // stop listener
            if (_clientSocket.IsListening)
                _clientSocket.ListenStop();
        }

        private void OnDisConnected(object owner, SocketError Flag)
        {
            if (SessionError != null)
                SessionError(this, new DtmErrorArgs(new SocketException((int)SocketError.NotConnected), 0));
        }
        #endregion

        #region IDispose
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!m_isDisposed && Disposing)
            {
                TearDown();
                m_isDisposed = true;
            }
        }
        #endregion
    }
}
