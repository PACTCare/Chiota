#region Directives
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Support;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode;
using VTDev.Libraries.CEXEngine.Crypto.Common;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using VTDev.Libraries.CEXEngine.CryptoException;
using VTDev.Libraries.CEXEngine.Networking;
using VTDev.Libraries.CEXEngine.Utility;
using System.Timers;
using VTDev.Libraries.CEXEngine.Crypto.Helper;
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

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM
{
    /// <summary>
    /// Performs an Asymmetric Key Exchange using the Deferred Trust Model KEX.
    /// <para>This work is preliminary, and subject to modification when the scheme is deployed. (eta is fall of 2015)</para>
    /// </summary>
    /// 
    /// <example>
    /// <description>Creating a DTM Server:</description>
    /// <code>
    /// // dtm server exchange parameters X11RNS1R2
    /// DtmParameters srvDtmParams = DtmParamSets.FromName(DtmParamSets.DtmParamNames.X42RNS1R1);       // preset contains all the settings required for the exchange
    ///
    /// // dtm server id
    /// DtmClientStruct srvDmtId = new DtmClientStruct(
    ///     new byte[] { 3, 3, 3, 3 },      // the clients public id, (should be at least 32 bytes, can be used as a contact lookup and initial authentication string)
    ///     new byte[] { 4, 4, 4, 4 });     // the clients secret id, (secret id can be anything.. a serialized structure, signed data, hash, etc)
    ///
    /// // create the server
    /// _dtmServer = new DtmKex(srvDtmParams, srvDmtId);
    /// _dtmServer.IdentityReceived += new DtmKex.IdentityReceivedDelegate(OnIdentityReceived);         // returns the client public and secret id fields, used to authenticate a host
    /// _dtmServer.PacketReceived += new DtmKex.PacketReceivedDelegate(OnPacketReceived);               // notify that a packet has been received (optional)
    /// _dtmServer.SessionEstablished += new DtmKex.SessionEstablishedDelegate(OnSessionEstablished);   // notify when the vpn state is up
    /// _dtmServer.PacketSent += new DtmKex.PacketReceivedDelegate(OnPacketSent);                       // notify when a packet has been sent to the remote host (optional)
    /// _dtmServer.DataReceived += new DtmKex.DataTransferredDelegate(OnDataReceived);                  // returns the decrypted message data
    /// _dtmServer.FileReceived += new DtmKex.FileTransferredDelegate(OnFileReceived);                  // notify that a file transfer has completed
    /// _dtmServer.FileRequest += new DtmKex.FileRequestDelegate(OnFileRequest);                        // notify that the remote host wants to send a file, can cancel or provide a path for the new file
    /// _dtmServer.SessionError += new DtmKex.SessionErrorDelegate(OnSessionError);                     // notify of any error conditions; includes the exception, and a severity code contained in the option flag
    ///
    /// // server starts listening
    /// _dtmServer.Listen(IPAddress.Any, Port);
    /// </code>
    /// </example>
    /// 
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.DtmParameters"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmClientStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmIdentityStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmPacketStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure.DtmSessionStruct"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument.DtmErrorArgs"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument.DtmEstablishedArgs"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument.DtmPacketArgs"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag.DtmErrorFlags"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag.DtmServiceFlags"/>
    /// <seealso cref="VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag.DtmPacketFlags"/>
    /// 
    /// <remarks>
    /// <description>Overview:</description>
    /// <para>DTM is designed for maximum flexibility, for this reason authentication between hosts is 'deferred' to another layer of software, whereby the users actions and settings can at 
    /// least in part determine the level of security, authentication, repudiation, and how an exchange is transacted.</para>
    /// 
    /// <para>The protocol is directed at end to end data exchanges, (such as voice or video conferencing between nodes), and a means by which nodes may authenticate and execute a secure
    /// communications channel without the need for signing, certificates, or third party authenticators. 
    /// This is intended as a semi-closed system of authentication, whereby a node may choose to engage a session with an unknown actor, 
    /// with both nodes determining a local trust value (ex. adding a contact to a list during a call, banning a host, etc.). 
    /// Expansions of the system beyond a closed or semi-closed framework are considered as a layer above this implementation; i.e. a shared trust model based on a signature scheme, 
    /// or the movement of contacts within a trust model framework.</para>
    /// 
    /// <para>Tasks such as host Authentication are forwarded to an upper layer of software, which in turn can determine an appropriate action. 
    /// For example; the identity exchange notifies the client via events; the <see cref="IdentityReceived"/> forwards an id field, and the symmetric, and asymmetric cipher parameters. 
    /// If the parameter sets do not meet a minimum security context, or the conversation is otherwise refused, that layer of software can terminate the session 
    /// simply by setting the Cancel flag to true in the event arguments, and a packet can be sent back to the requesting host notifying them of the cause of failure. 
    /// This could in turn, trigger another exchange attempt with stronger parameters.</para>
    /// 
    /// <para>This model proposes using two post-quantum secure ciphers; the first cipher should be considered as the Authenticator, or <c>Auth-Phase</c>. 
    /// The authenticating asymmetric cipher is used to encrypt the first (symmetric) session key. This session key is in turn used to encrypt the asymmetric parameters and the Public key
    /// of the second <c>Primary-Phase</c> asymmetric cipher. The primary asymmetric cipher encrypts a second symmetric key; which is used as the primary session key in the VPN.</para>
    /// <para>Both channels (Send and Receive) are encrypted with seperate keys; data Bob sends to Alice is encrypted with the symmetric key that Bob generated and exchanged, and data Bob receives
    /// from Alice is decrypted with the symmetric key that Alice generated. In this way each actor defines the security context for the channel that they transmit data on.</para>
    /// 
    /// <description>Exchange States:</description>
    /// <list type="table">
    ///     <listheader>
    ///         <term>Phase</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description>Connect</description>
    ///         <description>The server and client exchange a DtmIdentityStruct structure; containing just the public id field.</description>
    ///     </item>
    ///     <item>
    ///         <description>Init</description>
    ///         <description>The server and client exchange a full DtmIdentityStruct structure; containing the public id field and the PKE Parameters Id, used to create the <c>Auth-Phase</c> Asymmetric keys.</description>
    ///     </item>
    ///     <item>
    ///         <description>PreAuth</description>
    ///         <description>The server and client exchange their <c>Auth-Phase</c> Asymmetric Public Keys.</description>
    ///     </item>
    ///     <item>
    ///         <description>AuthEx</description>
    ///         <description>The server and client exchange their <c>Auth-Phase</c> Symmetric KeysParams.</description>
    ///     </item>
    ///     <item>
    ///         <description>Auth</description>
    ///         <description>The server and client exchange their private identity fields, used to mutually authenticate.</description>
    ///     </item>
    ///     <item>
    ///         <description>Sync</description>
    ///         <description>The server and client exchange their <c>Primary-Phase</c> Asymmetric and Session Parameters.</description>
    ///     </item>
    ///     <item>
    ///         <description>PrimeEx</description>
    ///         <description>The server and client exchange their <c>Primary-Phase</c> Asymmetric Public Key.</description>
    ///     </item>
    ///     <item>
    ///         <description>Primary</description>
    ///         <description>The server and client exchange their <c>Primary-Phase</c> Symmetric KeyParams.</description>
    ///     </item>
    ///     <item>
    ///         <description>Establish</description>
    ///         <description>The server and client acknowledge their mutual trust; the VPN is UP.</description>
    ///     </item>
    /// </list>
    /// 
    /// <description>Key Forwarding Sequence:</description>
    /// 
    /// <list type="table">
    ///     <listheader>
    ///         <term>Direction</term>
    ///         <term>Action</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description>Client</description>
    ///         <description>Forward Request</description>
    ///         <description>Client sends a key request, initiating the exchange</description>
    ///     </item>
    ///     <item>
    ///         <description>Server</description>
    ///         <description>Process Request</description>
    ///         <description>Process the request and send a key-response (w/key) OR key refused</description>
    ///     </item>
    ///     <item>
    ///         <description>Client</description>
    ///         <description>Process Response</description>
    ///         <description>Process the response and send a key-return (w/key) OR key refused</description>
    ///     </item>
    ///     <item>
    ///         <description>Server</description>
    ///         <description>Key Synchronized</description>
    ///         <description>Process the return and notify client of completion by sending a key-synchronized</description>
    ///     </item>
    /// </list>
    /// 
    /// <para>When keys have been synchronized, the KeySynchronized event is fired, and values are stored as DtmSessionKeyStructs in the 
    /// ForwardSession and ReturnSession properties.
    /// The forward key exchange period is an application operation, which can be performed by manually polling against the values in the 
    /// ForwardSession LifeTime and OptionFlag values. 
    /// The polling should only be done by the Server, the node that first accepted the call, and can be based on application and operation 
    /// factors such as the amount of data sent/received or the channels up-time.
    /// The ratchet flag triggers the immediate re-keying of the crypto stream (once the new keys have been exchanged).</para>
    /// 
    /// <description>Structures:</description>
    /// <list type="table">
    ///     <listheader>
    ///         <term>Structure</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description><see cref="DtmPacketStruct"/></description>
    ///         <description>The primary packet header used in a DTM key exchange; used to classify and describe the message content.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmIdentityStruct"/></description>
    ///         <description>Storage for the active identity, symmetric session, and asymmetric parameters.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmClientStruct"/></description>
    ///         <description>Used to store data that uniquely identifies the host.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmParameters"/></description>
    ///         <description>Defines the working parameters used by the DTM Key Exchange using a DtmKex instance.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmSessionStruct"/></description>
    ///         <description>Contains a minimal description of the symmetric cipher.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmFileInfoSruct"/></description>
    ///         <description>The DtmFileInfoSruct structure is a header that preceedes a file.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmForwardKeyStruct"/></description>
    ///         <description>The DtmForwardKeyStruct structure is used to store the primary session KeyParams, the cipher description, and operation flags.</description>
    ///     </item>
    /// </list>
    /// 
    /// <description>Enumerations:</description>
    /// <list type="table">
    ///     <listheader>
    ///         <term>Enumeration</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description><see cref="DtmErrorFlags"/></description>
    ///         <description>This enum represents the error flags that can be applied to the DtmPacket Option flag.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmErrorSeverityFlags"/></description>
    ///         <description>The flag indicating the severity of an error condition.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmExchangeFlags"/></description>
    ///         <description>This enum represents the DTM KEX exchange state flags.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmForwardingFlags"/></description>
    ///         <description>Key Forwarding state flags used to describe the state of a key forwarding exchange.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmMessageFlags"/></description>
    ///         <description>The flag indicating the message payload type.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmPacketFlags"/></description>
    ///         <description>Contains the primary message types; used as the Message flag in a DtmPacket.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmServiceFlags"/></description>
    ///         <description>Describes the specific type of operation of a service packet.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmTransferFlags"/></description>
    ///         <description>The flag indicating the state of a transfer operation.</description>
    ///     </item>
    /// </list>
    /// 
    /// <description>Arguments:</description>
    /// <list type="table">
    ///     <listheader>
    ///         <term>Argument</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description><see cref="DtmDataReceivedArgs"/></description>
    ///         <description>An event arguments class containing the decrypted message data.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmErrorArgs"/></description>
    ///         <description>An event arguments class containing the error state information.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmEstablishedArgs"/> </description>
    ///         <description>An event arguments class contains the final symmetric keys from a completed exchange.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmFileRequestArgs"/></description>
    ///         <description>An event arguments class containing the FileRequest state.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmIdentityArgs"/></description>
    ///         <description>An event arguments class containing the identity of a client.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmPacketArgs"/></description>
    ///         <description>An event arguments class contains the exchange state information.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmKeyRequestedArgs"/></description>
    ///         <description>An event arguments class containing the forward key parameters.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="DtmKeySynchronizedArgs"/></description>
    ///         <description>An event arguments class containing a forward and return session key pairing.</description>
    ///     </item>
    /// </list>
    /// 
    /// <description>Events:</description>
    /// <list type="table">
    ///     <listheader>
    ///         <term>Event</term>
    ///         <term>Description</term>
    ///     </listheader>
    ///     <item>
    ///         <description><see cref="DataReceived"/></description>
    ///         <description>Event fires each time data has been received through the post-exchange encrypted channel.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="PacketReceived"/></description>
    ///         <description>Event fires each time a valid packet has been received.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="Disconnected"/></description>
    ///         <description>Event fires when the connection is disposed.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="Disconnecting"/></description>
    ///         <description>Event fires when the connection is about to disconnect, but before resources are disposed.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="FileReceived"/></description>
    ///         <description>Event fires when the file transfer operation has completed.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="FileReceived"/></description>
    ///         <description>Event fires when the file transfer operation has completed.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="FileSent"/></description>
    ///         <description>Event fires when the file transfer operation has completed.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="FileRequest"/></description>
    ///         <description>Event fires when the host receives notification of a pending file transfer.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="IdentityReceived"/></description>
    ///         <description>Event fires when a packet containing identity data is received.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="KeyRequested"/></description>
    ///         <description>Event fires when a forwarding key has been requested by the remote host.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="KeySynchronized"/></description>
    ///         <description>Event fires when the key forwarding operation has completed and both send and receive session keys have been stored.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="FileProgressPercent"/></description>
    ///         <description>Event returns file bytes sent or received as an integer percentage.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="SessionError"/></description>
    ///         <description>Event fires when an error has occured.</description>
    ///     </item>
    ///     <item>
    ///         <description><see cref="SessionEstablished"/></description>
    ///         <description>Event fires when the vpn has been established.</description>
    ///     </item>
    /// </list>
    /// 
    /// </remarks>
    public sealed class DtmKex : IDisposable
    {
        #region Constants
        /// <summary>
        /// The default buffer size used in the message exchange
        /// </summary>
        private const int CHUNKSIZE = 8192;
        /// <summary>
        /// The number of milliseconds to wait on a blocking call, default 4 minutes
        /// </summary>
        private const int EXCHTIMEOUT = 1000 * 240;
        /// <summary>
        /// The keepalive timer interval
        /// </summary>
        private const int PULSEINTERVAL = 60000000; // ToDo: 60 * 1000
        /// <summary>
        /// The maximum size of a single message
        /// </summary>
        private const int MAXRCVBUFFER = 1024 * 1000 * 240;
        /// <summary>
        /// Maximum number of times the instance will accept a retransmission request
        /// </summary>
        private const int MAXSNDATTEMPT = 1024;
        /// <summary>
        /// The default connection timeout interval
        /// </summary>
        private const int DEFTIMEOUT = 10;
        /// <summary>
        /// The pre-pended padding delimiter
        /// </summary>
        private readonly byte[] PREDELIM = new byte[] { 255, 1, 254, 2, 253, 3 };
        /// <summary>
        /// The pre-pended padding delimiter
        /// </summary>
        private readonly byte[] POSTDELIM = new byte[] { 1, 255, 2, 254, 3, 253 };
        #endregion

        #region Fields
        private IAsymmetricKeyPair _authKeyPair;                        // the auth stage asymmetric key pair
        private bool _autoReconnect = true;                             // attempt to reconnect if line dropped
        private int _bufferCount = 0;                                   // the number of buffer segments
        private long _bytesSent = 0;                                    // the number of encrypted bytes sent to the remote host on the primary channel
        private long _bytesReceived = 0;                                // the number of encrypted bytes received from the remote host on the primary channel
        private TcpSocket _clientSocket;                                // the client/server main socket instance
        private IAsymmetricParameters _cltAsmParams;                    // the clients asymmetric cipher parameters
        private DtmSessionStruct _cltAuthSession;                       // the clients auth-stage symmetric key params
        private DtmIdentityStruct _cltIdentity;                         // the clients identity structure
        private KeyParams _cltKeyParams;                                // the clients symmetric keying material
        private IAsymmetricKey _cltPublicKey;                           // the clients asymmetric public key
        private ICipherMode _cltSymProcessor;                           // the clients symmetric cipher instance
        private int _connectionTimeOut = DEFTIMEOUT;                    // The number of contiguous missed keepalives before a connection is considered dropped
        private bool _disposeEngines = true;                            // dispose of crypto processors when class disposed
        private DtmClientStruct _dtmHost;                               // the servers client identity
        private DtmParameters _dtmParameters;                           // the dtm exchange parameters
        private ManualResetEvent _evtSendWait;                          // transmission delay event
        private DtmExchangeFlags _exchangeState;                        // current state of the exchange process
        private int _fileCounter = 0;                                   // the unique file id counter
        private DtmBufferSizes _fileBufferSize = DtmBufferSizes.KB32;   // the size of the tcp and file buffer elements
        private object _fileLock = new object();                        // locks file transfer container
        private DtmForwardKeyStruct _fwdSessionKey;                     // the key forwarding transmission key
        private bool _isDisconnecting = false;                          // dispose flag
        private bool m_isDisposed = false;                               // dispose flag
        private bool _isEstablished = false;                            // session established
        private bool _isForwardSession = false;                         // the forward session constructor was used, the kex will be skipped
        private bool _isServer = false;                                 // server if we granted the session
        private int _maxSendCounter = 0;                                // the max resend iterator
        private int _maxSendAttempts = MAXSNDATTEMPT;                   // the max resend attempts
        private DtmBufferSizes _messageBufferSize = DtmBufferSizes.KB8; // the size of the tcp and message buffer elements
        private IAsymmetricKeyPair _primKeyPair;                        // the primary stage asymmetric key pair
        private System.Timers.Timer _pulseTimer;                        // the keep alive timer
        private int _pulseCounter = 0;                                  // the missed keep alives counter
        private PacketBuffer _rcvBuffer;                                // the processing packet buffer
        private int _rcvSequence = 0;                                   // the session receive sequence register
        private DtmClientStruct _remoteIdentity;                        // the public and private id fields of the remote host
        private int _resendThreshold = 10;                              // the number of queued message packets before a resend is triggered
        private DtmForwardKeyStruct _retSessionKey;                     // the key forwarding receiving key
        private IRandom m_rndGenerator;                                  // the random generator
        private object _sendLock = new object();                        // locks the transmission queue
        private int _seqCounter = 0;                                    // tracks high sequence
        private PacketBuffer _sndBuffer;                                // the send packet buffer
        private int _sndSequence = 0;                                   // the session send sequence register
        private IAsymmetricParameters _srvAsmParams;                    // the servers asymmetric cipher parameters
        private DtmIdentityStruct _srvIdentity;                         // the servers identity structure
        private KeyParams _srvKeyParams;                                // the servers symmetric keying material
        private ICipherMode _srvSymProcessor;                           // the servers symmetric cipher instance
        private ConcurrentDictionary<long, DtmFileTransfer> _transQueue = new ConcurrentDictionary<long, DtmFileTransfer>(); // container holds the file transfer instances
        #endregion

        #region Delegates/Events
        /// <summary>
        /// The Packet Transferred delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmDataReceivedArgs"/> class</param>
        public delegate void DataTransferredDelegate(object owner, DtmDataReceivedArgs args);
        /// <summary>
        /// The Data Received event; fires each time data has been received through the post-exchange encrypted channel
        /// </summary>
        public event DataTransferredDelegate DataReceived;

        /// <summary>
        /// The Disconnected delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmPacketArgs"/> class</param>
        public delegate void DisconnectedDelegate(object owner, DtmPacketArgs args);
        /// <summary>
        /// The Disconnected event; fires when the connection is disposed
        /// </summary>
        public event DisconnectedDelegate Disconnected;
        /// <summary>
        /// The Disconnecting event; fires when the connection is about to disconnect, but before resources are disposed
        /// </summary>
        public event DisconnectedDelegate Disconnecting;

        /// <summary>
        /// The File Transferred delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmPacketArgs"/> class</param>
        public delegate void FileTransferredDelegate(object owner, DtmPacketArgs args);
        /// <summary>
        /// The File Received event; fires when the file transfer operation has completed
        /// </summary>
        public event FileTransferredDelegate FileReceived;
        /// <summary>
        /// The File Received event; fires when the file transfer operation has completed
        /// </summary>
        public event FileTransferredDelegate FileSent;

        /// <summary>
        /// The File Request delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmFileRequestArgs"/> class</param>
        public delegate void FileRequestDelegate(object owner, DtmFileRequestArgs args);
        /// <summary>
        /// The File Request event; fires when the host receives notification of a pending file transfer.
        /// <para>The event is received with the file name in the FilePath field, and must return the full path to the local destination, including file name.
        /// To cancel the file transmission, set the <see cref="DtmFileRequestArgs"/> to <c>true</c></para>
        /// </summary>
        public event FileRequestDelegate FileRequest;

        /// <summary>
        /// The Identity Received delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmIdentityArgs"/> class</param>
        public delegate void IdentityReceivedDelegate(object owner, DtmIdentityArgs args);
        /// <summary>
        /// The Identity Received event; fires when a packet containing identity data is received
        /// </summary>
        public event IdentityReceivedDelegate IdentityReceived;

        /// <summary>
        /// The Key Requested delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">The <see cref="DtmKeyRequestedArgs"/> forward key exchange parameters</param>
        public delegate void KeyRequestedDelegate(object owner, DtmKeyRequestedArgs args);
        /// <summary>
        /// A forwarding key has been requested by the remote host
        /// </summary>
        public event KeyRequestedDelegate KeyRequested;

        /// <summary>
        /// The Key Received delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmKeySynchronizedArgs"/> class</param>
        public delegate void KeySynchronizedDelegate(object owner, DtmKeySynchronizedArgs args);
        /// <summary>
        /// Both send and receive session keys have been stored
        /// </summary>
        public event KeySynchronizedDelegate KeySynchronized;

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
        /// Progress Percent Event; returns file bytes received as an integer percentage
        /// </summary>
        public event ProgressDelegate FileProgressPercent;

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

        /// <summary>
        /// The Session Established delegate
        /// </summary>
        /// <param name="owner">The owner object</param>
        /// <param name="args">A <see cref="DtmEstablishedArgs"/> class</param>
        public delegate void SessionEstablishedDelegate(object owner, DtmEstablishedArgs args);
        /// <summary>
        /// The Session Established; fires when the vpn has been established
        /// </summary>
        public event SessionEstablishedDelegate SessionEstablished;
        #endregion

        #region Properties
        /// <summary>
        /// Get: The key created by a key forwarding operation
        /// </summary>
        public DtmForwardKeyStruct ForwardSession
        {
            get { return _fwdSessionKey; }
        }

        /// <summary>
        /// Get: The key returned from a key forwarding operation
        /// </summary>
        public DtmForwardKeyStruct ReturnSession
        {
            get { return _retSessionKey; }
        }

        /// <summary>
        /// Get: Returns the Key and current IV values of the cipher used to Encrypt an outbound transmission.
        /// <para>The key exchange must be completed before this property is accessed.
        /// Note: Session key properties return the initialization vector in their current state, and should only be accessed for 
        /// storage once the encrypted transmissions have ended, i.e. just before Disconnect() is called. 
        /// This must be done in order to keep the vector synchronized and avoid overlapping vectors.</para>
        /// </summary>
        /// 
        /// <exception cref="CryptoKeyExchangeException">Thrown if the property is accessed before a key exchange has completed.</exception>
        public KeyParams TransmitKey
        {
            get 
            {
                if (!_isEstablished)
                    throw new CryptoKeyExchangeException("DtmKex:TransmitKey", "The key exchange has not completed!", new InvalidOperationException());

                return new KeyParams(_srvKeyParams.Key, _srvSymProcessor.IV); 
            }
        }

        /// <summary>
        /// Get: Returns the Key and current IV values of the cipher used to Decrypt an inbound transmission.
        /// <para>The key exchange must be completed before this property is accessed.
        /// Note: Session key properties return the initialization vector in their current state, and should only be accessed for 
        /// storage once the encrypted transmissions have ended, i.e. just before Disconnect() is called. 
        /// This must be done in order to keep the vector synchronized and avoid overlapping vectors.</para>
        /// </summary>
        /// 
        /// <exception cref="CryptoKeyExchangeException">Thrown if the property is accessed before a key exchange has completed.</exception>
        public KeyParams ReceiveKey
        {
            get
            {
                if (!_isEstablished)
                    throw new CryptoKeyExchangeException("DtmKex:ReceiveKey", "The key exchange has not completed!", new InvalidOperationException());

                return new KeyParams(_cltKeyParams.Key, _cltSymProcessor.IV);
            }
        }
        
        /// <summary>
        /// Get: The remote hosts public and secret identity arrays.
        /// <para>The vpn must be established before polling this property.</para>
        /// </summary>
        /// 
        /// <exception cref="CryptoKeyExchangeException">Thrown if the set value is out of range.</exception>
        public DtmClientStruct RemoteIdentity
        {
            get
            {
                if (!_isEstablished)
                    throw new CryptoKeyExchangeException("DtmKex:RemoteIdentity", "The key exchange has not completed!", new InvalidOperationException());

                return _remoteIdentity;
            }
            private set { _remoteIdentity = value;  }
        }

        /// <summary>
        /// Get/Set: Attempts to reconnect to a host if the connection is dropped through an error or timeout
        /// </summary>
        public bool AutoReconnect
        {
            get { return _autoReconnect; }
            set { _autoReconnect = value; }
        }

        /// <summary>
        /// Get: Returns the current executing exchange stage
        /// </summary>
        public DtmExchangeFlags ExchangeState
        {
            get { return _exchangeState; }
        }

        /// <summary>
        /// Get/Set: The number of contiguous missed keepalives (at one second intervals), before a connection is considered dropped.
        /// <para>This value is used by the AutoReconnect feature as the threshold before a reconnect operation is initiated.
        /// Adjust this interval based on the target devices reliability, processing power, and load;
        /// ex. a phone should wait 30 seconds or more, a computer 10 seconds or less.
        /// The default value is 10 seconds.</para>
        /// </summary>
        /// 
        /// <exception cref="CryptoKeyExchangeException">Thrown if the set value is out of range.</exception>
        public int ConnectionTimeOut
        {
            get { return _connectionTimeOut; }
            set 
            {
                if (value < 1 || value > 1024)
                    throw new CryptoKeyExchangeException("DtmKex:ConnectionTimeOut", "The value must be a postive number between 1 and 1024!", new ArgumentException());

                _connectionTimeOut = value; 
            }
        }

        /// <summary>
        /// Get: The connection state
        /// </summary>
        public bool IsConnected
        {
            get { return _clientSocket == null ? false : _clientSocket.IsConnected; }
        }

        /// <summary>
        /// Get: The VPN is Established
        /// </summary>
        public bool IsEstablished
        {
            get { return _isEstablished; }
        }

        /// <summary>
        /// Get/Set: The size of the file Tcp and buffer queue elements.
        /// <para>Buffer size <c>must match</c> remote client, otherwise an excess of partial packets could break the queing mechanism.</para>
        /// </summary>
        public DtmBufferSizes FileBufferSize
        {
            get { return _fileBufferSize; }
            set { _fileBufferSize = value; }
        }

        /// <summary>
        /// Get/Set: The maximum number of times a packet can be resent; default is <c>1024</c>
        /// </summary>
        /// 
        /// <exception cref="CryptoKeyExchangeException">Thrown if the value is less than <c>0</c></exception>
        public int MaxResend
        {
            get { return _maxSendAttempts; }
            set 
            {
                if (value < 0)
                    throw new CryptoKeyExchangeException("DtmKex:MaxResend", "The value must be a postive number!", new ArgumentException());

                _maxSendAttempts =  value; 
            }
        }

        /// <summary>
        /// Get/Set: The size of the message Tcp and buffer queue elements.
        /// <para>Buffer size <c>must match</c> remote client, otherwise an excess of partial packets could break the queing mechanism.
        /// The size of the buffer should align with the implementation type, i.e. be as close to the expected output segment size as possible,
        /// while large enough to process every stream segment; ex. if the average output of a video processor frame is  6 KB, set the packet size to 8 KB. 
        /// </para>
        /// </summary>
        public DtmBufferSizes MessageBufferSize
        {
            get { return _messageBufferSize; }
            set { _messageBufferSize = value; }
        }

        /// <summary>
        /// Get/Set: The number of queued message packets before a resend is triggered
        /// </summary>
        /// 
        /// <exception cref="CryptoKeyExchangeException">Thrown if the set value is out of range.</exception>
        public int ResendThreshold
        {
            get { return _resendThreshold; }
            set 
            {
                if (value < 1 || value > 1024)
                    throw new CryptoKeyExchangeException("DtmKex:ResendThreshold", "The value must be a postive number between 1 and 1024!", new ArgumentException());

                _resendThreshold = value; 
            }
        }

        /// <summary>
        /// Get: Returns the TcpSocket class instance
        /// </summary>
        public TcpSocket Socket
        {
            get { return _clientSocket; }
        }
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        /// 
        /// <param name="Parameters">A populated <see cref="DtmParameters"/> class containing the session parameters</param>
        /// <param name="LocalClient">A populated <see cref="DtmClientStruct"/> class containing the servers identity data</param>
        /// <param name="BufferCount">The number of send/receive buffers, default is 1024</param>
        /// <param name="DisposeEngines">if set to true (default), the primary symmetric ciphers are disposed when this class is disposed</param>
        public DtmKex(DtmParameters Parameters, DtmClientStruct LocalClient, int BufferCount = 1024, bool DisposeEngines = true)
        {
            _disposeEngines = DisposeEngines;
            _dtmParameters = Parameters;
            _dtmHost = LocalClient;
            _srvIdentity = new DtmIdentityStruct(LocalClient.PublicId, Parameters.AuthPkeId, Parameters.AuthSession, 0);
            _exchangeState = DtmExchangeFlags.Connect;
            _rcvBuffer = new PacketBuffer(BufferCount);
            _sndBuffer = new PacketBuffer(BufferCount);
            m_rndGenerator = GetPrng(_dtmParameters.RandomEngine);
            _bufferCount = BufferCount;
        }

        /// <summary>
        /// Initialize this class with a random generator
        /// </summary>
        /// 
        /// <param name="Parameters">A populated <see cref="DtmParameters"/> class containing the session parameters</param>
        /// <param name="LocalClient">A populated <see cref="DtmClientStruct"/> class containing the servers identity data</param>
        /// <param name="Generator">The initialized <see cref="IRandom"/> Prng instance</param>
        /// <param name="BufferCount">The number of send/receive buffers, default is 1024</param>
        /// <param name="DisposeEngines">if set to true (default), the primary symmetric ciphers are disposed when this class is disposed</param>
        public DtmKex(DtmParameters Parameters, DtmClientStruct LocalClient, IRandom Generator, int BufferCount = 1024, bool DisposeEngines = true)
        {
            _disposeEngines = DisposeEngines;
            _dtmParameters = Parameters;
            _dtmHost = LocalClient;
            _srvIdentity = new DtmIdentityStruct(LocalClient.PublicId, Parameters.AuthPkeId, Parameters.AuthSession, 0);
            _exchangeState = DtmExchangeFlags.Connect;
            _rcvBuffer = new PacketBuffer(BufferCount);
            _sndBuffer = new PacketBuffer(BufferCount);
            m_rndGenerator = Generator;
            _bufferCount = BufferCount;
        }

        /// <summary>
        /// Initialize this class with the established session keys and cipher descriptions.
        /// <para>This constructor can be used to re-initialize a session with existing primary session keys.
        /// Using this constructor, a session can be initialized using a forward secrecy pattern, 
        /// or used for situations where maintaining a socket connection for the duration of a call is impractical.
        /// Once a session has been established, primary keys can be obtained from the <see cref="TransmitKey"/> and <see cref="ReceiveKey"/> properties. 
        /// The remote clients dtm client identity structure is accessable through the <see cref="RemoteIdentity"/> structure.
        /// Note: Session key properties return the initialization vectors in their current state, and should only be accessed for 
        /// storage once all encrypted transmissions have ended, i.e. immediately before Disconnect() is called. 
        /// This must be done in order to keep the vector synchronized and avoid overlapping encryption vectors.</para>
        /// </summary>
        /// 
        /// <param name="Parameters">A populated <see cref="DtmParameters"/> class containing the session parameters</param>
        /// <param name="LocalClient">A populated <see cref="DtmClientStruct"/> class containing the servers identity data</param>
        /// <param name="RemoteClient">A populated <see cref="DtmClientStruct"/> class containing the remote hosts identity data</param>
        /// <param name="ForwardSession">The primary forward <see cref="DtmForwardKeyStruct"/>, containing the key and cipher description</param>
        /// <param name="ReturnSession">The primary return <see cref="DtmForwardKeyStruct"/>, containing the key and cipher description</param>
        /// <param name="BufferCount">The number of send/receive buffers, default is 1024</param>
        /// <param name="DisposeEngines">if set to true (default), the primary symmetric ciphers are disposed when this class is disposed</param>
        public DtmKex(DtmParameters Parameters, DtmClientStruct LocalClient, DtmClientStruct RemoteClient, DtmForwardKeyStruct ForwardSession, DtmForwardKeyStruct ReturnSession, int BufferCount = 1024, bool DisposeEngines = true)
        {
            _disposeEngines = DisposeEngines;
            _dtmParameters = Parameters;
            _dtmHost = LocalClient;
            _srvIdentity = new DtmIdentityStruct(LocalClient.PublicId, Parameters.AuthPkeId, Parameters.AuthSession, 0);
            _exchangeState = DtmExchangeFlags.Established;
            _rcvBuffer = new PacketBuffer(BufferCount);
            _sndBuffer = new PacketBuffer(BufferCount);
            m_rndGenerator = GetPrng(_dtmParameters.RandomEngine);
            _bufferCount = BufferCount;

            LoadSession(ForwardSession, ReturnSession);

            _isForwardSession = true;
        }

        private DtmKex()
        {
        }

        /// <summary>
        /// Finalize objects
        /// </summary>
        ~DtmKex()
        {
            Dispose(false);
        }
        #endregion

        #region Connect
        /// <summary>
        /// Connect to a server and begin the key exchange
        /// </summary>
        /// 
        /// <param name="HostName">The servers Host Nam</param>
        /// <param name="Port">The servers Port number</param>
        /// <param name="Async">Connect on a non-blocking TCP channel</param>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a socket error is returned</exception>
        public void Connect(string HostName, int Port, bool Async = true)
        {
            // create the connection
            _clientSocket = new TcpSocket();
            _clientSocket.Connected += new TcpSocket.ConnectedDelegate(OnClientConnected);
            _clientSocket.DataReceived += new TcpSocket.DataReceivedDelegate(OnDataReceived);
            _clientSocket.TcpSocketError += new TcpSocket.TcpSocketErrorDelegate(OnTcpSocketError);

            try
            {
                if (Async)
                    _clientSocket.ConnectAsync(HostName, Port);
                else
                    _clientSocket.Connect(HostName, Port);
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorArgs(new CryptoSocketException("DtmKex:Connect", "The connection attempt has failed", ex), DtmErrorSeverityFlags.Connection));

            }
        }

        /// <summary>
        /// Connect to a server and begin the key exchange
        /// </summary>
        /// 
        /// <param name="Address">The servers IP Address</param>
        /// <param name="Port">The servers Port number</param>
        /// <param name="Async">Connect on a non-blocking TCP channel</param>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a socket error is returned</exception>
        public void Connect(IPAddress Address, int Port, bool Async = true)
        {
            // create the connection
            _clientSocket = new TcpSocket();
            _clientSocket.Connected += new TcpSocket.ConnectedDelegate(OnClientConnected);
            _clientSocket.DataReceived += new TcpSocket.DataReceivedDelegate(OnDataReceived);
            _clientSocket.TcpSocketError += new TcpSocket.TcpSocketErrorDelegate(OnTcpSocketError);

            try
            {
                if (Async)
                    _clientSocket.ConnectAsync(Address, Port);
                else
                    _clientSocket.Connect(Address, Port);
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorArgs(new CryptoSocketException("DtmKex:Connect", "The connection attempt has failed", ex), DtmErrorSeverityFlags.Connection));
            }
        }

        /// <summary>
        /// Server has accepted the connection from the Client
        /// </summary>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a processing or socket error is returned</exception>
        private void OnClientConnected(object owner, SocketAsyncEventArgs args)
        {
            _clientSocket.ReceiveBufferSize = (int)MessageBufferSize;
            _clientSocket.SendBufferSize = (int)MessageBufferSize;

            // we are the client
            _isServer = false;

            try
            {
                if (_isForwardSession)
                    _isEstablished = true;  // using forward secrecy pattern
                else
                    ClientExchange();       // start the key exchange
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorArgs(new CryptoKeyExchangeException("DtmKex:OnClientConnected", "The key exchange has failed!", ex), DtmErrorSeverityFlags.Critical));

                return;
            }

            // listen for incoming data
            _clientSocket.ReceiveAsync();
        }

        /// <summary>
        /// Executes the client portion of the key exchange
        /// </summary>
        private void ClientExchange()
        {
            try
            {
                // send connect request
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Connect, 0, CreateConnect(), true);
                // process connect response
                Process(BlockingReceive());
                // init
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Init, 0, CreateInit(), true);
                Process(BlockingReceive());
                // preauth
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.PreAuth, 0, CreatePreAuth(), true);
                Process(BlockingReceive());
                // authex
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.AuthEx, 0, CreateAuthEx(), true);
                Process(BlockingReceive());
                // auth
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Auth, 0, CreateAuth(), true);
                Process(BlockingReceive());
                // sync
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Sync, 0, CreateSync(), true);
                Process(BlockingReceive());
                // primex
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.PrimeEx, 0, CreatePrimeEx(), true);
                Process(BlockingReceive());
                // primary
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Primary, 0, CreatePrimary(), true);
                Process(BlockingReceive());
                // established
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Established, 0, CreateEstablish(), true);
                Process(BlockingReceive());

                // clear the buffers
                _rcvBuffer.Clear();
                _sndBuffer.Clear();
                // start keep alive timer
                StartPulse();
            }
            catch
            {
                if (!_isDisconnecting)
                    throw;
            }
        }
        #endregion

        #region Listen
        /// <summary>
        /// Initialize the server and listen for incoming connections
        /// </summary>
        /// 
        /// <param name="HostName">The servers Host Name</param>
        /// <param name="Port">The servers Port number</param>
        /// <param name="Async">Listen on a non-blocking TCP connection</param>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a socket error is returned</exception>
        public void Listen(string HostName, int Port, bool Async = true)
        {
            _clientSocket = new TcpSocket();
            _clientSocket.Connected += new TcpSocket.ConnectedDelegate(OnServerConnected);
            _clientSocket.DataReceived += new TcpSocket.DataReceivedDelegate(OnDataReceived);
            _clientSocket.TcpSocketError += new TcpSocket.TcpSocketErrorDelegate(OnTcpSocketError);

            try
            {
                if (Async)
                    _clientSocket.ListenAsync(HostName, Port);
                else
                    _clientSocket.Listen(HostName, Port);
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorArgs(new CryptoSocketException("DtmKex:Listen", "The server experienced a socket error!", ex), DtmErrorSeverityFlags.Connection));
            }
        }

        /// <summary>
        /// Initialize the server and listen for incoming connections
        /// </summary>
        /// 
        /// <param name="Address">The servers IP Address</param>
        /// <param name="Port">The servers Port number</param>
        /// <param name="Async">Listen on a non-blocking TCP connection</param>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a socket error is returned</exception>
        public void Listen(IPAddress Address, int Port, bool Async = true)
        {
            _clientSocket = new TcpSocket();
            _clientSocket.Connected += new TcpSocket.ConnectedDelegate(OnServerConnected);
            _clientSocket.DataReceived += new TcpSocket.DataReceivedDelegate(OnDataReceived);
            _clientSocket.TcpSocketError += new TcpSocket.TcpSocketErrorDelegate(OnTcpSocketError);

            try
            {
                if (Async)
                    _clientSocket.ListenAsync(Address, Port);
                else
                    _clientSocket.Listen(Address, Port);
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorArgs(new CryptoSocketException("DtmKex:Listen", "The server received a socket error!", ex), DtmErrorSeverityFlags.Connection));
            }
        }

        /// <summary>
        /// Client has made a connection to the server
        /// </summary>
        /// 
        /// <exception cref="CryptoNetworkingException">Thrown if a processing or socket error is returned</exception>
        private void OnServerConnected(object owner, SocketAsyncEventArgs args)
        {
            // stop listening; create a new dtm class instance to listen for another client
            _clientSocket.ListenStop();
            _clientSocket.ReceiveBufferSize = (int)MessageBufferSize;
            _clientSocket.SendBufferSize = (int)MessageBufferSize;

            // a client has connected, we are the server
            _isServer = true;

            try
            {
                if (_isForwardSession)
                    _isEstablished = true;  // using forward secrecy pattern
                else
                    ServerExchange();       // run the key exchange
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorArgs(new CryptoKeyExchangeException("DtmKex:OnClientConnected", "The key exchange has failed!", ex), DtmErrorSeverityFlags.Critical));

                return;
            }

            // listen for incoming data
            _clientSocket.ReceiveAsync();
        }

        /// <summary>
        /// Executes the server portion of the key exchange
        /// </summary>
        private void ServerExchange()
        {
            try
            {
                // process blocking connect
                Process(BlockingReceive());
                // send a connect response
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Connect, 0, CreateConnect(), true);
                // init
                Process(BlockingReceive());
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Init, 0, CreateInit(), true);
                // preauth
                Process(BlockingReceive());
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.PreAuth, 0, CreatePreAuth(), true);
                // authex
                Process(BlockingReceive());
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.AuthEx, 0, CreateAuthEx(), true);
                // auth
                Process(BlockingReceive());
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Auth, 0, CreateAuth(), true);
                // sync
                Process(BlockingReceive());
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Sync, 0, CreateSync(), true);
                // primex
                Process(BlockingReceive());
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.PrimeEx, 0, CreatePrimeEx(), true);
                // primary
                Process(BlockingReceive());
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Primary, 0, CreatePrimary(), true);
                // established
                Process(BlockingReceive());
                Transmit(DtmPacketFlags.Exchange, (short)DtmExchangeFlags.Established, 0, CreateEstablish(), true);

                // clear the buffers
                _rcvBuffer.Clear();
                _sndBuffer.Clear();
                // start keep alive timer
                StartPulse();
            }
            catch
            {
                if (!_isDisconnecting)
                    throw;
            }
        }
        #endregion

        #region Data Received
        /// <summary>
        /// Entry point for post-exchange data received from the Tcp Socket
        /// </summary>
        private void OnDataReceived(DataReceivedEventArgs args)
        {
            if (args.Owner.Client.Equals(_clientSocket.Client))
            {
                // retrieve and buffer the packet
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

        /// <summary>
        /// Processes and queues incoming packets
        /// </summary>
        private void ProcessAndPush(PacketBuffer Buffer, MemoryStream PacketStream)
        {
            int hdrLen = DtmPacketStruct.GetHeaderSize();
            int pktLen = 0;
            // process the whole packet
            PacketStream.Seek(0, SeekOrigin.Begin);
            // get the header
            DtmPacketStruct dtmPkt = new DtmPacketStruct(PacketStream);
            PacketStream.Seek(0, SeekOrigin.Begin);

            // track high sequence number, filters corrupt packets
            if (dtmPkt.Sequence > _seqCounter && dtmPkt.PayloadLength < MAXRCVBUFFER && dtmPkt.OptionFlag < 1000)
                _seqCounter = dtmPkt.Sequence;

            // out of sync, possible packet loss
            if (_seqCounter - _rcvSequence > ResendThreshold)
            {
                // request a retransmission
                Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Resend, _rcvSequence + 1);
            }

            if (dtmPkt.PayloadLength + hdrLen == PacketStream.Length)
            {
                // resend was already processed
                if (dtmPkt.Sequence < _rcvSequence)
                    return;

                // push onto buffer
                Buffer.Push(dtmPkt.Sequence, PacketStream);
            }
            // more than one packet
            else if (dtmPkt.PayloadLength + hdrLen < PacketStream.Length)
            {
                byte[] buf;
                long pos = 0;

                do
                {
                    // get packet position
                    pos = PacketStream.Position;

                    if (PacketStream.Length - pos < DtmPacketStruct.GetHeaderSize())
                    {
                        // next packet corrupted, request a retransmission and exit
                        Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Resend, Buffer.GetHighKey() + 1);
                        return;
                    }

                    dtmPkt = new DtmPacketStruct(PacketStream);
                    pktLen = (int)(hdrLen + dtmPkt.PayloadLength);

                    if (pktLen > MAXRCVBUFFER || pktLen < 0 || PacketStream.Length - pos < pktLen)
                    {
                        // packet corrupted, request a retransmission and exit
                        Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Resend, Buffer.GetHighKey() + 1);
                        return;
                    }
                    else
                    {
                        // create the buffer
                        buf = new byte[pktLen];
                        PacketStream.Seek(pos, SeekOrigin.Begin);
                        PacketStream.Read(buf, 0, (int)pktLen);
                        // push onto buffer
                        Buffer.Push(dtmPkt.Sequence, new MemoryStream(buf));
                    }

                } while (PacketStream.Position < PacketStream.Length);
            }
            // malformed packet, send retransmit request
            else if (dtmPkt.PayloadLength > MAXRCVBUFFER || dtmPkt.PayloadLength < 0 || dtmPkt.PayloadLength + hdrLen > PacketStream.Length)
            {
                // packet corrupted, request a retransmission of last in queue + 1
                Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Resend, Buffer.GetHighKey() + 1);
            }
        }
        #endregion

        #region Channel Processors
        /// <summary>
        /// Disconnect from the remote host and teardown the connection
        /// </summary>
        /// 
        /// <param name="ReasonFlag">The reason for the disconnect, the default is the normal termination flag; ConnectionTerminated</param>
        public void Disconnect(DtmErrorFlags ReasonFlag = DtmErrorFlags.ConnectionTerminated)
        {
            // this is where you should poll session key properties for current state (if the disconnect is orderly)
            if (Disconnecting != null)
                Disconnecting(this, new DtmPacketArgs((short)_exchangeState, (long)ReasonFlag));

            _isDisconnecting = true;
            _isEstablished = false;

            // stop sending keepalives
            StopPulse();

            try
            {
                if (_clientSocket.IsConnected)
                {
                    Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Terminate, (long)ReasonFlag, null, true);
                    _clientSocket.TcpStream.Flush();
                    _clientSocket.Close();
                }
            }
            catch { }

            try
            {
                if (_clientSocket != null)
                {
                    _clientSocket.Dispose();
                    _clientSocket = null;
                }
                if (_evtSendWait != null)
                {
                    _evtSendWait.Dispose();
                    _evtSendWait = null;
                }
                if (_rcvBuffer != null)
                {
                    _rcvBuffer.Dispose();
                    _rcvBuffer = null;
                }
                if (_sndBuffer != null)
                {
                    _sndBuffer.Dispose();
                    _sndBuffer = null;
                }
            }
            catch { }

            try
            {
                TearDown();
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorArgs(new CryptoKeyExchangeException("DtmKex:Disconnect", "The tear down operation experienced an error!", ex), DtmErrorSeverityFlags.Warning));
            }
            finally
            {
                if (Disconnected != null)
                    Disconnected(this, new DtmPacketArgs((short)_exchangeState, (long)ReasonFlag));
            }
        }

        /// <summary>
        /// Loads the symmetric session keys into an active session
        /// </summary>
        /// 
        /// <param name="ForwardSession">The DtmForwardKeyStruct containing the transmission key, options, and the symmetric cipher description</param>
        /// <param name="ReturnSession">The DtmForwardKeyStruct containing the receiving key, options, and the symmetric cipher description</param>
        private void LoadSession(DtmForwardKeyStruct ForwardSession, DtmForwardKeyStruct ReturnSession)
        {
            _srvKeyParams = ForwardSession.Key;
            _srvSymProcessor = GetSymmetricCipher(ForwardSession.SessionParams);
            _srvSymProcessor.Initialize(true, _srvKeyParams);

            _cltKeyParams = ReturnSession.Key;
            _cltSymProcessor = GetSymmetricCipher(ReturnSession.SessionParams);
            _cltSymProcessor.Initialize(false, _cltKeyParams);
        }

        /// <summary>
        /// Process a message.
        /// <para>Use this method to process <see cref="DtmPacketStruct"/> data sent to the server</para>
        /// </summary>
        private void Process(MemoryStream PacketStream)
        {
            try
            {
                // increment rcv sequence
                _rcvSequence++;
                // get the header
                DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
                PacketStream.Seek(0, SeekOrigin.Begin);

                switch (pktHdr.PacketType)
                {
                    // message stream
                    case DtmPacketFlags.Message:
                        {
                            try
                            {
                                // received stream data
                                ReceiveMessage(PacketStream);
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
                    // service messages
                    case DtmPacketFlags.Service:
                        {
                            switch ((DtmServiceFlags)pktHdr.PacketFlag)
                            {
                                case DtmServiceFlags.KeepAlive:
                                    {
                                        // reset the keep alive counter
                                        _pulseCounter = 0;
                                        break;
                                    }
                                // process echo
                                case DtmServiceFlags.Echo:
                                    {
                                        // remove from buffer
                                        if (_sndBuffer.Exists(pktHdr.OptionFlag))
                                            _sndBuffer.Destroy(pktHdr.OptionFlag);

                                        break;
                                    }
                                case DtmServiceFlags.Resend:
                                    {
                                        // attempt resend, if not in buffer transmission, attempts a resync
                                        Resend(pktHdr);
                                        break;
                                    }
                                case DtmServiceFlags.DataLost:
                                    {
                                        // remote packet lost, try resync. note: if this happens often, increase buffer size in ctor + tcp
                                        MemoryStream pktData = CreateResync();
                                        _bytesSent += pktData.Length;
                                        Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.Resync, _bytesSent, pktData);
                                        break;
                                    }
                                case DtmServiceFlags.Resync:
                                    {
                                        // attempt to resync the crypto stream
                                        ProcessResync(PacketStream);
                                        break;
                                    }
                                case DtmServiceFlags.Refusal:
                                    {
                                        DtmErrorArgs args = new DtmErrorArgs(new ApplicationException("The session was refused by the remote host."), DtmErrorSeverityFlags.Connection);
                                        if (SessionError != null)
                                            SessionError(this, args);

                                        if (args.Cancel)
                                            Disconnect(DtmErrorFlags.ConnectionRefused);

                                        break;
                                    }
                                case DtmServiceFlags.Terminate:
                                    {
                                        // reserved
                                        DtmErrorArgs args = new DtmErrorArgs(new ApplicationException("The session was terminated by the remote host."), DtmErrorSeverityFlags.Critical);
                                        if (SessionError != null)
                                            SessionError(this, args);

                                        Disconnect();
                                        break;
                                    }
                            }

                            break;
                        }
                    // file transfer
                    case DtmPacketFlags.Transfer:
                        {
                            switch ((DtmTransferFlags)pktHdr.PacketFlag)
                            {
                                case DtmTransferFlags.Request:
                                    {
                                        // received file transfer request
                                        ReceiveFile(PacketStream);
                                        break;
                                    }
                                case DtmTransferFlags.Refused:
                                    {
                                        // refused by remote
                                        DtmErrorArgs args = new DtmErrorArgs(new ApplicationException("The session was refused by the remote host."), DtmErrorSeverityFlags.Connection);
                                        if (SessionError != null)
                                            SessionError(this, args);

                                        CloseTransfer(pktHdr.OptionFlag);
                                        break;
                                    }
                                case DtmTransferFlags.Received:
                                    {
                                        // refused by remote
                                        CloseTransfer(pktHdr.OptionFlag);
                                        break;
                                    }
                            }
                            break;
                        }
                    // key exchange
                    case DtmPacketFlags.Exchange:
                    {
                        // process exchange message
                        switch ((DtmExchangeFlags)pktHdr.PacketFlag)
                        {
                            case DtmExchangeFlags.Connect:
                                {
                                    // received public id
                                    ProcessConnect(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.Init:
                                {
                                    // received auth-stage params
                                    ProcessInit(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.PreAuth:
                                {
                                    // received public key
                                    ProcessPreAuth(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.AuthEx:
                                {
                                    // received symmetric key
                                    ProcessAuthEx(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.Auth:
                                {
                                    // received private id
                                    ProcessAuth(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.Sync:
                                {
                                    // received primary public key params
                                    ProcessSync(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.Primary:
                                {
                                    // received primary public key
                                    ProcessPrimary(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.PrimeEx:
                                {
                                    // received primary session key
                                    ProcessPrimeEx(PacketStream);
                                    break;
                                }
                            case DtmExchangeFlags.Established:
                                {
                                    // received ack established
                                    ProcessEstablish(PacketStream);
                                    break;
                                }
                            }
                            break;
                    }
                    // key forwarding
                    case DtmPacketFlags.Forwarding:
                    {
                        // key forwarding flags
                        switch ((DtmForwardingFlags)pktHdr.PacketFlag)
                        {
                            case DtmForwardingFlags.KeyRequest:
                                {
                                    ProcessKeyRequest(PacketStream);
                                    break;
                                }
                            case DtmForwardingFlags.KeyResponse:
                                {
                                    ProcessKeyResponse(PacketStream);
                                    break;
                                }
                            case DtmForwardingFlags.KeyReturn:
                                {
                                    ProcessKeyReturn(PacketStream);
                                    break;
                                }
                            case DtmForwardingFlags.KeySynchronized:
                                {
                                    ProcessKeySynchronized(PacketStream);
                                    break;
                                }
                            case DtmForwardingFlags.KeyRefused:
                                {
                                    if (SessionError != null)
                                        SessionError(this, new DtmErrorArgs(new CryptoKeyExchangeException("DtmKex:ForwardKey", "The key forwarding request was refused by the remote host!", new Exception()), DtmErrorSeverityFlags.Warning));
                                    
                                    break;
                                }
                        }
                        break;
                    }
                    default:
                    {
                        if (SessionError != null)
                            SessionError(this, new DtmErrorArgs(new CryptoKeyExchangeException("DtmKex:Process", "The data transmission encountered an error!", new InvalidDataException()), DtmErrorSeverityFlags.Critical));
                        
                        break;
                    }
                }

                // notify app
                if (PacketReceived != null)
                    PacketReceived(this, new DtmPacketArgs(pktHdr.PacketFlag, pktHdr.PayloadLength));
            }
            catch (Exception ex)
            {
                if (SessionError != null)
                    SessionError(this, new DtmErrorArgs(new CryptoKeyExchangeException("DtmKex:Process", "The data received caused an error!", ex), DtmErrorSeverityFlags.Critical));
            }
        }

        /// <summary>
        /// Resend a packet to a host
        /// </summary>
        private void Resend(DtmPacketStruct Packet)
        {
            if (_sndBuffer.Exists(Packet.Sequence))
            {
                _maxSendCounter++;

                // limit attack scope with session resend max
                if (_maxSendCounter > MaxResend)
                {
                    // let the app decide what to do next
                    DtmErrorArgs args = new DtmErrorArgs(new InvalidDataException("The stream has encountered data loss, attempting to resync.."), DtmErrorSeverityFlags.DataLoss);
                    if (SessionError != null)
                        SessionError(this, args);

                    if (args.Cancel)
                    {
                        Disconnect(DtmErrorFlags.ConnectionTimedOut);
                        return;
                    }
                }

                try
                {
                    MemoryStream pktStm = _sndBuffer.Peek(Packet.Sequence);
                    if (pktStm != null)
                    {
                        if (pktStm.Length > 0)
                            pktStm.WriteTo(_clientSocket.TcpStream);

                        _sndSequence++;
                    }
                }
                catch 
                {
                    // packet lost, request a resync
                    Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.DataLost);
                }
            }
            else
            {
                // packet lost, request a resync
                Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.DataLost);
            }
        }

        /// <summary>
        /// Sends a packet with increasing wait times. 
        /// <para>After 4 attempts fires a SessionError with optional cancellation token.</para>
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
                            DtmErrorArgs args = new DtmErrorArgs(ce, DtmErrorSeverityFlags.Warning);
                            SessionError(this, args);

                            if (args.Cancel)
                                Disconnect(DtmErrorFlags.ConnectionDropped);
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
                    DtmErrorArgs args = new DtmErrorArgs(new SocketException((int)SocketError.HostUnreachable), DtmErrorSeverityFlags.DataLoss);
                    SessionError(this, args);

                    if (args.Cancel)
                        Disconnect(DtmErrorFlags.ConnectionDropped);
                }
            }
        }

        /// <summary>
        /// Frame and Transmit the packet to the remote client
        /// </summary>
        /// 
        /// <param name="PacketType">The packet class</param>
        /// <param name="PacketFlag">The packet message type flag</param>
        /// <param name="OptionFlag">The option flag</param>
        /// <param name="Payload">The packet payload flag</param>
        /// <param name="Blocking">Blocking or Async transmit</param>
        private void Transmit(DtmPacketFlags PacketType, short PacketFlag, long OptionFlag = 0, MemoryStream Payload = null, bool Blocking = false)
        {
            lock (_sendLock)
            {
                long pldLen = Payload == null ? 0 : Payload.Length;
                // create a new packet: packet flag, payload size, sequence, and state flag
                MemoryStream pktStm = new DtmPacketStruct(PacketType, pldLen, _sndSequence, PacketFlag, OptionFlag).ToStream();

                // add payload
                if (Payload != null)
                {
                    // store total encrypted bytes sent
                    if (_isEstablished)
                        _bytesSent += Payload.Length;

                    // copy to output
                    pktStm.Seek(0, SeekOrigin.End);
                    Payload.WriteTo(pktStm);
                    pktStm.Seek(0, SeekOrigin.Begin);
                }

                // service requests are not buffered
                if (PacketType != DtmPacketFlags.Service)
                {
                    // store in the packet buffer
                    _sndBuffer.Push(_sndSequence, pktStm);
                }

                // increment send counter
                _sndSequence++;

                // transmit to remote client
                if (_clientSocket.IsConnected)
                {
                    if (!Blocking)
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
                                // buffer is full, slow down
                                Throttle(pktStm);
                            }
                            else if (se.SocketErrorCode != SocketError.Success)
                            {
                                // possible connection dropped, alert app
                                if (SessionError != null)
                                {
                                    DtmErrorArgs args = new DtmErrorArgs(ce, DtmErrorSeverityFlags.Connection);
                                    SessionError(this, args);

                                    if (args.Cancel)
                                        Disconnect(DtmErrorFlags.ConnectionDropped);
                                }
                            }
                        }
                    }
                    else
                    {
                        try
                        {
                            pktStm.WriteTo(_clientSocket.TcpStream);
                        }
                        catch (Exception ex)
                        {
                            // internal error, alert app
                            if (SessionError != null)
                            {
                                DtmErrorArgs args = new DtmErrorArgs(ex, DtmErrorSeverityFlags.Critical);
                                SessionError(this, args);

                                if (args.Cancel)
                                    Disconnect(DtmErrorFlags.ConnectionDropped);
                            }
                        }
                    }

                    // success, notify app
                    if (PacketSent != null)
                        PacketSent(this, new DtmPacketArgs((short)_exchangeState, pldLen));
                }
                else
                {
                    // possible connection dropped, alert app
                    if (SessionError != null)
                    {
                        DtmErrorArgs args = new DtmErrorArgs(new SocketException((int)SocketError.ConnectionReset), DtmErrorSeverityFlags.Connection);
                        SessionError(this, args);

                        if (args.Cancel)
                            Disconnect(DtmErrorFlags.ConnectionDropped);
                    }
                }
            }
        }
        #endregion

        #region Post-Exchange Channels
        #region Receive
        /// <summary>
        /// Used to read a blocking message response
        /// </summary>
        private MemoryStream BlockingReceive()
        {
            MemoryStream pktStm = null;

            try
            {
                // get the header
                pktStm = _clientSocket.GetStreamData(DtmPacketStruct.GetHeaderSize(), EXCHTIMEOUT);
                DtmPacketStruct pktHdr = new DtmPacketStruct(pktStm);

                // add the payload
                if (pktHdr.PayloadLength > 0)
                    _clientSocket.GetStreamData((int)pktHdr.PayloadLength, EXCHTIMEOUT).WriteTo(pktStm);

                pktStm.Seek(0, SeekOrigin.Begin);
            }
            catch (ObjectDisposedException)
            {
                // host is disconnected, notify app
                DtmErrorArgs args = new DtmErrorArgs(new SocketException((int)SocketError.HostDown), DtmErrorSeverityFlags.Connection);
                if (SessionError != null)
                    SessionError(this, args);

                if (args.Cancel)
                {
                    Disconnect(DtmErrorFlags.ConnectionDropped);
                    return null;
                }
            }

            if (pktStm == null || pktStm.Length == 0)
            {
                // exchange failed
                if (SessionError != null)
                    SessionError(this, new DtmErrorArgs(new SocketException((int)SocketError.HostUnreachable), DtmErrorSeverityFlags.Critical));

                Disconnect(DtmErrorFlags.ReceivedBadData);
                return null;
            }

            return pktStm;
        }

        /// <summary>
        /// Used Post-Exchange to decrypt bytes received from the client
        /// </summary>
        /// 
        /// <param name="PacketStream">The stream containing the ciphertext</param>
        private void ReceiveMessage(Stream PacketStream)
        {
            if (!_isEstablished)
                throw new CryptoKeyExchangeException("DtmKex:Receive", "The VPN has not been established!", new InvalidOperationException());

            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            // store total bytes received
            _bytesReceived += pktHdr.PayloadLength;
            byte[] enc = new byte[pktHdr.PayloadLength];
            // get the encrypted data
            PacketStream.Read(enc, 0, enc.Length);
            // decrypt it using servers processor
            byte[] dec = SymmetricTransform(_cltSymProcessor, enc);
            // remove padding
            dec = UnwrapMessage(dec);

            // return the data
            if (DataReceived != null)
            {
                DtmDataReceivedArgs args = new DtmDataReceivedArgs(new MemoryStream(dec), pktHdr.PacketFlag);
                DataReceived(this, args);
            }
        }
        #endregion

        #region Send
        /// <summary>
        /// Used Post-Exchange to encrypt data before it is sent to the client
        /// </summary>
        /// 
        /// <param name="PacketStream">The stream containing the data to encrypt</param>
        /// <param name="MessageType">The <see cref="DtmMessageFlags"/> flag describing the message payload type; default is Text</param>
        /// 
        /// <exception cref="CryptoKeyExchangeException">Thrown if called before the key exchange has completed.</exception>
        public void Send(Stream PacketStream, DtmMessageFlags MessageType = DtmMessageFlags.Text)
        {
            if (!_isEstablished)
                throw new CryptoKeyExchangeException("DtmKex:Send", "The VPN has not been established!", new InvalidOperationException());

            byte[] enc;
            int len = (int)(PacketStream.Length - PacketStream.Position);
            byte[] data = new byte[len];

            // get the data
            PacketStream.Read(data, 0, data.Length);
            // append/prepend random
            data = WrapMessage(data, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt the data with the clients symmetric processor
            enc = SymmetricTransform(_srvSymProcessor, data);
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);

            // optional delay before transmission
            if (_dtmParameters.MaxMessageDelayMS > 0)
                SendWait(_dtmParameters.MaxMessageDelayMS);

            // send to client
            Transmit(DtmPacketFlags.Message, (short)MessageType, 0, pldStm);
        }
        #endregion

        #region Receive File
        /// <summary>
        /// Used Post-Exchange to setup a file transfer from the remote host
        /// </summary>
        /// 
        /// <param name="PacketStream">The stream containing the file transfer request</param>
        private void ReceiveFile(Stream PacketStream)
        {
            // asynchronous transfer by sending a file key and info, and running the entire transfer on another socket..
            if (!_isEstablished)
                throw new CryptoKeyExchangeException("DtmKex:ReceiveFile", "The VPN has not been established!", new InvalidOperationException());
            if (FileRequest == null)
                throw new CryptoKeyExchangeException("DtmKex:ReceiveFile", "The FileRequest and FileReceived must be connected to perform a file transfer, read the documentation!", new InvalidOperationException());
            if (FileReceived == null)
                throw new CryptoKeyExchangeException("DtmKex:ReceiveFile", "The FileRequest and FileReceived must be connected to perform a file transfer, read the documentation!", new InvalidOperationException());

            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            // read the packet
            byte[] enc = new byte[pktHdr.PayloadLength];
            // get the encrypted data
            PacketStream.Read(enc, 0, enc.Length);
            // decrypt it using client crypto processor
            byte[] dec = SymmetricTransform(_cltSymProcessor, enc);
            // remove padding
            dec = UnwrapMessage(dec);
            MemoryStream pktStm = new MemoryStream(dec);

            // get file info header
            DtmFileInfoSruct pktFi = new DtmFileInfoSruct(pktStm);
            // get the key
            KeyParams fileKey = KeyParams.DeSerialize(pktStm);

            // forward request to app
            DtmFileRequestArgs args = new DtmFileRequestArgs(pktFi.FileName);
            FileRequest(this, args);

            // accept file or refuse and exit; app must send back a valid path or cancel; if cancel, send a refuse notice which will signal the end of the transfer, otherwise store file path and port
            if (args.Cancel || string.IsNullOrEmpty(args.FilePath) || args.FilePath.Equals(pktFi.FileName) || !Directory.Exists(Path.GetDirectoryName(args.FilePath)))
            {
                // send refuse and exit
                Transmit(DtmPacketFlags.Transfer, (short)DtmTransferFlags.Refused, pktHdr.OptionFlag);
            }
            else
            {
                // create the files crypto processor
                ICipherMode fileSymProcessor = SymmetricInit(_cltIdentity.Session, fileKey);
                // enable parallel decryption
                int blockSize = ((int)MessageBufferSize - DtmPacketStruct.GetHeaderSize()) - ((int)MessageBufferSize - DtmPacketStruct.GetHeaderSize()) % ((CTR)fileSymProcessor).ParallelMinimumSize;
                ((CTR)fileSymProcessor).ParallelBlockSize = blockSize;

                // init the file transfer host
                DtmFileTransfer fileTransfer = new DtmFileTransfer(fileSymProcessor, pktHdr.OptionFlag, 1024, (int)FileBufferSize);
                fileTransfer.FileTransferred += new DtmFileTransfer.FileTransferredDelegate(OnFileReceived);
                fileTransfer.ProgressPercent += new DtmFileTransfer.ProgressDelegate(OnFileReceivedProgress);
                // add to dictionary
                _transQueue.TryAdd(pktHdr.OptionFlag, fileTransfer);

                try
                {
                    // start the transfer on a new thread
                    Task socketTask = Task.Factory.StartNew(() =>
                    {
                        fileTransfer.StartReceive(_clientSocket.RemoteAddress, (int)pktFi.OptionsFlag, args.FilePath);
                    });
                    socketTask.Wait(10);
                }
                catch (AggregateException ae)
                {
                    if (SessionError != null)
                        SessionError(this, new DtmErrorArgs(ae.GetBaseException(), DtmErrorSeverityFlags.Warning));
                }
            }
        }

        /// <summary>
        /// Fires when a file received operation has completed
        /// </summary>
        private void OnFileReceived(object owner, DtmPacketArgs args)
        {
            if (FileReceived != null)
                FileReceived(this, args);

            lock (_fileLock)
            {
                // ackowledge file received and cleanup
                Transmit(DtmPacketFlags.Transfer, (short)DtmTransferFlags.Received, args.OptionFlag);
                Wait(10);
                // close processor
                CloseTransfer(args.OptionFlag);
            }
        }

        /// <summary>
        /// Fires when a file receive operation completes
        /// </summary>
        private void OnFileReceivedProgress(object sender, System.ComponentModel.ProgressChangedEventArgs e)
        {
            if (FileProgressPercent != null)
                FileProgressPercent(this, e);
        }
        #endregion

        #region Send File
        /// <summary>
        /// Used to initialize the file transfer sequence.
        /// <para>Sends a file request with the file id, name, and size.</para>
        /// </summary>
        /// 
        /// <param name="FilePath">The full path to the file to send</param>
        public void SendFile(string FilePath)
        {
            // store file length
            long len = new FileInfo(FilePath).Length;
            // increment file id
            _fileCounter++;
            // get an open port
            int port = NetworkUtils.NextOpenPort();
            // create the file info header
            byte[] btInfo = new DtmFileInfoSruct(Path.GetFileName(FilePath), len, port).ToBytes();

            // create a new symmetric key 
            KeyParams fileKey = GenerateSymmetricKey(_srvIdentity.Session);
            MemoryStream keyStrm = (MemoryStream)KeyParams.Serialize(fileKey);
            // add the key
            btInfo = ArrayUtils.Concat(btInfo, keyStrm.ToArray());

            // wrap the request
            btInfo = WrapMessage(btInfo, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt with master
            btInfo = SymmetricTransform(_srvSymProcessor, btInfo);

            // initialize the files unique crypto processor
            ICipherMode fileSymProcessor = SymmetricInit(_srvIdentity.Session, fileKey);
            // tune for parallel processing
            int blockSize = ((int)MessageBufferSize - DtmPacketStruct.GetHeaderSize()) - ((int)MessageBufferSize - DtmPacketStruct.GetHeaderSize()) % ((CTR)fileSymProcessor).ParallelMinimumSize;
            ((CTR)fileSymProcessor).ParallelBlockSize = blockSize;

            // build the file transfer instance
            DtmFileTransfer fileTransfer = new DtmFileTransfer(fileSymProcessor, _fileCounter, 1024, (int)FileBufferSize);
            fileTransfer.FileTransferred += new DtmFileTransfer.FileTransferredDelegate(OnFileSent);
            fileTransfer.ProgressPercent += new DtmFileTransfer.ProgressDelegate(OnFileSentProgress);
            // add to dictionary
            _transQueue.TryAdd(_fileCounter, fileTransfer);

            // send header to the remote host in a file request
            Transmit(DtmPacketFlags.Transfer, (short)DtmTransferFlags.Request, _fileCounter, new MemoryStream(btInfo));

            // initiate with non-blocking listen
            fileTransfer.StartSend(_clientSocket.LocalAddress, port, FilePath);

            if (fileTransfer.IsConnected)
            {
                try
                {
                    // start on a new thread
                    Task socketTask = Task.Factory.StartNew(() =>
                    {
                        fileTransfer.SendFile();
                    });
                    socketTask.Wait(10);
                }
                catch (AggregateException ae)
                {
                    if (SessionError != null)
                        SessionError(this, new DtmErrorArgs(ae.GetBaseException(), DtmErrorSeverityFlags.Warning));
                }
            }
            else
            {
                // remove from pending and dispose
                CloseTransfer(_fileCounter);

                // alert app
                DtmErrorArgs args = new DtmErrorArgs(new SocketException((int)SocketError.ConnectionAborted), DtmErrorSeverityFlags.Connection);
                if (SessionError != null)
                    SessionError(this, args);

                if (args.Cancel)
                    Disconnect();
            }
        }

        /// <summary>
        /// Removes a file transfer instance from the queue
        /// </summary>
        private void CloseTransfer(long FileId)
        {
            lock (_fileLock)
            {
                if (_transQueue.ContainsKey(FileId))
                {
                    DtmFileTransfer fileTransfer = null;
                    _transQueue.TryRemove(FileId, out fileTransfer);

                    try
                    {
                        if (fileTransfer != null)
                            fileTransfer.Dispose();
                    }
                    catch { }
                }
            }
        }

        /// <summary>
        /// Fires when a file send operation completes
        /// </summary>
        private void OnFileSent(object owner, DtmPacketArgs args)
        {
            if (FileSent != null)
                FileSent(this, args);
        }

        /// <summary>
        /// File send progress event handler
        /// </summary>
        private void OnFileSentProgress(object sender, System.ComponentModel.ProgressChangedEventArgs e)
        {
            if (FileProgressPercent != null)
                FileProgressPercent(this, e);
        }
        #endregion

        #region Send/Receive
        /// <summary>
        /// Blocking transceiver; sends a packet and waits for a response.
        /// <para>For use with time sensitive data, that requires fast synchronous processing.
        /// Sent and received packets are not queued or buffered.</para>
        /// </summary>
        /// 
        /// <param name="DataStream">The payload data to send to the remote host</param>
        /// <param name="TimeOut">The number of milliseconds to wait before timing out (default is infinite)</param>
        /// 
        /// <returns>The return streams decrypted payload data, or a null or empty stream on failure</returns>
        /// 
        /// <exception cref="CryptoKeyExchangeException">Thrown if called before the key exchange has completed.</exception>
        public MemoryStream SendReceive(MemoryStream DataStream, int TimeOut = Timeout.Infinite)
        {
            if (!_isEstablished)
                throw new CryptoKeyExchangeException("DtmKex:SendReceive", "The VPN is not established!", new InvalidOperationException());

            byte[] data = DataStream.ToArray();
            // append/prepend random
            data = WrapMessage(data, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt the data with the clients symmetric processor
            byte[] enc = SymmetricTransform(_srvSymProcessor, data);
            // store total bytes sent
            _bytesSent += enc.Length;

            // optional delay before transmission
            if (_dtmParameters.MaxMessageDelayMS > 0)
                SendWait(_dtmParameters.MaxMessageDelayMS);

            // create the packet
            MemoryStream pktStm = new DtmPacketStruct(DtmPacketFlags.Message, enc.Length, _sndSequence, (short)DtmMessageFlags.Text).ToStream();
            pktStm.Seek(0, SeekOrigin.End);
            pktStm.Write(enc, 0, enc.Length);
            pktStm.Seek(0, SeekOrigin.Begin);
            // transmit data
            _clientSocket.Send(pktStm);
            _sndSequence++;

            // wait for response
            pktStm = BlockingReceive();
            if (pktStm == null)
                return null;

            // get the header
            DtmPacketStruct dtmHdr = new DtmPacketStruct(pktStm);
            // payload buffer
            data = new byte[dtmHdr.PayloadLength];
            // copy data to buffer
            pktStm.Write(data, 0, data.Length);
            // decrypt response
            data = SymmetricTransform(_cltSymProcessor, data);
            // remove padding
            data = UnwrapMessage(data);
            // increment rcv counter
            _rcvSequence++;
            // record encrypted byte count for resync
            _bytesReceived += dtmHdr.PayloadLength;

            return new MemoryStream(data);
        }
        #endregion
        #endregion

        #region Exchange Staging
        /* Functions are in order of execution. 
           The Create functions create a packet for transmission.
           The Process functions process the received packet. */

        /// <summary>
        /// Send the servers partial public identity structure <see cref="DtmIdentityStruct"/>.
        /// <para>The packet header; <see cref="DtmPacketStruct"/>, contains the message type, payload length, sequence number, and exchange state.
        /// The payload is the servers public identity field in a default DtmIdentityStruct structure.</para>
        /// </summary>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers public identity structure</returns>
        private MemoryStream CreateConnect()
        {
            // the option flag is used to describe minimum security level required from this instance
            int sec = (int)DtmParamSets.GetContext(_dtmParameters.OId);
            // create a partial id and add auth asymmetric and session params.
            MemoryStream sid = new DtmIdentityStruct(_srvIdentity.Identity, new byte[] { 0, 0, 0, 0 }, new DtmSessionStruct(), sec).ToStream();
            // stage completed
            _exchangeState = DtmExchangeFlags.Connect;

            return sid;
        }

        /// <summary>
        /// Processes the clients public identity field for preliminary authentication.
        /// <para>Process the clients partial Auth-Stage public identity structure; <see cref="DtmIdentityStruct"/></para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        /// 
        /// <remarks>
        /// The client auto-negotiates to the security level of the server (the host accepting the connection request).
        /// Fires the <see cref="IdentityReceived"/> event; returning the <see cref="DtmIdentityArgs"/> object containing the clients public id structure.
        /// <para>The session can be aborted by setting the DtmIdentityArgs Cancel flag to true.</para>
        /// </remarks>
        private void ProcessConnect(MemoryStream PacketStream)
        {
            _exchangeState = DtmExchangeFlags.Connect;
            // seek past header
            PacketStream.Seek(DtmPacketStruct.GetHeaderSize(), SeekOrigin.Begin);
            // get the clients id structure
            _cltIdentity = new DtmIdentityStruct(PacketStream);

            // pass it to the client, evaluate the id
            if (IdentityReceived != null)
            {
                DtmIdentityArgs args = new DtmIdentityArgs(DtmExchangeFlags.Connect, (long)DtmErrorFlags.ConnectionRefused, _cltIdentity);
                IdentityReceived(this, args);

                if (args.Cancel)
                {
                    // refuse the session; user can change disconnect flag
                    Disconnect((DtmErrorFlags)args.Flag);
                }
            }

            // synchronize security level with the server
            if (!_isServer)
            {
                // get the servers security context and compare it to ours
                DtmParamSets.SecurityContexts srvSec = (DtmParamSets.SecurityContexts)_cltIdentity.OptionFlag;
                DtmParamSets.SecurityContexts cltSec = DtmParamSets.GetContext(_dtmParameters.OId);

                if (cltSec != srvSec)
                {
                    // match servers security parameters
                    if (!NegotiateSecurity(srvSec))
                    {
                        // the negotiation failed
                        Disconnect(DtmErrorFlags.InternalError);
                    }
                    else
                    {
                        // notify user that security parameters has changed
                        if (SessionError != null)
                        {
                            DtmParamSets.SecurityContexts sxt = DtmParamSets.GetContext(_dtmParameters.OId);
                            DtmErrorArgs args = new DtmErrorArgs(new CryptoKeyExchangeException(string.Format("The Security context has changed: {0}", sxt.ToString())), DtmErrorSeverityFlags.Warning);
                            SessionError(this, args);

                            if (args.Cancel)
                            {
                                // give user a cancellation option
                                Disconnect(DtmErrorFlags.ConnectionRefused);
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// The remote server requires a security parameters negotiation to continue.
        /// <para>Evaluates the requested security parameter requirement from a server, 
        /// using the security context stored in the servers identity structure option flag.</para>
        /// </summary>
        /// 
        /// <param name="Context">The servers required security level</param>
        /// 
        /// <returns>Returns true if the negotiation succeeds</returns>
        private bool NegotiateSecurity(DtmParamSets.SecurityContexts Context)
        {
            // get the clients id structure
            DtmParamSets.SecurityContexts sxt = DtmParamSets.GetContext(_dtmParameters.OId);

            // note: only negotiate up as a security measure?
            if (Context == DtmParamSets.SecurityContexts.X1)
                _dtmParameters = (DtmParameters)DtmParamSets.DTMX11RNS1R2.DeepCopy();
            else if (Context == DtmParamSets.SecurityContexts.X2)
                _dtmParameters = (DtmParameters)DtmParamSets.DTMX21RNS1R2.DeepCopy();
            else if (Context == DtmParamSets.SecurityContexts.X3)
                _dtmParameters = (DtmParameters)DtmParamSets.DTMX31RNS1R1.DeepCopy();
            else if (Context == DtmParamSets.SecurityContexts.X4)
                _dtmParameters = (DtmParameters)DtmParamSets.DTMX41RNS1R1.DeepCopy();
            else
                return false; // error or failure

            // copy new security params
            _srvIdentity = new DtmIdentityStruct(_dtmHost.PublicId, _dtmParameters.AuthPkeId, _dtmParameters.AuthSession, 0);

            return true;
        }

        /// <summary>
        /// Send the servers full public identity structure <see cref="DtmIdentityStruct"/>; contains the public id field, the asymmetric parameters, and the symmetric session parameters.
        /// <para>The packet header; <see cref="DtmPacketStruct"/>, contains the message type, payload length, sequence number, and exchange state.
        /// The payload is the servers preliminary identity structure (DtmIdentityStruct), containing the public id field, the session key parameters <see cref="DtmSessionStruct"/>, and the
        /// Auth-Stage PKE parameters OId.</para>
        /// </summary>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers public identity structure</returns>
        private MemoryStream CreateInit()
        {
            // create a partial id and add auth asymmetric and session params
            MemoryStream sid = _srvIdentity.ToStream();
            // stage completed
            _exchangeState = DtmExchangeFlags.Init;

            return sid;
        }

        /// <summary>
        /// Processes the clients public identity and clients Auth-Stage PKE parameter set Id; <see cref="IAsymmetricParameters"/>.
        /// <para>Process the clients Auth-Stage public identity structure; <see cref="DtmIdentityStruct"/></para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        /// 
        /// <remarks>Fires the <see cref="IdentityReceived"/> event; returning the <see cref="DtmIdentityArgs"/> object containing the clients public id structure.
        /// <para>The session can be aborted by setting the DtmIdentityArgs Cancel flag to true.</para>
        /// </remarks>
        private void ProcessInit(MemoryStream PacketStream)
        {
            _exchangeState = DtmExchangeFlags.Init;
            // seek past header
            PacketStream.Seek(DtmPacketStruct.GetHeaderSize(), SeekOrigin.Begin);
            // get the clients id structure
            _cltIdentity = new DtmIdentityStruct(PacketStream);
            // get client asymmetric params
            _cltAsmParams = GetAsymmetricParams(_cltIdentity.PkeId);
            // store the auth session
            _cltAuthSession = _cltIdentity.Session;
            // store public id
            _remoteIdentity.PublicId = _cltIdentity.Identity;

            // pass it to the client again, so it can be refused on basis of params
            if (IdentityReceived != null)
            {
                DtmIdentityArgs args = new DtmIdentityArgs(DtmExchangeFlags.Init, (long)DtmErrorFlags.ConnectionRefused, _cltIdentity);
                IdentityReceived(this, args);

                if (args.Cancel)
                {
                    // refuse the session
                    Disconnect((DtmErrorFlags)args.Flag);
                }
            }
        }

        /// <summary>
        /// Send the servers Auth-Stage Asymmetric Public key; <see cref="IAsymmetricKey"/>, built using the PKE params id from the servers identity structure.
        /// <para>The packet header; <see cref="DtmPacketStruct"/>, contains the message type, payload length, sequence number, and exchange state.
        /// The payload is the servers Auth-Stage asymmetric Public Key.</para>
        /// </summary>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers Auth-Stage asymmetric Public Key</returns>
        private MemoryStream CreatePreAuth()
        {
            // server asym params
            _srvAsmParams = GetAsymmetricParams(_srvIdentity.PkeId);
            // generate the servers auth-stage key pair
            _authKeyPair = GenerateAsymmetricKeyPair(_srvAsmParams);
            // serialize servers public key
            MemoryStream pbk = _authKeyPair.PublicKey.ToStream();
            // stage completed
            _exchangeState = DtmExchangeFlags.PreAuth;

            return pbk;
        }

        /// <summary>
        /// Processes the clients Auth-Stage <see cref="IAsymmetricKey">AsymmetricKey</see> Public key.
        /// <para>Stores the clients Auth-Stage Asymmetric Public Key.</para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessPreAuth(MemoryStream PacketStream)
        {
            _exchangeState = DtmExchangeFlags.PreAuth;
            // seek past header
            PacketStream.Seek(DtmPacketStruct.GetHeaderSize(), SeekOrigin.Begin);
            // get client params
            _cltAsmParams = GetAsymmetricParams(_cltIdentity.PkeId);
            // store client public key
            _cltPublicKey = GetAsymmetricPublicKey(PacketStream, _cltAsmParams);
        }

        /// <summary>
        /// Send the servers Auth-Stage Symmetric <see cref="KeyParams"/>, encrypted with the clients Public Key.
        /// <para>The packet header; <see cref="DtmPacketStruct"/>, contains the message type, payload length, sequence number, and exchange state.
        /// The payload is the servers Auth-Stage Symmetric KeyParams, encrypted with the clients Asymmetric Public Key.</para>
        /// </summary>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers Auth-Stage Symmetric Key</returns>
        private MemoryStream CreateAuthEx()
        {
            // create a session key based on servers symmetric session params
            _srvKeyParams = GenerateSymmetricKey(_srvIdentity.Session);
            // serialize the keyparams structure
            byte[] srvKrw = ((MemoryStream)KeyParams.Serialize(_srvKeyParams)).ToArray();
            // encrypt the servers symmetric key with the clients public key
            byte[] enc = AsymmetricEncrypt(_cltAsmParams, _cltPublicKey, srvKrw);
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);
            // stage completed
            _exchangeState = DtmExchangeFlags.AuthEx;

            // optional delay before transmission
            if (_dtmParameters.MaxSymKeyDelayMS > 0)
                SendWait(_dtmParameters.MaxSymKeyDelayMS, _dtmParameters.MaxSymKeyDelayMS / 2);

            return pldStm;
        }

        /// <summary>
        /// Processes and stores the clients Auth-Stage Symmetric <see cref="KeyParams"/>, 
        /// decrypted with the servers <see cref="IAsymmetricKeyPair">Asymmetric KeyPair</see>.
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessAuthEx(MemoryStream PacketStream)
        {
            _exchangeState = DtmExchangeFlags.AuthEx;
            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            // read the data
            byte[] data = new byte[pktHdr.PayloadLength];
            PacketStream.Read(data, 0, data.Length);
            // decrypt the symmetric key
            byte[] dec = AsymmetricDecrypt(_srvAsmParams, _authKeyPair, data);
            // deserialize the keyparams structure
            _cltKeyParams = KeyParams.DeSerialize(new MemoryStream(dec));
        }

        /// <summary>
        /// Sends the servers private identity; <see cref="DtmIdentityStruct"/>, encrypted with the servers Symmetric Key.
        /// </summary>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers private identity</returns>
        private MemoryStream CreateAuth()
        {
            // send secret id and return auth status in options flag
            _srvIdentity.Identity = _dtmHost.SecretId;
            // create the servers auth-stage symmetric cipher
            _srvSymProcessor = SymmetricInit(_srvIdentity.Session, _srvKeyParams);
            byte[] data = _srvIdentity.ToBytes();
            // wrap the id with random
            data = WrapMessage(data, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt the identity
            byte[] enc = SymmetricTransform(_srvSymProcessor, data);
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);
            // stage completed
            _exchangeState = DtmExchangeFlags.Auth;

            return pldStm;
        }

        /// <summary>
        /// Process the clients private identity.
        /// <para>Decrypts and stores the clients private identity using the clients Auth-Stage Symmetric Key.</para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessAuth(MemoryStream PacketStream)
        {
            _exchangeState = DtmExchangeFlags.Auth;
            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            byte[] data = new byte[pktHdr.PayloadLength];
            PacketStream.Read(data, 0, data.Length);
            // create the clients auth-stage symmetric cipher
            _cltSymProcessor = SymmetricInit(_cltIdentity.Session, _cltKeyParams);
            // decrypt the payload
            byte[] dec = SymmetricTransform(_cltSymProcessor, data);
            // remove random padding
            dec = UnwrapMessage(dec);
            // get the clients private id
            _cltIdentity = new DtmIdentityStruct(new MemoryStream(dec));

            // notify user
            if (IdentityReceived != null)
            {
                DtmIdentityArgs args = new DtmIdentityArgs(DtmExchangeFlags.Auth, (long)DtmErrorFlags.ConnectionRefused, _cltIdentity);
                IdentityReceived(this, args);

                if (args.Cancel)
                {
                    // refuse the session
                    Disconnect((DtmErrorFlags)args.Flag);
                }
            }
        }

        /// <summary>
        /// Send the servers Primary-Stage session parameters in a <see cref="DtmIdentityStruct"/> structure.
        /// <para>The packet header; <see cref="DtmPacketStruct"/>, contains the message type, payload length, sequence number, and exchange state.
        /// The payload is the servers identity structure (DtmIdentityStruct), containing the secret id field, the session key parameters <see cref="DtmSessionStruct"/>, and the
        /// primary-stage PKE parameters Id.</para>
        /// </summary>
        /// 
        /// <returns>A raw packet containing the packet header, and the servers private identity</returns>
        private MemoryStream CreateSync()
        {
            _exchangeState = DtmExchangeFlags.Sync;
            // change to primary parameters
            _srvIdentity = new DtmIdentityStruct(_dtmHost.SecretId, _dtmParameters.PrimaryPkeId, _dtmParameters.PrimarySession, 0);
            // serialize identity
            byte[] data = _srvIdentity.ToBytes();
            // wrap the id with random
            data = WrapMessage(data, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt with servers session key
            byte[] enc = SymmetricTransform(_srvSymProcessor, data);
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);
            // stage completed
            _exchangeState = DtmExchangeFlags.Sync;

            return pldStm;
        }

        /// <summary>
        /// Process the clients identity structure <see cref="DtmIdentityStruct"/>.
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessSync(MemoryStream PacketStream)
        {
            _exchangeState = DtmExchangeFlags.Sync;
            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            // read the data
            byte[] data = new byte[pktHdr.PayloadLength];
            PacketStream.Read(data, 0, data.Length);
            // use clients symmetric key to decrypt data
            byte[] dec = SymmetricTransform(_cltSymProcessor, data);
            // remove random padding
            dec = UnwrapMessage(dec);
            // get the identity
            _cltIdentity = new DtmIdentityStruct(dec);
            // store secret id
            _remoteIdentity.SecretId = _cltIdentity.Identity;

            // pass id to the client, include oid
            if (IdentityReceived != null)
            {
                DtmIdentityArgs args = new DtmIdentityArgs(DtmExchangeFlags.Sync, (long)DtmErrorFlags.ConnectionRefused, _cltIdentity);
                IdentityReceived(this, args);

                if (args.Cancel)
                {
                    // refuse the session
                    Disconnect((DtmErrorFlags)args.Flag);
                }
            }

            // get the params oid
            _cltAsmParams = GetAsymmetricParams(_cltIdentity.PkeId);
        }

        /// <summary>
        /// Sends the servers Primary-Stage <see cref="IAsymmetricKey">AsymmetricKey</see> Public key.
        /// </summary>
        /// 
        /// <returns>A Stream containing the raw packet data</returns>
        private MemoryStream CreatePrimeEx()
        {
            // get the cipher parameters
            _srvAsmParams = GetAsymmetricParams(_srvIdentity.PkeId);
            // create new public key pair
            _primKeyPair = GenerateAsymmetricKeyPair(_srvAsmParams);
            // serailize the public key
            byte[] keyBytes = _primKeyPair.PublicKey.ToBytes();
            // pad public key
            keyBytes = WrapMessage(keyBytes, _dtmParameters.MaxAsmKeyAppend, _dtmParameters.MaxAsmKeyPrePend);
            // encrypt the servers public key
            byte[] enc = SymmetricTransform(_srvSymProcessor, keyBytes);
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);
            // stage completed
            _exchangeState = DtmExchangeFlags.PrimeEx;

            // optional wait random timeout
            if (_dtmParameters.MaxAsmKeyDelayMS > 0)
                SendWait(_dtmParameters.MaxAsmKeyDelayMS, _dtmParameters.MaxAsmKeyDelayMS / 2);

            return pldStm;
        }

        /// <summary>
        /// Processes the clients Primary-Stage <see cref="IAsymmetricKey">AsymmetricKey</see> Public key.
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessPrimeEx(MemoryStream PacketStream)
        {
            _exchangeState = DtmExchangeFlags.PrimeEx;
            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            // read the data
            byte[] data = new byte[pktHdr.PayloadLength];
            PacketStream.Read(data, 0, data.Length);
            // use clients symmetric key to decrypt data
            byte[] dec = SymmetricTransform(_cltSymProcessor, data);
            // remove padding
            dec = UnwrapMessage(dec);
            MemoryStream cltStream = new MemoryStream(dec);
            // store the clients public key
            _cltPublicKey = GetAsymmetricPublicKey(cltStream, _cltAsmParams);
        }

        /// <summary>
        /// Sends the servers primary-stage Symmetric <see cref="KeyParams"/>.
        /// </summary>
        /// 
        /// <returns>A Stream containing the raw packet data</returns>
        private MemoryStream CreatePrimary()
        {
            // create the primary session key
            KeyParams tmpKey = GenerateSymmetricKey(_srvIdentity.Session);
            // serialize the keyparams structure
            byte[] srvKrw = ((MemoryStream)KeyParams.Serialize(tmpKey)).ToArray();
            // encrypt the symmetric key with the primary asymmetric cipher
            byte[] enc = AsymmetricEncrypt(_cltAsmParams, _cltPublicKey, srvKrw);
            // pad the encrypted key with random
            enc = WrapMessage(enc, _dtmParameters.MaxSymKeyAppend, _dtmParameters.MaxSymKeyPrePend);
            // encrypt the result with the auth symmetric key
            enc = SymmetricTransform(_srvSymProcessor, enc);
            // clear auth key
            _srvKeyParams.Dispose();
            // swap to primary symmetric key
            _srvKeyParams = tmpKey;
            // payload container
            MemoryStream pldStm = new MemoryStream(enc);
            // stage completed
            _exchangeState = DtmExchangeFlags.Primary;

            return pldStm;
        }

        /// <summary>
        /// Processes and stores the clients primary-stage Symmetric <see cref="KeyParams"/>, 
        /// decrypted with the servers <see cref="IAsymmetricKeyPair">Asymmetric KeyPair</see>.
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessPrimary(MemoryStream PacketStream)
        {
            _exchangeState = DtmExchangeFlags.Primary;
            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            // read the data
            byte[] data = new byte[pktHdr.PayloadLength];
            PacketStream.Read(data, 0, data.Length);
            // decrypt using the auth stage symmetric key
            data = SymmetricTransform(_cltSymProcessor, data);
            // remove random padding
            data = UnwrapMessage(data);
            // decrypt the symmetric key using the primary asymmetric cipher
            byte[] dec = AsymmetricDecrypt(_srvAsmParams, _primKeyPair, data);
            // clear auth key
            _cltKeyParams.Dispose();
            // deserialize the primary session key
            _cltKeyParams = KeyParams.DeSerialize(new MemoryStream(dec));
        }

        /// <summary>
        /// Notify that the VPN is established
        /// </summary>
        /// 
        /// <returns>A Stream containing the raw packet data</returns>
        private MemoryStream CreateEstablish()
        {
            MemoryStream pktStm = new DtmPacketStruct(DtmPacketFlags.Exchange, 0, _sndSequence, (short)DtmExchangeFlags.Established).ToStream();

            // notify
            if (PacketSent != null)
                PacketSent(this, new DtmPacketArgs((short)_exchangeState, pktStm.Length));

            // stage completed
            _exchangeState = DtmExchangeFlags.Established;

            return pktStm;
        }

        /// <summary>
        /// The VPN is two-way established.
        /// <para>Note that SessionEstablished event is used, it is expected that processing will continue externally.
        /// In this case the post-exchange symmetric cipher instances are not initialized internally, 
        /// and the Send and Receive methods will throw an error, i.e. you can use either the event or the internal processors.</para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A Stream containing the raw packet data</param>
        private void ProcessEstablish(MemoryStream PacketStream)
        {
            _exchangeState = DtmExchangeFlags.Established;
            // clear the auth processors
            _srvSymProcessor.Dispose();
            _cltSymProcessor.Dispose();

            // initialize the Send/Receive encryption ciphers
            _srvSymProcessor = SymmetricInit(_srvIdentity.Session, _srvKeyParams);
            _cltSymProcessor = SymmetricInit(_cltIdentity.Session, _cltKeyParams);

            // one or the other
            if (SessionEstablished != null)
            {
                // app can continue processing out of class; if this class is to be disposed, you must set the DestroyEngine flag to false in the constructor 
                DtmEstablishedArgs args = new DtmEstablishedArgs(_clientSocket.Client, _srvSymProcessor, _cltSymProcessor, 0);
                SessionEstablished(this, args);
            }

            _isEstablished = true;
        }
        #endregion

        #region Forward Secrecy
        /// <summary>
        /// Initiates a forward key exchange across an encrypted channel.
        /// <para>A key request is sent to the remote host; the remote host can either forward a new key or decline the operation.
        /// When a new forward session key is received, the KeyRequested event fires, allowing the application to set the 
        /// key valid lifetime parameters. Once both keys have been received and the transaction has completed, 
        /// the KeySynchronized event is fired, and the keys are stored in the ForwardSessionKey and the ReturnSessionKey properties.
        /// The RatchetStream flag triggers an immediate re-keying of the symmetric crypto processors.</para>
        /// </summary>
        /// 
        /// <param name="RatchetStream">Setting the flag to <c>true</c> triggers the re-keying of the symmetric crypto processors</param>
        public void ForwardKeyRequest(bool RatchetStream = false)
        {
            if (!_isEstablished)
                throw new CryptoKeyExchangeException("DtmKex:ForwardKeyRequest", "The VPN has not been established!", new InvalidOperationException());
            if (KeySynchronized == null)
                throw new CryptoKeyExchangeException("DtmKex:ForwardKeyRequest", "The KeySynchronized event is not defined!", new InvalidOperationException());

            long excFlag = (long)(RatchetStream == true ? DtmForwardingFlags.RatchetRequest : DtmForwardingFlags.ForwardRequest);
            // send the request asynchronously
            Transmit(DtmPacketFlags.Forwarding, (short)DtmForwardingFlags.KeyRequest, excFlag);
        }
        
        /// <summary>
        /// Process the key request
        /// </summary>
        private void ProcessKeyRequest(Stream PacketStream)
        {
            // key forwarding is not enabled
            if (KeySynchronized == null)
            {
                // not enabled on this system, refuse it
                Transmit(DtmPacketFlags.Forwarding, (short)DtmForwardingFlags.KeyRefused);

                // notify the app
                if (SessionError != null)
                {
                    DtmErrorArgs args = new DtmErrorArgs(new CryptoKeyExchangeException("DtmKex:ProcessKeyRequest", "The remote host has sent a forward key!", new InvalidOperationException()), DtmErrorSeverityFlags.Warning);
                    SessionError(this, args);
                }
            }
            else
            {
                DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
                short excFlag = (short)pktHdr.OptionFlag;
                long lifespan = 0;
                long optFlag = 0;

                // notify app; event args pass forward exchange params, params are dictated by responder
                DtmKeyRequestedArgs args = new DtmKeyRequestedArgs(excFlag);
                if (KeyRequested != null)
                {
                    KeyRequested(this, args);

                    lifespan = args.LifeSpan;
                    optFlag = args.OptionsFlag;
                }

                if (args.Cancel)
                {
                    // notify operation was cancelled
                    Transmit(DtmPacketFlags.Forwarding, (short)DtmForwardingFlags.KeyRefused);
                }
                else
                {
                    // create the forward session key
                    KeyParams key = GenerateSymmetricKey(_srvIdentity.Session);
                    _fwdSessionKey = new DtmForwardKeyStruct(key, _srvIdentity.Session, lifespan, excFlag, optFlag);
                    // append/prepend random
                    byte[] data = WrapMessage(_fwdSessionKey.ToBytes(), _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
                    // encrypt the data with the clients symmetric processor
                    byte[] enc = SymmetricTransform(_srvSymProcessor, data);
                    // payload container
                    MemoryStream pldStm = new MemoryStream(enc);

                    // send the key
                    Transmit(DtmPacketFlags.Forwarding, (short)DtmForwardingFlags.KeyResponse, lifespan, pldStm);
                }
            }
        }

        /// <summary>
        /// Process the return key, and send our key
        /// </summary>
        private void ProcessKeyResponse(Stream PacketStream)
        {
            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            // store total bytes received
            _bytesReceived += pktHdr.PayloadLength;
            // get the encrypted data
            byte[] enc = new byte[pktHdr.PayloadLength];
            PacketStream.Read(enc, 0, enc.Length);
            // decrypt it using clients crypto processor
            byte[] dec = SymmetricTransform(_cltSymProcessor, enc);
            // remove padding
            dec = UnwrapMessage(dec);
            // get the return session key
            _retSessionKey = new DtmForwardKeyStruct(dec);

            short excFlag = _retSessionKey.Instruction;
            long lifespan = _retSessionKey.LifeSpan;
            long optFlag = _retSessionKey.OptionsFlag;

            // notify app; parameter selection is passive, node granting forward session dictates terms
            DtmKeyRequestedArgs args = new DtmKeyRequestedArgs();
            if (KeyRequested != null)
            {
                KeyRequested(this, args);
            }

            if (args.Cancel)
            {
                // notify operation cancelled
                Transmit(DtmPacketFlags.Forwarding, (short)DtmForwardingFlags.KeyRefused);
            }
            else
            {
                // create the forward session key
                KeyParams key = GenerateSymmetricKey(_srvIdentity.Session);
                // requestor mirrors exchange options
                _fwdSessionKey = new DtmForwardKeyStruct(key, _srvIdentity.Session, lifespan, excFlag, optFlag);
                // append/prepend random
                byte[] data = WrapMessage(_fwdSessionKey.ToBytes(), _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
                // encrypt the data with the servers symmetric processor
                enc = SymmetricTransform(_srvSymProcessor, data);
                // payload container
                MemoryStream pldStm = new MemoryStream(enc);
                // send the key
                Transmit(DtmPacketFlags.Forwarding, (short)DtmForwardingFlags.KeyReturn, 0, pldStm);
            }
        }

        /// <summary>
        /// Process the return key, and notify app
        /// </summary>
        private void ProcessKeyReturn(Stream PacketStream)
        {
            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            // store total bytes received
            _bytesReceived += pktHdr.PayloadLength;
            // get the encrypted data
            byte[] enc = new byte[pktHdr.PayloadLength];
            PacketStream.Read(enc, 0, enc.Length);
            // decrypt it using clients crypto processor
            byte[] dec = SymmetricTransform(_cltSymProcessor, enc);
            // remove padding
            dec = UnwrapMessage(dec);
            // get the session key
            _retSessionKey = new DtmForwardKeyStruct(dec);

            // send ack to trigger sync event on remote
            Transmit(DtmPacketFlags.Forwarding, (short)DtmForwardingFlags.KeySynchronized);

            // keys are synced, notify app
            DtmKeySynchronizedArgs args = new DtmKeySynchronizedArgs(_fwdSessionKey, _retSessionKey);
            KeySynchronized(this, args);

            if (args.Cancel)
            {
                // notify operation was cancelled
                Transmit(DtmPacketFlags.Forwarding, (short)DtmForwardingFlags.KeyRefused);
            }
            else
            {
                // ratchet up the stream
                if ((DtmForwardingFlags)_fwdSessionKey.Instruction == DtmForwardingFlags.RatchetRequest)
                {
                    // load the new keys
                    LoadSession(_fwdSessionKey, _retSessionKey);
                }
            }
        }

        /// <summary>
        /// Keys are synchronized, notify app
        /// </summary>
        private void ProcessKeySynchronized(Stream PacketStream)
        {
            DtmKeySynchronizedArgs args = new DtmKeySynchronizedArgs(_fwdSessionKey, _retSessionKey);
            KeySynchronized(this, args);

            if (args.Cancel)
            {
                // notify operation was cancelled
                Transmit(DtmPacketFlags.Forwarding, (short)DtmForwardingFlags.KeyRefused);
            }
            else
            {
                // ratchet up the stream
                if ((DtmForwardingFlags)_fwdSessionKey.Instruction == DtmForwardingFlags.RatchetRequest)
                {
                    // load the new keys
                    LoadSession(_fwdSessionKey, _retSessionKey);
                }
            }
        }
        #endregion

        #region KeepAlive
        /// <summary>
        /// Begins the keep alive timer
        /// </summary>
        private void StartPulse()
        {
            _pulseTimer = new System.Timers.Timer();
            _pulseTimer.Elapsed += new ElapsedEventHandler(OnTimerPulse);
            // 1 second intervals
            _pulseTimer.Interval = PULSEINTERVAL;
            _pulseTimer.Start();
        }

        /// <summary>
        /// Stops the keep alive timer
        /// </summary>
        private void StopPulse()
        {
            if (_pulseTimer != null)
            {
                _pulseTimer.Stop();
                _pulseTimer.Dispose();
            }
        }

        /// <summary>
        /// The keep alive timer event handler
        /// </summary>
        private void OnTimerPulse(object sender, ElapsedEventArgs e)
        {
            _pulseCounter++;

            // default trigger is 30 seconds without a keep alive
            if (_pulseCounter > ConnectionTimeOut)
            {
                if (_autoReconnect)
                {
                    // attempt to reconnect
                    if (!Reconnect())
                    {
                        // connection unvailable
                        if (SessionError != null)
                        {
                            DtmErrorArgs args = new DtmErrorArgs(new SocketException((int)SocketError.ConnectionReset), DtmErrorSeverityFlags.Critical);
                            SessionError(this, args);
                            Disconnect(DtmErrorFlags.ConnectionTimedOut);
                        }
                    }
                    else
                    {
                        // resync the crypto stream
                        Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.DataLost);
                    }
                }
                else
                {
                    // possible connection dropped, alert app
                    if (SessionError != null)
                    {
                        DtmErrorArgs args = new DtmErrorArgs(new SocketException((int)SocketError.ConnectionReset), DtmErrorSeverityFlags.Critical);
                        SessionError(this, args);

                        if (args.Cancel)
                            Disconnect(DtmErrorFlags.ConnectionTimedOut);
                    }
                }
            }
            else
            {
                Transmit(DtmPacketFlags.Service, (short)DtmServiceFlags.KeepAlive);
            }
        }
        #endregion

        #region Reconnect
        /// <summary>
        /// Attempt to reconnect to the remote host
        /// </summary>
        /// 
        /// <returns>Returns true if connected</returns>
        public bool Reconnect()
        {
            if (_isDisconnecting)
                return false;

            try
            {
                if (_clientSocket.IsConnected)
                    _clientSocket.Close();
            }
            catch { }

            try
            {
                if (_isServer)
                {
                    _clientSocket.Listen(_clientSocket.LocalAddress, _clientSocket.LocalPort);

                    return _clientSocket.IsConnected;
                }
                else
                {
                    _clientSocket.Connect(_clientSocket.LocalAddress, _clientSocket.LocalPort, 10000);

                    return _clientSocket.IsConnected;
                }

            }
            catch
            {
                return false;
            }
        }
        #endregion

        #region Resync
        /// <summary>
        /// Creates a Resync packet.
        /// <para>The packet contains the encrypted identity field, 
        /// used to test for a successful resyning of the crypto stream.</para>
        /// </summary>
        /// 
        /// <returns>A resync packet payload</returns>
        private MemoryStream CreateResync()
        {
            // wrap the id
            byte[] data = WrapMessage(_srvIdentity.Identity, _dtmParameters.MaxMessageAppend, _dtmParameters.MaxMessagePrePend);
            // encrypt with servers session key
            byte[] enc = SymmetricTransform(_srvSymProcessor, data);

            return new MemoryStream(enc);
        }

        /// <summary>
        /// Used to process a resync response.
        /// <para>The remote host has sent the number of bytes encrypted as the OptionFlag in the DtmPacket.
        /// The resynchronization of the crypto stream involves first encrypting an equal sized array, 
        /// and then testing for validity by decrypting the payload and comparing it to the stored client id.
        /// If the Resync fails, the client Disconnects, notifies the application, and performs a teardown of the VPN.</para>
        /// </summary>
        /// 
        /// <param name="PacketStream">A resync packet</param>
        private void ProcessResync(MemoryStream PacketStream)
        {
            // get the header
            DtmPacketStruct pktHdr = new DtmPacketStruct(PacketStream);
            int len = (int)(pktHdr.OptionFlag - pktHdr.PayloadLength - _bytesReceived);

            if (len > 0)
            {
                byte[] pad = new byte[len];
                // sync the cipher stream
                SymmetricTransform(_cltSymProcessor, pad);
            }
            else if (len < 0)
            {
                // can't resync, alert user and disconnect
                DtmErrorArgs args = new DtmErrorArgs(new InvalidDataException("The data stream could not be resynced, connection aborted!"), DtmErrorSeverityFlags.Critical);
                if (SessionError != null)
                    SessionError(this, args);

                Disconnect(DtmErrorFlags.UnrecoverableDataLoss);
                return;
            }

            // read the packet
            byte[] data = new byte[pktHdr.PayloadLength];
            // get the encrypted data
            PacketStream.Read(data, 0, data.Length);
            // decrypt the payload
            byte[] id = SymmetricTransform(_cltSymProcessor, data);
            // remove random padding
            id = UnwrapMessage(id);

            // compare to stored id
            if (!ArrayUtils.AreEqual(id, _cltIdentity.Identity))
            {
                // resync failed, abort connection
                DtmErrorArgs args = new DtmErrorArgs(new InvalidDataException("The data stream could not be resynced, connection aborted!"), DtmErrorSeverityFlags.Critical);
                if (SessionError != null)
                    SessionError(this, args);

                Disconnect(DtmErrorFlags.UnrecoverableDataLoss);
                return;
            }
        }
        #endregion

        #region Crypto
        /// <summary>
        /// Decrypt an array with an asymmetric cipher
        /// </summary>
        private byte[] AsymmetricDecrypt(IAsymmetricParameters Parameters, IAsymmetricKeyPair KeyPair, byte[] Data)
        {
            using (IAsymmetricCipher cipher = GetAsymmetricCipher(Parameters))
            {
                if (cipher.GetType().Equals(typeof(NTRUEncrypt)))
                    ((NTRUEncrypt)cipher).Initialize(KeyPair);
                else
                    cipher.Initialize(KeyPair.PrivateKey);

                return cipher.Decrypt(Data);
            }
        }

        /// <summary>
        /// Encrypt an array with an asymmetric cipher
        /// </summary>
        private byte[] AsymmetricEncrypt(IAsymmetricParameters Parameters, IAsymmetricKey PublicKey, byte[] Data)
        {
            using (IAsymmetricCipher cipher = GetAsymmetricCipher(Parameters))
            {
                cipher.Initialize(PublicKey);
                return cipher.Encrypt(Data);
            }
        }

        /// <summary>
        /// Generat an asymmetric key-pair
        /// </summary>
        private IAsymmetricKeyPair GenerateAsymmetricKeyPair(IAsymmetricParameters Parameters)
        {
            using (IAsymmetricGenerator gen = GetAsymmetricGenerator(Parameters))
                _authKeyPair = gen.GenerateKeyPair();

            return (IAsymmetricKeyPair)_authKeyPair.Clone();
        }

        /// <summary>
        /// Generate a symmetric key
        /// </summary>
        private KeyParams GenerateSymmetricKey(DtmSessionStruct Session)
        {
            return new KeyParams(m_rndGenerator.GetBytes(Session.KeySize), m_rndGenerator.GetBytes(Session.IvSize));
        }

        /// <summary>
        /// Initialize the symmetric cipher
        /// </summary>
        private ICipherMode SymmetricInit(DtmSessionStruct Session, KeyParams Key)
        {
            ICipherMode cipher = GetSymmetricCipher(Session);
            cipher.Initialize(true, Key);

            return cipher;
        }

        /// <summary>
        /// Transform an array with the symmetric cipher
        /// </summary>
        private byte[] SymmetricTransform(ICipherMode Cipher, byte[] Data)
        {
            byte[] ptext = new byte[Data.Length];
            Cipher.Transform(Data, ptext);

            return ptext;
        }
        #endregion

        #region Helpers
        /// <summary>
        /// Parses message array for a padding delimiter
        /// </summary>
        /// 
        /// <param name="Message">The message data array</param>
        /// <param name="Delimiter">The delimiter array</param>
        /// 
        /// <returns>The zero based starting position of the delimiter, otherwise -1</returns>
        private int ContainsDelimiter(byte[] Message, byte[] Delimiter)
        {
            for (int i = 0; i < Message.Length; i++)
            {
                if (Message[i] == Delimiter[0])
                {
                    if (Message.Length >= i + Delimiter.Length)
                    {
                        for (int j = 1; j < Delimiter.Length; j++)
                        {
                            if (Message[i + j] != Delimiter[j])
                                break;
                            else if (j == Delimiter.Length - 1)
                                return i;
                        }
                    }
                }
            }

            return -1;
        }

        /// <summary>
        /// Creates a serialized request packet (DtmPacket)
        /// </summary>
        private MemoryStream CreateRequest(DtmPacketFlags Message, short State, int Sequence = 0)
        {
            return new DtmPacketStruct(Message, 0, 0, State).ToStream();
        }

        /// <summary>
        /// Get the asymmetric cipher instance
        /// </summary>
        /// 
        /// <param name="Parameters">The cipher parameters</param>
        /// 
        /// <returns>The cipher instance</returns>
        private IAsymmetricCipher GetAsymmetricCipher(IAsymmetricParameters Parameters)
        {
            IAsymmetricCipher cipher = null;

            try
            {
                if (Parameters.GetType().Equals(typeof(NTRUParameters)))
                    cipher = new NTRUEncrypt((NTRUParameters)Parameters);
                else if (Parameters.GetType().Equals(typeof(MPKCParameters)))
                    cipher = new MPKCEncrypt((MPKCParameters)Parameters);
                else if (Parameters.GetType().Equals(typeof(RLWEParameters)))
                    cipher = new RLWEEncrypt((RLWEParameters)Parameters);

                return cipher;
            }
            catch (Exception ex)
            {
                throw new CryptoKeyExchangeException("DtmKex:GetAsymmetricCipher", "The cipher could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Get the asymmetric generator instance
        /// </summary>
        /// 
        /// <param name="Parameters">The cipher parameters</param>
        /// 
        /// <returns>The generator instance</returns>
        private IAsymmetricGenerator GetAsymmetricGenerator(IAsymmetricParameters Parameters)
        {
            IAsymmetricGenerator gen = null;

            try
            {
                if (Parameters.GetType().Equals(typeof(NTRUParameters)))
                    gen = new NTRUKeyGenerator((NTRUParameters)Parameters);
                else if (Parameters.GetType().Equals(typeof(MPKCParameters)))
                    gen = new MPKCKeyGenerator((MPKCParameters)Parameters);
                else if (Parameters.GetType().Equals(typeof(RLWEParameters)))
                    gen = new RLWEKeyGenerator((RLWEParameters)Parameters);

                return gen;
            }
            catch (Exception ex)
            {
                throw new CryptoKeyExchangeException("DtmKex:GetAsymmetricGenerator", "The generator could not be loaded!", ex);
            }
        }

        /// <summary>
        /// Get the asymmetric parameters from a byte array
        /// </summary>
        /// 
        /// <param name="Data">The encoded parameters</param>
        /// 
        /// <returns>The asymmetric parameters</returns>
        private IAsymmetricParameters GetAsymmetricParams(byte[] Data)
        {
            IAsymmetricParameters param = null;

            try
            {
                if (Data.Length > 4)
                {
                    if (Data[0] == (byte)AsymmetricEngines.McEliece)
                        param = new MPKCParameters(Data);
                    else if (Data[0] == (byte)AsymmetricEngines.NTRU)
                        param = new NTRUParameters(Data);
                    else if (Data[0] == (byte)AsymmetricEngines.RingLWE)
                        param = new RLWEParameters(Data);
                }
                else
                {
                    if (Data[0] == (byte)AsymmetricEngines.McEliece)
                        param = MPKCParamSets.FromId(Data);
                    else if (Data[0] == (byte)AsymmetricEngines.NTRU)
                        param = NTRUParamSets.FromId(Data);
                    else if (Data[0] == (byte)AsymmetricEngines.RingLWE)
                        param = RLWEParamSets.FromId(Data);
                }

                return param;
            }
            catch (Exception ex)
            {
                throw new CryptoKeyExchangeException("DtmKex:GetAsymmetricParams", "The param set is unknown!", ex);
            }
        }

        /// <summary>
        /// Get the asymmetric public key from a stream
        /// </summary>
        /// 
        /// <param name="KeyStream">The encoded public key</param>
        /// <param name="Parameters">The cipher parameters</param>
        /// 
        /// <returns>The public key</returns>
        private IAsymmetricKey GetAsymmetricPublicKey(Stream KeyStream, IAsymmetricParameters Parameters)
        {
            IAsymmetricKey key = null;

            try
            {
                if (Parameters.GetType().Equals(typeof(NTRUParameters)))
                    key = new NTRUPublicKey(KeyStream);
                else if (Parameters.GetType().Equals(typeof(MPKCParameters)))
                    key = new MPKCPublicKey(KeyStream);
                else if (Parameters.GetType().Equals(typeof(RLWEParameters)))
                    key = new RLWEPublicKey(KeyStream);

                return key;
            }
            catch (Exception ex)
            {
                throw new CryptoKeyExchangeException("DtmKex:GetAsymmetricPublicKey", "The public key could not be loaded!", ex);
            }
        }

        private IBlockCipher GetBlockCipher(BlockCiphers EngineType, int BlockSize, int RoundCount, Digests KdfEngine)
        {
            try
            {
                return BlockCipherFromName.GetInstance(EngineType, BlockSize, RoundCount, KdfEngine);
            }
            catch (Exception ex)
            {
                throw new CryptoKeyExchangeException("DtmKex:GetBlockCipher", ex);
            }
        }

        private IDigest GetDigest(Digests DigestType)
        {
            try
            {
                return DigestFromName.GetInstance(DigestType);
            }
            catch
            {
                throw new CryptoKeyExchangeException("DtmKex:GetDigest", "The digest type is not supported!", new ArgumentException());
            }
        }

        private IRandom GetPrng(Prngs PrngType)
        {
            try
            {
                return PrngFromName.GetInstance(PrngType);
            }
            catch
            {
                throw new CryptoKeyExchangeException("DtmKex:GetPrng", "The Prng type is unknown!", new ArgumentException());
            }
        }

        private ICipherMode GetSymmetricCipher(DtmSessionStruct Session)
        {
            try
            {
                IBlockCipher engine = GetBlockCipher((BlockCiphers)Session.EngineType, (int)Session.IvSize, (int)Session.RoundCount, (Digests)Session.KdfEngine);
                return new CTR(engine);
            }
            catch (Exception ex)
            {
                throw new CryptoKeyExchangeException("DtmKex:GetSymmetricCipher", "The symmetric cipher type is unknown!", ex);
            }
        }

        /// <summary>
        /// Waits a maximum (random) number of milliseconds before resuming thread
        /// </summary>
        /// 
        /// <param name="WaitMaxMs">The maximum wait time in milliseconds</param>
        /// <param name="WaitMinMs">The minimum wait time in milliseconds</param>
        private void SendWait(int WaitMaxMs, int WaitMinMs = 0)
        {
            if (WaitMaxMs > 0)
            {
                int max;
                if (WaitMinMs > 0 && WaitMinMs < WaitMaxMs)
                    max  = m_rndGenerator.Next(WaitMaxMs);
                else
                    max = m_rndGenerator.Next(WaitMinMs, WaitMaxMs);

                if (_evtSendWait == null)
                    _evtSendWait = new ManualResetEvent(false);

                _evtSendWait.WaitOne(max);
                _evtSendWait.Set();
            }
        }

        /// <summary>
        /// Tear down the connection; destroys all structures provided by this class
        /// </summary>
        private void TearDown()
        {
            if (m_rndGenerator != null)
            {
                m_rndGenerator.Dispose();
                m_rndGenerator = null;
            }
            if (_authKeyPair != null)
            {
                _authKeyPair.Dispose();
                _authKeyPair = null;
            }
            if (_cltAsmParams != null)
            {
                _cltAsmParams.Dispose();
                _cltAsmParams = null;
            }
            if (_cltPublicKey != null)
            {
                _cltPublicKey.Dispose();
                _cltPublicKey = null;
            }
            if (_primKeyPair != null)
            {
                _primKeyPair.Dispose();
                _primKeyPair = null;
            }
            // cipher streaming managed through class
            if (SessionEstablished == null || _disposeEngines == true)
            {
                if (_cltKeyParams != null)
                {
                    _cltKeyParams.Dispose();
                    _cltKeyParams = null;
                }
                if (_srvKeyParams != null)
                {
                    _srvKeyParams.Dispose();
                    _srvKeyParams = null;
                }
                if (_srvSymProcessor != null)
                {
                    _srvSymProcessor.Dispose();
                    _srvSymProcessor = null;
                }
                if (_cltSymProcessor != null)
                {
                    _cltSymProcessor.Dispose();
                    _cltSymProcessor = null;
                }
            }

            _bufferCount = 0;
            _bytesSent = 0;
            _bytesReceived = 0;
            _cltIdentity.Reset();
            _fileCounter = 0;
            _maxSendCounter = 0;
            _maxSendAttempts = MAXSNDATTEMPT;
            _rcvSequence = 0;
            _sndSequence = 0;
        }

        /// <summary>
        /// Removes random padding from a message array
        /// </summary>
        /// 
        /// <param name="Message">The message aray</param>
        /// 
        /// <returns>The unwrapped message</returns>
        private byte[] UnwrapMessage(byte[] Message)
        {
            int len = 0;
            if ((len = ContainsDelimiter(Message, PREDELIM)) > 0)
                ArrayUtils.RemoveRange(ref Message, 0, len + (PREDELIM.Length - 1));

            if ((len = ContainsDelimiter(Message, POSTDELIM)) > 0)
                ArrayUtils.RemoveRange(ref Message, len, Message.Length - 1);

            return Message;
        }

        /// <summary>
        /// Waits the number specified of milliseconds before resuming thread
        /// </summary>
        /// 
        /// <param name="WaitMs">The wait time in milliseconds; <c>0</c> = forever</param>
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

        /// <summary>
        /// Wrap a message with random bytes
        /// </summary>
        /// 
        /// <param name="Message">The data to wrap</param>
        /// <param name="MaxAppend">The (random) maximum number of bytes to append</param>
        /// <param name="MaxPrepend">The (random) maximum number of bytes to prepend</param>
        /// 
        /// <returns>The wrapped array</returns>
        private byte[] WrapMessage(byte[] Message, int MaxAppend, int MaxPrepend)
        {
            // wrap the message in random and add a message header
            if (MaxAppend > 0 || MaxPrepend > 0)
            {
                byte[] rand = new byte[0];
                int apl = 0;
                int ppl = 0;
                int min = 0;

                // wrap the message with a random number of bytes
                if (MaxAppend > 0)
                {
                    min = MaxAppend / 2; // min is half
                    apl = m_rndGenerator.Next(min, MaxAppend);
                }
                if (MaxPrepend > 0)
                {
                    min = MaxPrepend / 2;
                    ppl = m_rndGenerator.Next(min, MaxPrepend);
                }

                int len = apl + ppl;
                if (len > 0)
                    rand = m_rndGenerator.GetBytes(len);

                if (ppl > 0 && apl > 0)
                {
                    byte[][] rds = ArrayUtils.Split(rand, ppl);
                    Message = ArrayUtils.Concat(rds[0], PREDELIM, Message, POSTDELIM, rds[1]);
                }
                else if (apl > 0)
                {
                    Message = ArrayUtils.Concat(Message, POSTDELIM, rand);
                }
                else if (ppl > 0)
                {
                    Message = ArrayUtils.Concat(rand, PREDELIM, Message);
                }
            }

            return Message;
        }
        #endregion

        #region Event Handlers
        /// <summary>
        /// Forwards any TCP errors originating from the client
        /// </summary>
        private void OnTcpSocketError(object owner, CryptoSocketException ex)
        {
            if (SessionError != null)
                SessionError(this, new DtmErrorArgs(ex, DtmErrorSeverityFlags.Connection));
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
                Disconnect();
                m_isDisposed = true;
            }
        }
        #endregion
    }
}
