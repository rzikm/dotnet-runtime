// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System.Diagnostics;
using System.IO;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Crypto;
using System.Net.Quic.Implementations.Managed.Internal.Frames;
using System.Net.Quic.Implementations.Managed.Internal.Headers;
using System.Net.Quic.Implementations.Managed.Internal.Recovery;
using System.Net.Quic.Implementations.Managed.Internal.Sockets;
using System.Net.Quic.Implementations.Managed.Internal.Streams;
using System.Net.Quic.Implementations.Managed.Internal.Tracing;
using System.Net.Quic.Implementations.Managed.Internal.Tls;
using System.Net.Security;
using System.Security.Authentication;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;

#pragma warning disable IDE0060

namespace System.Net.Quic.Implementations.Managed
{
    public sealed partial class ManagedQuicConnection : QuicConnection, IAsyncDisposable
    {
        public static new bool IsSupported => true;

#pragma warning disable IDE0060 // Remove unused parameter
        public static new async ValueTask<QuicConnection> ConnectAsync(QuicClientConnectionOptions options, CancellationToken cancellationToken = default)
#pragma warning restore IDE0060 // Remove unused parameter
        {
            options.Validate(nameof(options));

            var connection = new ManagedQuicConnection(options, TlsFactory.Default);

            connection._socketContext.WakeUp();
            connection._socketContext.Start();

            await connection._connectTcs.GetTask().ConfigureAwait(false);

            return connection;
        }

        // This limit should ensure that if we can fit at least an ack frame into the packet,
        private const int RequiredAllowanceForSending = 2 * ConnectionId.MaximumLength + 40;

        internal readonly SingleEventValueTaskSource _connectTcs = new SingleEventValueTaskSource();

        private readonly SingleEventValueTaskSource _closeTcs = new SingleEventValueTaskSource();

        /// <summary>
        ///     Object for creating a trace of this connection.
        /// </summary>
        private readonly IQuicTrace? _trace;

        /// <summary>
        ///     Timestamp when last <see cref="ConnectionCloseFrame"/> was sent, or 0 if no such frame was sent yet.
        /// </summary>
        private long _lastConnectionCloseSentTimestamp;

        /// <summary>
        ///     Packet number spaces for the three main packet types.
        /// </summary>
        private readonly PacketNumberSpace[] _pnSpaces = new PacketNumberSpace[3]
        {
            new PacketNumberSpace(PacketType.Initial, PacketSpace.Initial),
            new PacketNumberSpace(PacketType.Handshake, PacketSpace.Handshake),
            new PacketNumberSpace(PacketType.OneRtt, PacketSpace.Application)
        };

        /// <summary>
        ///     Recovery controller used for this connection.
        /// </summary>
        private RecoveryController Recovery { get; }

        /// <summary>
        ///     If true, the connection is in draining state. The connection MUST not send packets in such state. The
        ///     The connection transitions to closed at <see cref="_closingPeriodEndTimestamp"/> at the latest.
        /// </summary>
        private bool _isDraining;

        /// <summary>
        ///     If true, the connection is in closing or draining state and will be considered close at
        ///     <see cref="_closingPeriodEndTimestamp"/> at the latest.
        /// </summary>
        internal bool IsClosing => _closingPeriodEndTimestamp != null;

        internal bool Connected => HandshakeConfirmed;

        /// <summary>
        ///     Timestamp when the connection close will be initiated due to lack of packets from peer.
        /// </summary>
        private long _idleTimeout = long.MaxValue; // use infinite by default

        /// <summary>
        ///     True if an ack-eliciting packet has been sent since last receiving an ack-eliciting packet.
        /// </summary>
        private bool _ackElicitingWasSentSinceLastReceive;

        /// <summary>
        ///     Timestamp when the closing period will be end and the connection will be considered closed.
        /// </summary>
        private long? _closingPeriodEndTimestamp;

        /// <summary>
        ///     True if the connection is in closed state.
        /// </summary>
        internal bool IsClosed => _closeTcs.IsSet;

        /// <summary>
        ///     Gets the current state of the connection.
        /// </summary>
        internal QuicConnectionState ConnectionState
        {
            get
            {
                if (IsClosed) return QuicConnectionState.Closed;
                if (_isDraining) return QuicConnectionState.Draining;
                if (IsClosing) return QuicConnectionState.Closing;
                if (Connected) return QuicConnectionState.Connected;
                return QuicConnectionState.None;
            }
        }

        private readonly bool _canAccept;

        /// <summary>
        ///     QUIC transport parameters used for this endpoint.
        /// </summary>
        internal readonly TransportParameters _localTransportParameters;

        /// <summary>
        ///     The TLS handshake module.
        /// </summary>
        internal ITls Tls { get; }

        private readonly SocketAddress _remoteSocketAddress;

        /// <summary>
        ///     Context of the socket serving this connection.
        /// </summary>
        private QuicConnectionContext _socketContext;

        /// <summary>
        ///     True if handshake has been confirmed by the peer. For server this means that TLS has reported handshake complete,
        ///     for client it means that a HANDSHAKE_DONE frame has been received.
        /// </summary>
        private bool HandshakeConfirmed => IsServer ? Tls.IsHandshakeComplete : _handshakeDoneReceived;

        /// <summary>
        ///     For client: True if HANDSHAKE_DONE frame has been received.
        ///     For Server: true if HANDSHAKE_DONE frame has been delivered.
        /// </summary>
        private bool _handshakeDoneReceived;

        /// <summary>
        ///     True if this side of connection belongs to the server.
        /// </summary>
        internal readonly bool IsServer;

        /// <summary>
        ///     Collection of streams for this connection.
        /// </summary>
        private readonly StreamCollection _streams = new StreamCollection();

        /// <summary>
        ///     Collection of local connection ids used by this endpoint.
        /// </summary>
        private readonly ConnectionIdCollection _localConnectionIdCollection = new ConnectionIdCollection();

        /// <summary>
        ///     Collection of local connection ids used by remote endpoint.
        /// </summary>
        private readonly ConnectionIdCollection _remoteConnectionIdCollection = new ConnectionIdCollection();

        /// <summary>
        ///     Flow control limits set by this endpoint for the peer for the entire connection.
        /// </summary>
        internal ConnectionFlowControlLimits _receiveLimits;

        /// <summary>
        ///     Values of <see cref="_receiveLimits"/> that peer has confirmed received.
        /// </summary>
        private ConnectionFlowControlLimits _receiveLimitsAtPeer;

        /// <summary>
        ///     Flow control limits set by the peer for this endpoint for the entire connection.
        /// </summary>
        internal ConnectionFlowControlLimits _sendLimits;

        /// <summary>
        ///     QUIC transport parameters requested by peer endpoint.
        /// </summary>
        internal TransportParameters _peerTransportParameters = TransportParameters.Default;

        /// <summary>
        ///     Error received via CONNECTION_CLOSE frame to be reported to the user.
        /// </summary>
        private QuicTransportError? _inboundError;

        /// <summary>
        ///     Error to send in next packet in a CONNECTION_CLOSE frame.
        /// </summary>
        private QuicTransportError? _outboundError;

        /// <summary>
        ///     Version of the QUIC protocol used for this connection.
        /// </summary>
        private readonly QuicVersion version = QuicVersion.Draft27;

        /// <summary>
        ///     Timer when at the latest the next ACK frame should be sent.
        /// </summary>
        private long _nextAckTimer = long.MaxValue;

        /// <summary>
        ///     True if PING frame should be sent during next flight.
        /// </summary>
        private bool _pingWanted;

        /// <summary>
        ///     True if this instance has been disposed.
        /// </summary>
        private bool _disposed;

        /// <summary>
        ///     If not null, contains the exception that terminated the socket maintenance task.
        /// </summary>
        private Exception? _socketContextException;

        internal QuicConnectionOptions _connectionOptions;

        /// <summary>
        ///     Requests sending PING frame to the peer, requiring the peer to send acknowledgement back.
        /// </summary>
        internal void Ping()
        {
            _pingWanted = true;
        }

        // client constructor
        internal ManagedQuicConnection(QuicClientConnectionOptions options, TlsFactory tlsFactory)
            : base(true)
        {
            _connectionOptions = options;
            _canAccept = options.MaxInboundUnidirectionalStreams > 0 || options.MaxInboundBidirectionalStreams > 0;
            IsServer = false;

            _targetHostName = options.ClientAuthenticationOptions!.TargetHost;

            _socketContext = new SingleConnectionSocketContext(options.LocalEndPoint, options.RemoteEndPoint!, this).ConnectionContext;

            _remoteSocketAddress = RemoteEndPoint.Serialize();

            _localTransportParameters = TransportParameters.FromConnectionOptions(options);
            Tls = tlsFactory.CreateClient(this, options, _localTransportParameters);

            // init random connection ids for the client
            SourceConnectionId = ConnectionId.Random(ConnectionId.DefaultCidSize);
            DestinationConnectionId = ConnectionId.Random(ConnectionId.DefaultCidSize);
            _trace = InitTrace(IsServer, DestinationConnectionId.Data);
            Recovery = new RecoveryController(_trace);
            _localConnectionIdCollection.Add(SourceConnectionId);

            // derive also clients initial secrets.
            DeriveInitialProtectionKeys(DestinationConnectionId.Data);

            // generate first Crypto frames
            Tls.TryAdvanceHandshake();

            CoreInit();
        }

        // server constructor
        internal ManagedQuicConnection(QuicConnectionContext socketContext,
            IPEndPoint remoteEndpoint, ReadOnlySpan<byte> odcid, TlsFactory tlsFactory)
            : base(true)
        {

            IsServer = true;
            _socketContext = socketContext;
            _serverRemoteEndpoint = remoteEndpoint;
            _remoteSocketAddress = _serverRemoteEndpoint.Serialize();

            _trace = InitTrace(IsServer, odcid);
            Recovery = new RecoveryController(_trace);

            var options = socketContext.GetServerConnectionOptions(this);
            options.Validate("options");
            _connectionOptions = options;

            _localTransportParameters = TransportParameters.FromConnectionOptions(_connectionOptions);

            _canAccept = _connectionOptions.MaxInboundUnidirectionalStreams > 0 || _connectionOptions.MaxInboundBidirectionalStreams > 0;
            Tls = tlsFactory.CreateServer(this, options, _localTransportParameters);

            CoreInit();
        }

        private static IQuicTrace? InitTrace(bool isServer, ReadOnlySpan<byte> odcid)
        {
            string? traceType = Environment.GetEnvironmentVariable("DOTNETQUIC_TRACE");
            if (traceType == "console")
            {
                return new TextWriterTrace(Console.Out, isServer);
            }
            else if (traceType != null)
            {
                string filename = $"{DateTime.Now:yyyy-MM-dd_HH-mm-ss.fff}-{(isServer ? "server" : "client")}.qlog";
                return new QlogTrace(File.Open(filename, FileMode.Create), odcid.ToArray(), isServer);
            }

            return null;
        }

        private void CoreInit()
        {
            _trace?.OnTransportParametersSet(_localTransportParameters);

            _receiveLimits.UpdateMaxData(_localTransportParameters.InitialMaxData);
            _receiveLimits.UpdateMaxStreamsBidi(_localTransportParameters.InitialMaxStreamsBidi);
            _receiveLimits.UpdateMaxStreamsUni(_localTransportParameters.InitialMaxStreamsUni);
            _receiveLimitsAtPeer = _receiveLimits;

            MaxStreamsUniFrameSent = _receiveLimits.MaxStreamsUni;
            MaxStreamsBidiFrameSent = _receiveLimits.MaxStreamsBidi;
        }


        /// <summary>
        ///     Connection ID used by this endpoint to identify packets for this connection.
        /// </summary>
        internal ConnectionId? SourceConnectionId { get; private set; }

        /// <summary>
        ///     Connection ID used by the peer to identify packets for this connection.
        /// </summary>
        internal ConnectionId? DestinationConnectionId { get; private set; }

        /// <summary>
        /// Gets the name of the server the client is trying to connect to. That name is used for server certificate validation. It can be a DNS name or an IP address.
        /// </summary>
        /// <returns>The name of the server the client is trying to connect to.</returns>
        internal string? _targetHostName;

        /// <summary>
        /// Gets the name of the server the client is trying to connect to. That name is used for server certificate validation. It can be a DNS name or an IP address.
        /// </summary>
        /// <returns>The name of the server the client is trying to connect to.</returns>
        public override string TargetHostName => _targetHostName ?? "";

        /// <summary>
        ///     Sets new socket context that will from now on service the connection.
        /// </summary>
        /// <param name="context">The new context.</param>
        internal void SetSocketContext(QuicConnectionContext context)
        {
            _socketContext = context;
        }

        /// <summary>
        ///     Returns timestamp of the next timer event, after timeout, <see cref="OnTimeout"/> should be called.
        /// </summary>
        /// <returns>Timestamp in ticks of the next timer or long.MaxValue if no timer is needed.</returns>
        internal long GetNextTimerTimestamp()
        {
            if (_closeTcs.IsSet)
            {
                // connection already closed, no timer needed
                return long.MaxValue;
            }

            // if (HasApplicationDataToSend())
            // {
            //     // start immediately
            //     return Timestamp.Now;
            // }

            long timer = _idleTimeout;

            if (_closingPeriodEndTimestamp != null)
            {
                // no other timer besides idle timeout and closing period makes sense when closing.
                return Math.Min(timer, _closingPeriodEndTimestamp.Value);
            }

            // do not incorporate next ack timer if we cannot send ack anyway
            if (Recovery.GetAvailableCongestionWindowBytes() >= RequiredAllowanceForSending)
            {
                timer = Math.Min(timer, _nextAckTimer);

                if (Recovery.IsPacing && HasApplicationDataToSend())
                {
                    timer = Math.Min(timer, Recovery.GetPacingTimerForNextFullPacket());
                }
            }

            timer = Math.Min(timer, Recovery.LossRecoveryTimer);

            return timer;
        }

        internal void OnTimeout(long timestamp)
        {
            if (_closingPeriodEndTimestamp.HasValue)
            {
                if (timestamp >= _closingPeriodEndTimestamp)
                {
                    SignalConnectionClose();
                }
                return;
            }

            if (timestamp >= _idleTimeout)
            {
                OnIdleTimeout();
            }

            if (timestamp >= Recovery.LossRecoveryTimer)
            {
                Recovery.OnLossDetectionTimeout(Tls.IsHandshakeComplete, timestamp);
            }
        }

        internal void OnIdleTimeout()
        {
            SetException(new QuicException(QuicError.ConnectionIdle, null, null, "Connection idle."));
            SignalConnectionClose();
        }

        /// <summary>
        ///     Advances the cryptographic handshake based on received data.
        /// </summary>
        private void DoHandshake()
        {
            if (!Tls.TryAdvanceHandshake() && _outboundError == null)
            {
                CloseConnection(TransportErrorCode.InternalError, "SSL error");
                return;
            }

            // get peer transport parameters, if we didn't do so already
            if (!ReferenceEquals(_peerTransportParameters, TransportParameters.Default)
                // the transport parameters may not have been received yet
                || Tls.WriteLevel == EncryptionLevel.Initial)
            {
                return;
            }

            var param = Tls.GetPeerTransportParameters(IsServer);

            if (param == null)
            {
                // failed to retrieve transport parameters.
                CloseConnection(TransportErrorCode.TransportParameterError);
                return;
            }

            ref ConnectionFlowControlLimits limits = ref _sendLimits;

            limits.UpdateMaxData(param.InitialMaxData);
            limits.UpdateMaxStreamsBidi(param.InitialMaxStreamsBidi);
            limits.UpdateMaxStreamsUni(param.InitialMaxStreamsUni);

            Recovery.MaxAckDelay = Timestamp.FromMilliseconds(param.MaxAckDelay);

            _peerTransportParameters = param;
        }

        /// <summary>
        ///     Derives initial protection keys based on the destination connection id sent by the client.
        /// </summary>
        /// <param name="dcid">Destination connection ID sent from client-sent packets.</param>
        private void DeriveInitialProtectionKeys(byte[] dcid)
        {
            byte[] readSecret;
            byte[] writeSecret;

            var algorithm = QuicConstants.InitialCipherSuite;

            if (IsServer)
            {
                readSecret = KeyDerivation.DeriveClientInitialSecret(dcid);
                writeSecret = KeyDerivation.DeriveServerInitialSecret(dcid);
            }
            else
            {
                writeSecret = KeyDerivation.DeriveClientInitialSecret(dcid);
                readSecret = KeyDerivation.DeriveServerInitialSecret(dcid);
            }

            SetEncryptionSecrets(EncryptionLevel.Initial, algorithm, readSecret, writeSecret);
        }

        /// <summary>
        ///     Gets the amount of data this endpoint can send at this time
        /// </summary>
        /// <returns></returns>
        internal int GetSendingAllowance(long timestamp, bool ignorePacer)
        {
            // ignore the pacer if we need to send an ack
            if (ignorePacer)
            {
                return Recovery.GetAvailableCongestionWindowBytes();
            }

            return Recovery.GetSendingAllowance(timestamp);
        }

        private bool ShouldIgnorePacer(long timestamp)
        {
            return _nextAckTimer <= timestamp || _pingWanted || ShouldSendConnectionClose(timestamp);
        }

        /// <summary>
        ///     Gets <see cref="EncryptionLevel"/> at which the next packet should be sent.
        /// </summary>
        internal EncryptionLevel GetWriteLevel(long timestamp)
        {
            // if there is a probe waiting to be sent on any level, send it.
            // Because probe packets are not limited by congestion window, this avoids a live-lock in
            // scenario where there is a pending ack in e.g. Initial epoch, but the connection cannot
            // send it because it is limited by congestion window, because it has in-flight packets
            // in Handshake epoch.
            var probeSpace = PacketSpace.Initial;
            for (int i = 1; i < _pnSpaces.Length; i++)
            {
                var packetSpace = (PacketSpace)i;
                var recoverySpace = Recovery.GetPacketNumberSpace(packetSpace);
                if (recoverySpace.RemainingLossProbes > Recovery.GetPacketNumberSpace(probeSpace).RemainingLossProbes)
                {
                    probeSpace = packetSpace;
                }
            }

            if (Recovery.GetPacketNumberSpace(probeSpace).RemainingLossProbes > 0)
            {
                return (EncryptionLevel)probeSpace;
            }

            // if pending errors, send them in appropriate epoch,
            if (_outboundError?.IsQuicError == true)
            {
                if (!ShouldSendConnectionClose(timestamp))
                    return EncryptionLevel.None;

                EncryptionLevel desiredLevel = Tls.WriteLevel;
                if (!Connected && desiredLevel == EncryptionLevel.Application)
                {
                    // don't use application level if handshake is not complete
                    return EncryptionLevel.Handshake;
                }

                return desiredLevel;
            }

            // Check if the pacer allow us to send something. note that this also handles the case when we need to
            // ignore the pacer due to pending ack.
            if (GetSendingAllowance(timestamp, ShouldIgnorePacer(timestamp)) < RequiredAllowanceForSending)
            {
                // can't send anything now
                return EncryptionLevel.None;
            }

            for (int i = 0; i < _pnSpaces.Length; i++)
            {
                var level = (EncryptionLevel)i;
                var pnSpace = _pnSpaces[i];

                // to advance handshake
                if (pnSpace.CryptoSendStream.IsFlushable ||
                    // send acknowledgement if needed, prefer sending acks in Initial and Handshake
                    // immediately since there is a great chance of coalescing with next level
                    (i < 2 ? pnSpace.AckElicited : pnSpace.NextAckTimer <= timestamp))
                    return level;
            }

            // check if we have something to send.
            if (HasApplicationDataToSend() || ShouldSendConnectionClose(timestamp))
            {
                return EncryptionLevel.Application;
            }

            // otherwise we have no data to send.
            return EncryptionLevel.None;
        }

        private bool HasApplicationDataToSend()
        {
            // TODO-RZ: this list may be incomplete
            return _pingWanted ||
                _streams.HasFlushableStreams ||
                _streams.HasUpdateableStreams ||
                MaxStreamsUniFrameSent < _receiveLimits.MaxStreamsUni ||
                MaxStreamsBidiFrameSent < _receiveLimits.MaxStreamsBidi;
        }

        private static PacketSpace GetPacketSpace(PacketType packetType)
        {
            return packetType switch
            {
                PacketType.Initial => PacketSpace.Initial,
                PacketType.ZeroRtt => PacketSpace.Application,
                PacketType.Handshake => PacketSpace.Handshake,
                PacketType.OneRtt => PacketSpace.Application,
                _ => throw new ArgumentOutOfRangeException(nameof(packetType), packetType, null)
            };
        }

        private static EncryptionLevel GetEncryptionLevel(PacketType packetType)
        {
            return packetType switch
            {
                PacketType.Initial => EncryptionLevel.Initial,
                PacketType.Handshake => EncryptionLevel.Handshake,
                PacketType.ZeroRtt => EncryptionLevel.EarlyData,
                PacketType.OneRtt => EncryptionLevel.Application,
                PacketType.Retry => EncryptionLevel.None,
                PacketType.VersionNegotiation => EncryptionLevel.None,
                _ => throw new ArgumentOutOfRangeException(nameof(packetType), packetType, null)
            };
        }

        /// <summary>
        ///     Gets instance of <see cref="PacketNumberSpace"/> associated with the given encryption level.
        /// </summary>
        /// <param name="encryptionLevel">The encryption level.</param>
        internal PacketNumberSpace GetPacketNumberSpace(EncryptionLevel encryptionLevel)
        {
            return encryptionLevel switch
            {
                EncryptionLevel.Initial => _pnSpaces[0],
                EncryptionLevel.Handshake => _pnSpaces[1],
                EncryptionLevel.EarlyData => _pnSpaces[2],
                EncryptionLevel.Application => _pnSpaces[2],
                _ => throw new ArgumentOutOfRangeException(nameof(encryptionLevel), encryptionLevel, null)
            };
        }

        /// <summary>
        ///     Prepares the connection for termination due to an error. The connection will start closing once the
        ///     when the error is actually sent.
        /// </summary>
        /// <param name="errorCode">The error code identifying the nature of the error.</param>
        /// <param name="reason">Optional short human-readable reason for closing.</param>
        /// <param name="frameType">Optional type of the frame which was being processed when the error was encountered</param>
        /// <returns>Always returns <see cref="ProcessPacketResult.Error"/> to simplify packet processing code</returns>
        private ProcessPacketResult CloseConnection(TransportErrorCode errorCode, string? reason = null,
            FrameType frameType = FrameType.Padding)
        {
            _outboundError ??= new QuicTransportError(errorCode, reason, frameType);
            return ProcessPacketResult.Error;
        }

        public override async ValueTask DisposeAsync()
        {
            await CloseAsync(_connectionOptions.DefaultCloseErrorCode).ConfigureAwait(false);

            // Dispose remote certificate only if it hasn't been accessed via getter, in which case the accessing code becomes the owner of the certificate lifetime.
            if (!_remoteCertificateExposed)
            {
                _remoteCertificate?.Dispose();
            }

            _disposed = true;
            Tls.Dispose();
        }

        private void SetEncryptionSecrets(EncryptionLevel level, TlsCipherSuite algorithm,
            ReadOnlySpan<byte> readSecret, ReadOnlySpan<byte> writeSecret)
        {
            var pnSpace = GetPacketNumberSpace(level);
            Debug.Assert(pnSpace.SendCryptoSeal == null, "Protection keys already derived");

            pnSpace.RecvCryptoSeal = CryptoSeal.Create(algorithm, readSecret);
            pnSpace.SendCryptoSeal = CryptoSeal.Create(algorithm, writeSecret);

            _trace?.OnKeyUpdated(readSecret, level, !IsServer, KeyUpdateTrigger.Tls, null);
            _trace?.OnKeyUpdated(writeSecret, level, IsServer, KeyUpdateTrigger.Tls, null);
        }

        internal void SetEncryptionSecrets(EncryptionLevel level, ReadOnlySpan<byte> readSecret,
            ReadOnlySpan<byte> writeSecret)
        {
            var alg = Tls.GetNegotiatedCipher();
            SetEncryptionSecrets(level, alg, readSecret, writeSecret);
        }

        internal void AddHandshakeData(EncryptionLevel level, ReadOnlySpan<byte> data)
        {
            SendStream cryptoOutboundStream = GetPacketNumberSpace(level).CryptoSendStream;
            cryptoOutboundStream.Enqueue(data);
        }

        internal void FlushHandshakeData()
        {
            for (int i = 0; i < 3; i++)
            {
                SendStream cryptoOutboundStream = GetPacketNumberSpace((EncryptionLevel)i).CryptoSendStream;
                cryptoOutboundStream.ForceFlushPartialChunk();
            }
        }

        internal void SendTlsAlert(int alert)
        {
            // RFC: A TLS alert is turned into a QUIC connection error by converting the
            // one-byte alert description into a QUIC error code.  The alert
            // description is added to 0x100 to produce a QUIC error code from the
            // range reserved for CRYPTO_ERROR.  The resulting value is sent in a
            // QUIC CONNECTION_CLOSE frame.

            CloseConnection((TransportErrorCode)alert + 0x100, $"Tls alert - {alert}");
            if (!_connectTcs.IsSet)
            {
                _connectTcs.TryCompleteException(new AuthenticationException($"Tls alert - {alert}"));
            }
        }

        private enum ProcessPacketResult
        {
            /// <summary>
            ///     Packet processed without errors.
            /// </summary>
            Ok,

            /// <summary>
            ///     Packet is discarded. E.g. because it could not be decrypted (yet).
            /// </summary>
            DropPacket,

            /// <summary>
            ///     Packet is valid but violates the protocol, the connection should be closed.
            /// </summary>
            Error
        }

        #region Public API


        public override IPEndPoint LocalEndPoint => _socketContext.LocalEndPoint;

        // TODO-RZ: create a defensive copy of the endpoint
        private readonly IPEndPoint? _serverRemoteEndpoint;
        public override IPEndPoint RemoteEndPoint => IsServer
            // server connections get passed IPEndPoint
            ? (IPEndPoint)_serverRemoteEndpoint!
            // for clients, check the RemoteEndPoint of the Socket
            : _socketContext.RemoteEndPoint!;

        public override async ValueTask<QuicStream> OpenOutboundStreamAsync(QuicStreamType type, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfError();

            return await OpenStream(type == QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        }

        public override async ValueTask<QuicStream> AcceptInboundStreamAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfError();

            if (!_canAccept)
            {
                throw new InvalidOperationException(SR.net_quic_accept_not_allowed);
            }

            try
            {
                return await _streams.IncomingStreams.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ChannelClosedException ex) when (ex.InnerException is not null)
            {
                // rethrow the inner exception
                ExceptionDispatchInfo.Throw(ex.InnerException);
                throw;
            }
        }

        public override SslApplicationProtocol NegotiatedApplicationProtocol
        {
            get
            {
                ThrowIfDisposed();
                return Tls.GetNegotiatedProtocol();
            }
        }

        /// <summary>
        /// Keeps track whether <see cref="RemoteCertificate"/> has been accessed so that we know whether to dispose the certificate or not.
        /// </summary>
        private bool _remoteCertificateExposed;
        internal X509Certificate2? _remoteCertificate;

        /// <summary>
        /// The certificate provided by the peer.
        /// For an outbound/client connection will always have the peer's (server) certificate; for an inbound/server one, only if the connection requested and the peer (client) provided one.
        /// </summary>
        public override X509Certificate? RemoteCertificate
        {
            get
            {
                _remoteCertificateExposed = true;
                return _remoteCertificate;
            }
        }

        public override ValueTask CloseAsync(long errorCode, CancellationToken cancellationToken = default)
        {
            if (_disposed || _closeTcs.IsSet)
            {
                return default;
            }

            if (!Connected)
            {
                // TODO: is this necessary?
                // abandon connection attempt
                _connectTcs.TryCompleteException(new QuicException(QuicError.ConnectionAborted, errorCode, "Abandon connection attempt"));
                _closeTcs.TryComplete();
                return default;
            }

            _outboundError = new QuicTransportError((TransportErrorCode)errorCode, null, FrameType.Padding, false);

            // abort all pending stream operations on our side
            foreach (var stream in _streams.OpenStreams)
            {
                stream.OnConnectionClosed(MakeOperationAbortedException());
            }

            _streams.IncomingStreams.Writer.TryComplete(MakeOperationAbortedException());
            _socketContext.WakeUp();

            return _closeTcs.GetTask();
        }

        #endregion

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(_disposed, typeof(ManagedQuicConnection));
        }

        internal void ThrowIfError()
        {
            if (_socketContextException != null)
                throw new Exception("Internal socket operation failed", _socketContextException);

            if (_outboundError != null)
            {
                if (!_outboundError.IsQuicError)
                {
                    // connection close initiated by application
                    throw new QuicException(QuicError.OperationAborted, null, "Operation Aborted");
                }
                else if (_outboundError.ErrorCode != TransportErrorCode.NoError)
                {
                    // connection close initiated by us (transport)
                    throw new QuicException(QuicError.TransportError, (long)_outboundError.ErrorCode, _outboundError.ReasonPhrase ?? "Protocol Error");
                }
            }

            if (_inboundError != null)
            {
                // connection close initiated by peer
                throw MakeConnectionAbortedException(_inboundError);
            }
        }

        private void DropPacketNumberSpace(PacketSpace space, ObjectPool<SentPacket> sentPacketPool)
        {
            // TODO-RZ: discard the PacketNumberSpace instance and let GC collect it?
            var pnSpace = _pnSpaces[(int)space];
            if (pnSpace.SendCryptoSeal == null)
            {
                // already dropped
                return;
            }

            Recovery.DropUnackedData(space, Tls.IsHandshakeComplete, sentPacketPool);

            // drop protection keys
            pnSpace.SendCryptoSeal = null;
            pnSpace.RecvCryptoSeal = null;

            pnSpace.NextAckTimer = long.MaxValue;
            ResetAckTimer();
        }

        internal void SignalConnectionClose() => _closeTcs.TryComplete();

        /// <summary>
        ///     Starts closing period.
        /// </summary>
        /// <param name="now">Timestamp of the current moment.</param>
        /// <param name="error">Error which led to connection closing.</param>
        private void StartClosing(long now, QuicTransportError error)
        {
            Debug.Assert(_closingPeriodEndTimestamp == null);
            Debug.Assert(error != null);

            // The closing and draining states SHOULD exists for at least three times the current PTO interval
            // Note: this is to properly discard reordered/delayed packets.
            _closingPeriodEndTimestamp = now + 3 * Recovery.GetProbeTimeoutInterval();

            // disable ack timer
            _nextAckTimer = long.MaxValue;

            SetException(MakeConnectionAbortedException(error));
        }

        private void StartDraining()
        {
            _isDraining = true;

            // for all user's purposes, the connection is closed.
            SignalConnectionClose();
        }

        /// <summary>
        ///     Calculates idle timeout based on the local and peer endpoints transport parameters.
        /// </summary>
        private long GetIdleTimeoutPeriod()
        {
            long localTimeout = Timestamp.FromMilliseconds(_localTransportParameters.MaxIdleTimeout);
            long peerTimeout = Timestamp.FromMilliseconds(_peerTransportParameters.MaxIdleTimeout);

            return (localTimeout, peerTimeout) switch
            {
                (0, 0) => 0,
                (long t, 0) => t,
                (0, long t) => t,
                (long t, long u) => Math.Min(t, u)
            };
        }

        private void RestartIdleTimer(long now)
        {
            long timeout = GetIdleTimeoutPeriod();
            if (timeout > 0)
            {
                // RFC: If the idle timeout is enabled by either peer, a connection is
                // silently closed and its state is discarded when it remains idle for
                // longer than the minimum of the max_idle_timeouts (see Section 18.2)
                // and three times the current Probe Timeout (PTO).
                _idleTimeout = now + timeout + 3 * Recovery.GetProbeTimeoutInterval();
            }
        }

        private void SignalConnected()
        {
            _connectTcs.TryComplete();
        }

        private static QuicException MakeOperationAbortedException()
        {
            return new QuicException(QuicError.OperationAborted, null, "Operation Aborted");
        }

        private static Exception MakeConnectionAbortedException(QuicTransportError error)
        {
            // check for TLS Alerts
            if (error.IsQuicError && (int)error.ErrorCode > 0x100)
            {
                return new AuthenticationException("$TLS Alert :{(TlsAlert) (error.ErrorCode - 0x100)}");
            }

            return new QuicException(QuicError.ConnectionAborted, (long)error.ErrorCode, $"Connection aborted: '{error.ReasonPhrase}'");
        }

        internal void OnSocketContextException(Exception e)
        {
            _socketContextException = e;
            CloseConnection(TransportErrorCode.InternalError);
            SetException(e);
        }

        internal void SetException(Exception e)
        {
            _connectTcs.TryCompleteException(e);
            _closeTcs.TryComplete();
            _streams.IncomingStreams.Writer.TryComplete(e);

            foreach (var stream in _streams.OpenStreams)
            {
                stream.OnFatalException(e);
            }
        }

        /// <summary>
        ///     Perform any cleanup that must be done from the socket thread
        /// </summary>
        internal void DoCleanup()
        {
            _trace?.Dispose();
        }
    }
}

#pragma warning restore IDE0060
