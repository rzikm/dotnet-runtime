// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.Net.Quic.Implementations.Managed.Internal.Headers;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace System.Net.Quic.Implementations.Managed.Internal.Tls
{
    internal sealed class MockTls : ITls
    {
        // magic bytes to distinguish this implementation from the other TLS implementations
        private static readonly byte[] _magicBytes = Encoding.UTF8.GetBytes(".NET QUIC mock TLS");

        private static readonly Random _random = new Random();

        private static byte[] GenerateRandomSecret()
        {
            var secret = new byte[32];

            lock (_random)
            {
                _random.NextBytes(secret);
            }

            return secret;
        }

        private readonly byte[] _handshakeWriteSecret = GenerateRandomSecret();
        private readonly byte[] _applicationWriteSecret = GenerateRandomSecret();

        private readonly ManagedQuicConnection _connection;
        private readonly TransportParameters _localTransportParams;
        private TransportParameters? _remoteTransportParams;
        private readonly List<SslApplicationProtocol> _alpn;
        private readonly SslAuthenticationOptions _authOptions = new SslAuthenticationOptions();

        private ArrayBuffer _recvBufferInitial = new ArrayBuffer(1200, true);
        private ArrayBuffer _recvBufferHandshake = new ArrayBuffer(1200, true);

        private readonly bool IsClient;

        private bool _certRequired;
        private bool _sentInitial;
        private SslApplicationProtocol _negotiatedAlpn;

        public MockTls(ManagedQuicConnection connection, QuicClientConnectionOptions options, TransportParameters localTransportParams)
            : this(connection, localTransportParams, options.ClientAuthenticationOptions!.ApplicationProtocols)
        {
            IsClient = true;
            _authOptions.UpdateOptions(options.ClientAuthenticationOptions);
            WriteLevel = EncryptionLevel.Initial;
        }

        public MockTls(ManagedQuicConnection connection, QuicServerConnectionOptions options, TransportParameters localTransportParams)
            : this(connection, localTransportParams, options.ServerAuthenticationOptions!.ApplicationProtocols)
        {
            IsClient = false;
            _authOptions.UpdateOptions(options.ServerAuthenticationOptions);
            WriteLevel = EncryptionLevel.Initial;
        }

        private MockTls(ManagedQuicConnection connection, TransportParameters localTransportParams,
            List<SslApplicationProtocol>? alpn)
        {
            _connection = connection;
            _localTransportParams = localTransportParams;
            _alpn = alpn ?? throw new ArgumentNullException(nameof(SslServerAuthenticationOptions.ApplicationProtocols));
        }

        public void Dispose()
        {
            _recvBufferInitial.Dispose();
            _recvBufferHandshake.Dispose();
        }

        public bool IsHandshakeComplete { get; private set; }
        public EncryptionLevel WriteLevel { get; private set; }
        public void OnHandshakeDataReceived(EncryptionLevel level, ReadOnlySpan<byte> data)
        {
            ref ArrayBuffer buffer = ref level == EncryptionLevel.Initial
                ? ref _recvBufferInitial
                : ref _recvBufferHandshake;

            buffer.EnsureAvailableSpace(data.Length);
            data.CopyTo(buffer.AvailableSpan);
            buffer.Commit(data.Length);
        }

        private sealed class ClientHello
        {
            public required string HostName { get; init; }
            public required TransportParameters TransportParameters { get; init; }
            public required byte[] ClientHandshakeSecret { get; init; }
            public required byte[] ClientApplicationSecret { get; init; }
            public required List<SslApplicationProtocol> Alpn { get; init; }

            public void Write(QuicWriter writer)
            {
                writer.WriteVarInt(HostName.Length);
                writer.WriteSpan(Encoding.UTF8.GetBytes(HostName));
                var sizeSpan = writer.GetWritableSpan(2);
                int written = TransportParameters.Write(writer.AvailableSpan, false, TransportParameters);
                QuicPrimitives.WriteVarInt(sizeSpan, written, 2);
                writer.Advance(written);
                writer.WriteSpan(ClientHandshakeSecret);
                writer.WriteSpan(ClientApplicationSecret);

                writer.WriteVarInt(Alpn.Count);
                foreach (var protocol in Alpn)
                {
                    writer.WriteVarInt(protocol.Protocol.Length);
                    writer.WriteSpan(protocol.Protocol.Span);
                }
            }

            public static ClientHello Read(QuicReader reader)
            {
                if (!reader.TryReadVarInt(out var length)
                    || !reader.TryReadSpan((int)length, out var span)
                    || !reader.TryReadVarInt(out var size)
                    || !TransportParameters.Read(reader.ReadSpan((int)size), false, out var transportParameters)
                    || !reader.TryReadSpan(32, out var clientHandshakeSecret)
                    || !reader.TryReadSpan(32, out var clientApplicationSecret)
                    || !reader.TryReadVarInt(out var alpnCount))
                {
                    throw new Exception("Failed to read ClientHello");
                }

                var alpn = new List<SslApplicationProtocol>();

                for (int i = 0; i < alpnCount; i++)
                {
                    if (!reader.TryReadVarInt(out var alpnLength)
                        || !reader.TryReadSpan((int)alpnLength, out var alpnSpan))
                    {
                        throw new Exception("Failed to read ClientHello");
                    }

                    alpn.Add(new SslApplicationProtocol(alpnSpan.ToArray()));
                }

                return new ClientHello
                {
                    HostName = Encoding.UTF8.GetString(span),
                    TransportParameters = transportParameters,
                    ClientHandshakeSecret = clientHandshakeSecret.ToArray(),
                    ClientApplicationSecret = clientApplicationSecret.ToArray(),
                    Alpn = alpn
                };
            }
        }

        private sealed class ServerHello
        {
            public required TransportParameters TransportParameters { get; init; }
            public required byte[] ServerHandshakeSecret { get; init; }

            public void Write(QuicWriter writer)
            {
                var sizeSpan = writer.GetWritableSpan(2);
                int written = TransportParameters.Write(writer.AvailableSpan, true, TransportParameters);
                QuicPrimitives.WriteVarInt(sizeSpan, written, 2);
                writer.Advance(written);
                writer.WriteSpan(ServerHandshakeSecret);
            }

            public static ServerHello Read(QuicReader reader)
            {
                if (!reader.TryReadVarInt(out var size)
                    || !TransportParameters.Read(reader.ReadSpan((int)size), true, out var transportParameters)
                    || !reader.TryReadSpan(32, out var serverHandshakeSecret))
                {
                    throw new Exception("Failed to read ServerHello");
                }

                return new ServerHello
                {
                    TransportParameters = transportParameters,
                    ServerHandshakeSecret = serverHandshakeSecret.ToArray()
                };
            }
        }

        private sealed class ServerHandshake
        {
            public required X509Certificate2 ServerCertificate { get; init; }
            public required bool RequireClientCertificate { get; init; }
            public required byte[] ServerApplicationSecret { get; init; }
            public required SslApplicationProtocol NegotiatedAlpn { get; init; }

            public void Write(QuicWriter writer)
            {
                writer.WriteVarInt(ServerCertificate.RawData.Length);
                writer.WriteSpan(ServerCertificate.RawData);
                writer.WriteVarInt(RequireClientCertificate ? 1 : 0);
                writer.WriteSpan(ServerApplicationSecret);
                writer.WriteVarInt(NegotiatedAlpn.Protocol.Length);
                writer.WriteSpan(NegotiatedAlpn.Protocol.Span);
            }

            public static ServerHandshake? TryRead(QuicReader reader)
            {
                if (!reader.TryReadVarInt(out var length)
                    || !reader.TryReadSpan((int)length, out var span)
                    || !reader.TryReadVarInt(out var requireClientCertificate)
                    || !reader.TryReadSpan(32, out var serverApplicationSecret)
                    || !reader.TryReadVarInt(out var alpnLength)
                    || !reader.TryReadSpan((int)alpnLength, out var alpnSpan))
                {
                    return null;
                }

                return new ServerHandshake
                {
                    ServerCertificate = new X509Certificate2(span.ToArray()),
                    RequireClientCertificate = requireClientCertificate != 0,
                    ServerApplicationSecret = serverApplicationSecret.ToArray(),
                    NegotiatedAlpn = new SslApplicationProtocol(alpnSpan.ToArray())
                };
            }
        }

        private sealed class ClientHandshake
        {
            public required X509Certificate2? ClientCertificate { get; init; }

            public void Write(QuicWriter writer)
            {
                if (ClientCertificate != null)
                {
                    writer.WriteVarInt(ClientCertificate.RawData.Length);
                    writer.WriteSpan(ClientCertificate.RawData);
                }
                else
                {
                    writer.WriteVarInt(0);
                }
            }

            public static ClientHandshake? TryRead(QuicReader reader)
            {
                if (!reader.TryReadVarInt(out var length)
                    || !reader.TryReadSpan((int)length, out var span))
                {
                    return null;
                }

                return new ClientHandshake
                {
                    ClientCertificate = length > 0 ? new X509Certificate2(span.ToArray()) : null,
                };
            }
        }

        public bool TryAdvanceHandshake()
        {
            // The handshake flow we want to imitate looks like this:
            //
            // Initial[0]: CRYPTO[CH] ->
            //
            //                                  Initial[0]: CRYPTO[SH] ACK[0]
            //                        Handshake[0]: CRYPTO[EE, CERT, CV, FIN]
            //
            // Initial[1]: ACK[0]
            // Handshake[0]: CRYPTO[FIN], ACK[0]
            //
            //                                           Handshake[1]: ACK[0]

            if (IsHandshakeComplete)
                return true;

            if (IsClient)
            {
                if (!_sentInitial)
                {
                    WriteClientHello();
                    _sentInitial = true;
                }

                if (_recvBufferInitial.ActiveLength > 0)
                {
                    ReadServerHello();
                    WriteLevel = EncryptionLevel.Handshake;
                }

                if (_recvBufferHandshake.ActiveLength > 0)
                {
                    if (ReadServerHandshake())
                    {
                        WriteClientHandshake();

                        WriteLevel = EncryptionLevel.Application;
                        IsHandshakeComplete = true;
                    }
                }
            }
            else // server
            {
                if (_recvBufferInitial.ActiveLength > 0)
                {
                    if (ReadClientHello())
                    {
                        WriteServerHello();
                        WriteServerHandshake();

                        WriteLevel = EncryptionLevel.Handshake;
                    }
                }

                if (_recvBufferHandshake.ActiveLength > 0)
                {
                    if (ReadClientHandshake())
                    {
                        IsHandshakeComplete = true;
                        WriteLevel = EncryptionLevel.Application;

                        // send an improvised fin message
                        AddHandshakeData(EncryptionLevel.Application, _magicBytes);
                    }
                }
            }

           Flush();
           return true;
        }

        private void WriteClientHello()
        {
            var buffer = ArrayPool<byte>.Shared.Rent(10*1024);
            QuicWriter writer = new QuicWriter(new Memory<byte>(buffer));

            new ClientHello{
                HostName = _authOptions.TargetHost!,
                TransportParameters = _localTransportParams,
                ClientHandshakeSecret = _handshakeWriteSecret,
                ClientApplicationSecret = _applicationWriteSecret,
                Alpn = _alpn
            }.Write(writer);

            AddHandshakeData(EncryptionLevel.Initial, writer.Buffer.Span.Slice(0, writer.BytesWritten));
            ArrayPool<byte>.Shared.Return(buffer);
        }

        private void WriteServerHello()
        {
            var buffer = ArrayPool<byte>.Shared.Rent(10*1024);
            QuicWriter writer = new QuicWriter(new Memory<byte>(buffer));

            new ServerHello
            {
                TransportParameters = _localTransportParams,
                ServerHandshakeSecret = _handshakeWriteSecret
            }.Write(writer);

            AddHandshakeData(EncryptionLevel.Initial, writer.Buffer.Span.Slice(0, writer.BytesWritten));
            ArrayPool<byte>.Shared.Return(buffer);
        }

        private void WriteClientHandshake()
        {
            var buffer = ArrayPool<byte>.Shared.Rent(10*1024);
            QuicWriter writer = new QuicWriter(new Memory<byte>(buffer));

            new ClientHandshake
            {
                ClientCertificate = _certRequired ? _authOptions.ClientCertificates![0] as X509Certificate2 : null
            }.Write(writer);

            AddHandshakeData(EncryptionLevel.Handshake, writer.Buffer.Span.Slice(0, writer.BytesWritten));
            ArrayPool<byte>.Shared.Return(buffer);
        }

        private void WriteServerHandshake()
        {
            var buffer = ArrayPool<byte>.Shared.Rent(10*1024);
            QuicWriter writer = new QuicWriter(new Memory<byte>(buffer));

            new ServerHandshake
            {
                ServerCertificate = _authOptions.CertificateContext!.TargetCertificate,
                RequireClientCertificate = _authOptions.RemoteCertRequired,
                ServerApplicationSecret = _applicationWriteSecret,
                NegotiatedAlpn = _negotiatedAlpn
            }.Write(writer);

            AddHandshakeData(EncryptionLevel.Handshake, writer.Buffer.Span.Slice(0, writer.BytesWritten));
            ArrayPool<byte>.Shared.Return(buffer);
        }

        private bool ReadClientHello()
        {
            QuicReader reader = new QuicReader(_recvBufferInitial.ActiveMemory);

            var clientHello = ClientHello.Read(reader);
            _connection._targetHostName = clientHello.HostName;
            _remoteTransportParams = clientHello.TransportParameters;

            SetEncryptionSecrets(EncryptionLevel.Handshake, clientHello.ClientHandshakeSecret, _handshakeWriteSecret);

            // server can derive the application secrets from the first initial
            SetEncryptionSecrets(EncryptionLevel.Application, clientHello.ClientApplicationSecret, _applicationWriteSecret);
            _recvBufferInitial.Discard(reader.BytesRead);

            return NegotiateAlpn(clientHello.Alpn);
        }

        private void ReadServerHello()
        {
            QuicReader reader = new QuicReader(_recvBufferInitial.ActiveMemory);

            var serverHello = ServerHello.Read(reader);
            _remoteTransportParams = serverHello.TransportParameters;

            SetEncryptionSecrets(EncryptionLevel.Handshake, serverHello.ServerHandshakeSecret, _handshakeWriteSecret);
            _recvBufferInitial.Discard(reader.BytesRead);
        }

        private bool ReadClientHandshake()
        {
            QuicReader reader = new QuicReader(_recvBufferHandshake.ActiveMemory);

            var clientHandshake = ClientHandshake.TryRead(reader);
            if (clientHandshake == null)
            {
                return false;
            }

            // TODO: validate client certificate
            _connection._remoteCertificate = clientHandshake.ClientCertificate;
            ValidateCertificate(clientHandshake.ClientCertificate, new X509Certificate2Collection());
            _recvBufferHandshake.Discard(reader.BytesRead);
            return true;
        }

        private bool ReadServerHandshake()
        {
            QuicReader reader = new QuicReader(_recvBufferHandshake.ActiveMemory);

            var serverHandshake = ServerHandshake.TryRead(reader);
            if (serverHandshake == null)
            {
                return false;
            }

            _certRequired = serverHandshake.RequireClientCertificate;
            SetEncryptionSecrets(EncryptionLevel.Application, serverHandshake.ServerApplicationSecret, _applicationWriteSecret);
            _negotiatedAlpn = serverHandshake.NegotiatedAlpn;

            _connection._remoteCertificate = serverHandshake.ServerCertificate;
            // TODO: send additional certs
            ValidateCertificate(serverHandshake.ServerCertificate, new X509Certificate2Collection());
            _recvBufferHandshake.Discard(reader.BytesRead);

            return true;
        }

        public TlsCipherSuite GetNegotiatedCipher() => QuicConstants.InitialCipherSuite;

        public TransportParameters? GetPeerTransportParameters(bool isServer) => _remoteTransportParams;

        public SslApplicationProtocol GetNegotiatedProtocol() => _negotiatedAlpn;

        private void AddHandshakeData(EncryptionLevel level, ReadOnlySpan<byte> data)
        {
            _connection.AddHandshakeData(level, data);
        }

        private void SendTlsAlert(int alert)
        {
            _connection.SendTlsAlert(alert);
        }

        private void SetEncryptionSecrets(EncryptionLevel level, ReadOnlySpan<byte> readSecret,
            ReadOnlySpan<byte> writeSecret)
        {
            _connection.SetEncryptionSecrets(level, readSecret, writeSecret);
        }

        private void Flush()
        {
            _connection.FlushHandshakeData();
        }

        private bool NegotiateAlpn(List<SslApplicationProtocol> clientAlpn)
        {
            foreach (var alpn in clientAlpn)
            {
                if (_alpn.Contains(alpn))
                {
                    _negotiatedAlpn = alpn;
                    return true;
                }
            }

            SendTlsAlert(/* NoApplicationProtocol */ 120);
            return false;
        }

        private static readonly Oid s_serverAuthOid = new Oid("1.3.6.1.5.5.7.3.1", null);
        private static readonly Oid s_clientAuthOid = new Oid("1.3.6.1.5.5.7.3.2", null);

        public unsafe void ValidateCertificate(X509Certificate2? certificate, X509Certificate2Collection additionalCertificates)
        {
            SslPolicyErrors sslPolicyErrors = SslPolicyErrors.None;
            bool wrapException = false;

            X509Chain? chain = null;
            try
            {
                if (certificate is not null)
                {
                    chain = new X509Chain();
                    if (_authOptions.CertificateChainPolicy != null)
                    {
                        chain.ChainPolicy = _authOptions.CertificateChainPolicy;
                    }
                    else
                    {
                        chain.ChainPolicy.RevocationMode = _authOptions.CertificateRevocationCheckMode;
                        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

                        // TODO: configure chain.ChainPolicy.CustomTrustStore to mirror behavior of SslStream.VerifyRemoteCertificate (https://github.com/dotnet/runtime/issues/73053)
                    }

                    // set ApplicationPolicy unless already provided.
                    if (chain.ChainPolicy.ApplicationPolicy.Count == 0)
                    {
                        // Authenticate the remote party: (e.g. when operating in server mode, authenticate the client).
                        chain.ChainPolicy.ApplicationPolicy.Add(IsClient ? s_serverAuthOid : s_clientAuthOid);
                    }

                    chain.ChainPolicy.ExtraStore.AddRange(additionalCertificates);

                    bool checkCertName = !chain!.ChainPolicy!.VerificationFlags.HasFlag(X509VerificationFlags.IgnoreInvalidName);
                    sslPolicyErrors |= CertificateValidation.BuildChainAndVerifyProperties(chain!, certificate, checkCertName, !IsClient, TargetHostNameHelper.NormalizeHostName(_authOptions.TargetHost), IntPtr.Zero, 0);
                }
                else if (_authOptions.RemoteCertRequired)
                {
                    sslPolicyErrors |= SslPolicyErrors.RemoteCertificateNotAvailable;
                }

                if (_authOptions.CertValidationDelegate is not null)
                {
                    wrapException = true;
                    if (!_authOptions.CertValidationDelegate(_connection, certificate, chain, sslPolicyErrors))
                    {
                        wrapException = false;

                        SendTlsAlert(/* BadCertificate */ 42);
                    }
                }
                else if (sslPolicyErrors != SslPolicyErrors.None)
                {
                    SendTlsAlert(/* BadCertificate */ 42);
                }
            }
            catch
            {
                if (wrapException)
                {
                    SendTlsAlert(/* Internal Error */ 80);
                }
            }
            finally
            {
                if (chain is not null)
                {
                    X509ChainElementCollection elements = chain.ChainElements;
                    for (int i = 0; i < elements.Count; i++)
                    {
                        elements[i].Certificate.Dispose();
                    }

                    chain.Dispose();
                }
            }

        }

    }


    // copy of the same type from System.Net.Security but without making use of internal overloads not available here
    internal sealed class SslAuthenticationOptions
    {
        internal SslAuthenticationOptions()
        {
            TargetHost = string.Empty;
        }

        internal void UpdateOptions(SslClientAuthenticationOptions sslClientAuthenticationOptions)
        {
            if (CertValidationDelegate == null)
            {
                CertValidationDelegate = sslClientAuthenticationOptions.RemoteCertificateValidationCallback;
            }
            else if (sslClientAuthenticationOptions.RemoteCertificateValidationCallback != null &&
                     CertValidationDelegate != sslClientAuthenticationOptions.RemoteCertificateValidationCallback)
            {
                // Callback was set in constructor to different value.
                throw new InvalidOperationException(nameof(RemoteCertificateValidationCallback));
            }

            if (CertSelectionDelegate == null)
            {
                CertSelectionDelegate = sslClientAuthenticationOptions.LocalCertificateSelectionCallback;
            }
            else if (sslClientAuthenticationOptions.LocalCertificateSelectionCallback != null &&
                     CertSelectionDelegate != sslClientAuthenticationOptions.LocalCertificateSelectionCallback)
            {
                throw new InvalidOperationException(nameof(LocalCertificateSelectionCallback));
            }

            // Common options.
            AllowRenegotiation = sslClientAuthenticationOptions.AllowRenegotiation;
            AllowTlsResume = sslClientAuthenticationOptions.AllowTlsResume;
            ApplicationProtocols = sslClientAuthenticationOptions.ApplicationProtocols;
            CheckCertName = !(sslClientAuthenticationOptions.CertificateChainPolicy?.VerificationFlags.HasFlag(X509VerificationFlags.IgnoreInvalidName) == true);
            EnabledSslProtocols = FilterOutIncompatibleSslProtocols(sslClientAuthenticationOptions.EnabledSslProtocols);
            EncryptionPolicy = sslClientAuthenticationOptions.EncryptionPolicy;
            IsServer = false;
            RemoteCertRequired = true;
            CertificateContext = sslClientAuthenticationOptions.ClientCertificateContext;
            TargetHost = sslClientAuthenticationOptions.TargetHost ?? string.Empty;

            // Client specific options.
            CertificateRevocationCheckMode = sslClientAuthenticationOptions.CertificateRevocationCheckMode;
            ClientCertificates = sslClientAuthenticationOptions.ClientCertificates;
            CipherSuitesPolicy = sslClientAuthenticationOptions.CipherSuitesPolicy;

            if (sslClientAuthenticationOptions.CertificateChainPolicy != null)
            {
                CertificateChainPolicy = sslClientAuthenticationOptions.CertificateChainPolicy.Clone();
            }
        }

        internal void UpdateOptions(ServerOptionsSelectionCallback optionCallback, object? state)
        {
            CheckCertName = false;
            TargetHost = string.Empty;
            IsServer = true;
            UserState = state;
            ServerOptionDelegate = optionCallback;
        }

        internal void UpdateOptions(SslServerAuthenticationOptions sslServerAuthenticationOptions)
        {
            if (sslServerAuthenticationOptions.ServerCertificate == null &&
                sslServerAuthenticationOptions.ServerCertificateContext == null &&
                sslServerAuthenticationOptions.ServerCertificateSelectionCallback == null &&
                CertSelectionDelegate == null)
            {
                throw new NotSupportedException("net_ssl_io_no_server_cert");
            }

            if ((sslServerAuthenticationOptions.ServerCertificate != null ||
                 sslServerAuthenticationOptions.ServerCertificateContext != null ||
                 CertSelectionDelegate != null) &&
                sslServerAuthenticationOptions.ServerCertificateSelectionCallback != null)
            {
                throw new InvalidOperationException(nameof(ServerCertificateSelectionCallback));
            }

            if (CertValidationDelegate == null)
            {
                CertValidationDelegate = sslServerAuthenticationOptions.RemoteCertificateValidationCallback;
            }
            else if (sslServerAuthenticationOptions.RemoteCertificateValidationCallback != null &&
                     CertValidationDelegate != sslServerAuthenticationOptions.RemoteCertificateValidationCallback)
            {
                // Callback was set in constructor to differet value.
                throw new InvalidOperationException(nameof(RemoteCertificateValidationCallback));
            }

            IsServer = true;
            AllowRenegotiation = sslServerAuthenticationOptions.AllowRenegotiation;
            AllowTlsResume = sslServerAuthenticationOptions.AllowTlsResume;
            ApplicationProtocols = sslServerAuthenticationOptions.ApplicationProtocols;
            EnabledSslProtocols = FilterOutIncompatibleSslProtocols(sslServerAuthenticationOptions.EnabledSslProtocols);
            EncryptionPolicy = sslServerAuthenticationOptions.EncryptionPolicy;
            RemoteCertRequired = sslServerAuthenticationOptions.ClientCertificateRequired;
            CipherSuitesPolicy = sslServerAuthenticationOptions.CipherSuitesPolicy;
            CertificateRevocationCheckMode = sslServerAuthenticationOptions.CertificateRevocationCheckMode;
            if (sslServerAuthenticationOptions.ServerCertificateContext != null)
            {
                CertificateContext = sslServerAuthenticationOptions.ServerCertificateContext;
            }
            else if (sslServerAuthenticationOptions.ServerCertificate != null)
            {
                X509Certificate2? certificateWithKey = sslServerAuthenticationOptions.ServerCertificate as X509Certificate2;

                CertificateContext = SslStreamCertificateContext.Create(certificateWithKey!, additionalCertificates: null, offline: false, trust: null);
            }

            if (sslServerAuthenticationOptions.ServerCertificateSelectionCallback != null)
            {
                ServerCertSelectionDelegate = sslServerAuthenticationOptions.ServerCertificateSelectionCallback;
            }

            if (sslServerAuthenticationOptions.CertificateChainPolicy != null)
            {
                CertificateChainPolicy = sslServerAuthenticationOptions.CertificateChainPolicy.Clone();
            }
        }

        private static SslProtocols FilterOutIncompatibleSslProtocols(SslProtocols protocols)
        {
            if (protocols.HasFlag(SslProtocols.Tls12) || protocols.HasFlag(SslProtocols.Tls13))
            {
#pragma warning disable 0618
                // SSL2 is mutually exclusive with >= TLS1.2
                // On Windows10 SSL2 flag has no effect but on earlier versions of the OS
                // opting into both SSL2 and >= TLS1.2 causes negotiation to always fail.
                protocols &= ~SslProtocols.Ssl2;
#pragma warning restore 0618
            }

            return protocols;
        }

        internal bool AllowRenegotiation { get; set; }
        internal string TargetHost { get; set; }
        internal X509CertificateCollection? ClientCertificates { get; set; }
        internal List<SslApplicationProtocol>? ApplicationProtocols { get; set; }
        internal bool IsServer { get; set; }
        internal bool IsClient => !IsServer;
        internal SslStreamCertificateContext? CertificateContext { get; set; }
        internal SslProtocols EnabledSslProtocols { get; set; }
        internal X509RevocationMode CertificateRevocationCheckMode { get; set; }
        internal EncryptionPolicy EncryptionPolicy { get; set; }
        internal bool RemoteCertRequired { get; set; }
        internal bool CheckCertName { get; set; }
        internal RemoteCertificateValidationCallback? CertValidationDelegate { get; set; }
        internal LocalCertificateSelectionCallback? CertSelectionDelegate { get; set; }
        internal ServerCertificateSelectionCallback? ServerCertSelectionDelegate { get; set; }
        internal CipherSuitesPolicy? CipherSuitesPolicy { get; set; }
        internal object? UserState { get; set; }
        internal ServerOptionsSelectionCallback? ServerOptionDelegate { get; set; }
        internal X509ChainPolicy? CertificateChainPolicy { get; set; }
        internal bool AllowTlsResume { get; set; }
    }
}
