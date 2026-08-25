// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Net.Test.Common;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;
using TestCertificates = System.Net.Test.Common.Configuration.Certificates;

namespace System.Net.Security.Tests
{
    public class ExportKeyingMaterialTest
    {
        private static readonly byte[] s_label = "EXPORTER-test-label"u8.ToArray();
        private static readonly byte[] s_otherLabel = "EXPORTER-other-label"u8.ToArray();
        private static readonly byte[] s_context = "context-value"u8.ToArray();

        private static async Task<(SslStream Client, SslStream Server)> AuthenticateAsync(SslProtocols protocol = SslProtocols.Tls12)
        {
            (Stream clientStream, Stream serverStream) = TestHelper.GetConnectedStreams();
            var client = new SslStream(clientStream, leaveInnerStreamOpen: false, TestHelper.AllowAnyServerCertificate);
            var server = new SslStream(serverStream, leaveInnerStreamOpen: false);

            using X509Certificate2 serverCertificate = TestCertificates.GetServerCertificate();

            Task clientTask = client.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = protocol,
            });
            Task serverTask = server.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = serverCertificate,
                EnabledSslProtocols = protocol,
            });

            await Task.WhenAll(clientTask, serverTask).WaitAsync(TimeSpan.FromSeconds(30));
            return (client, server);
        }

        [Theory]
        [InlineData(SslProtocols.Tls12)]
        [InlineData(SslProtocols.Tls13)]
        [PlatformSpecific(TestPlatforms.Linux | TestPlatforms.FreeBSD | TestPlatforms.Windows)]
        public async Task ExportKeyingMaterial_SameInputs_PeersDeriveIdenticalMaterial(SslProtocols protocol)
        {
            if (protocol == SslProtocols.Tls13 && !PlatformDetection.SupportsTls13)
            {
                return;
            }

            (SslStream client, SslStream server) = await AuthenticateAsync(protocol);
            try
            {
                byte[] clientMaterial = new byte[32];
                byte[] serverMaterial = new byte[32];

                client.ExportKeyingMaterial(s_label, s_context, clientMaterial);
                server.ExportKeyingMaterial(s_label, s_context, serverMaterial);

                Assert.Equal(clientMaterial, serverMaterial);
                Assert.NotEqual(new byte[32], clientMaterial);
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [Fact]
        [PlatformSpecific(TestPlatforms.Linux | TestPlatforms.FreeBSD | TestPlatforms.Windows)]
        public async Task ExportKeyingMaterial_NoContextOverload_PeersDeriveIdenticalMaterial()
        {
            (SslStream client, SslStream server) = await AuthenticateAsync();
            try
            {
                byte[] clientMaterial = new byte[48];
                byte[] serverMaterial = new byte[48];

                client.ExportKeyingMaterial(s_label, clientMaterial);
                server.ExportKeyingMaterial(s_label, serverMaterial);

                Assert.Equal(clientMaterial, serverMaterial);
                Assert.NotEqual(new byte[48], clientMaterial);
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [Fact]
        [PlatformSpecific(TestPlatforms.Linux | TestPlatforms.FreeBSD | TestPlatforms.Windows)]
        public async Task ExportKeyingMaterial_DifferentLabels_ProduceDifferentMaterial()
        {
            (SslStream client, SslStream server) = await AuthenticateAsync();
            try
            {
                byte[] first = new byte[32];
                byte[] second = new byte[32];

                client.ExportKeyingMaterial(s_label, first);
                client.ExportKeyingMaterial(s_otherLabel, second);

                Assert.NotEqual(first, second);
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [Fact]
        [PlatformSpecific(TestPlatforms.Linux | TestPlatforms.FreeBSD | TestPlatforms.Windows)]
        public async Task ExportKeyingMaterial_DifferentContexts_ProduceDifferentMaterial()
        {
            (SslStream client, SslStream server) = await AuthenticateAsync();
            try
            {
                byte[] first = new byte[32];
                byte[] second = new byte[32];

                client.ExportKeyingMaterial(s_label, s_context, first);
                client.ExportKeyingMaterial(s_label, "different-context"u8, second);

                Assert.NotEqual(first, second);
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [Fact]
        [PlatformSpecific(TestPlatforms.Linux | TestPlatforms.FreeBSD | TestPlatforms.Windows)]
        public async Task ExportKeyingMaterial_SameInputs_IsDeterministic()
        {
            (SslStream client, SslStream server) = await AuthenticateAsync();
            try
            {
                byte[] first = new byte[64];
                byte[] second = new byte[64];

                client.ExportKeyingMaterial(s_label, s_context, first);
                client.ExportKeyingMaterial(s_label, s_context, second);

                Assert.Equal(first, second);
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [Fact]
        [PlatformSpecific(TestPlatforms.Linux | TestPlatforms.FreeBSD)]
        public async Task ExportKeyingMaterial_NoContextVsEmptyContext_ProduceDifferentMaterial()
        {
            // RFC 5705 distinguishes an absent context from an empty (zero-length) context.
            // OpenSSL honors this distinction; Schannel cannot represent a present-but-empty
            // context, so this behavior is validated only on the OpenSSL-backed platforms.
            (SslStream client, SslStream server) = await AuthenticateAsync();
            try
            {
                byte[] noContext = new byte[32];
                byte[] emptyContext = new byte[32];

                client.ExportKeyingMaterial(s_label, noContext);
                client.ExportKeyingMaterial(s_label, ReadOnlySpan<byte>.Empty, emptyContext);

                Assert.NotEqual(noContext, emptyContext);
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [Fact]
        [PlatformSpecific(TestPlatforms.Linux | TestPlatforms.FreeBSD | TestPlatforms.Windows)]
        public async Task ExportKeyingMaterial_EmptyOutput_IsNoOp()
        {
            (SslStream client, SslStream server) = await AuthenticateAsync();
            try
            {
                client.ExportKeyingMaterial(s_label, Span<byte>.Empty);
                client.ExportKeyingMaterial(s_label, s_context, Span<byte>.Empty);
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [Fact]
        public void ExportKeyingMaterial_BeforeHandshake_Throws()
        {
            using var stream = new SslStream(new MemoryStream());
            Assert.Throws<InvalidOperationException>(() => stream.ExportKeyingMaterial(s_label, new byte[16]));
            Assert.Throws<InvalidOperationException>(() => stream.ExportKeyingMaterial(s_label, s_context, new byte[16]));
        }

        [Fact]
        [PlatformSpecific(TestPlatforms.OSX)]
        public async Task ExportKeyingMaterial_UnsupportedPlatform_ThrowsPlatformNotSupported()
        {
            (SslStream client, SslStream server) = await AuthenticateAsync();
            try
            {
                Assert.Throws<PlatformNotSupportedException>(() => client.ExportKeyingMaterial(s_label, new byte[16]));
                Assert.Throws<PlatformNotSupportedException>(() => client.ExportKeyingMaterial(s_label, s_context, new byte[16]));
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }
    }
}
