// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace System.Net.Quic.Tests;

[Collection(nameof(DisableParallelization))]
[ConditionalClass(typeof(QuicTestBase), nameof(QuicTestBase.IsSupported))]
public sealed class QuicConnectionDatagramTests : QuicTestBase
{
    public QuicConnectionDatagramTests(ITestOutputHelper output) : base(output) { }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public Task DatagramSendAdvertised_SetsPropertiesCorrectly(bool serverAdvertised, bool clientAdvertised)
    {
        var clientOptions = CreateQuicClientOptions(new IPEndPoint(IPAddress.Loopback, 0));
        clientOptions.ReceiveDatagramCallback = clientAdvertised ? (connection, datagram) => { } : null;

        var serverOptions = CreateQuicServerOptions();
        serverOptions.ReceiveDatagramCallback = serverAdvertised ? (connection, datagram) => { } : null;

        return RunClientServer(client =>
        {
            AssertProperties(serverAdvertised, clientAdvertised, client);
            return Task.CompletedTask;
        }, server =>
        {
            AssertProperties(clientAdvertised, serverAdvertised, server);
            return Task.CompletedTask;
        },
        clientOptions: clientOptions, 
        listenerOptions: CreateQuicListenerOptions(serverOptions: serverOptions));

        static void AssertProperties(bool peerAdvertised, bool localAdvertised, QuicConnection connection)
        {
            Assert.Equal(peerAdvertised, connection.DatagramSendEnabled);
            Assert.Equal(localAdvertised, connection.DatagramReceiveEnabled);
            
            if (peerAdvertised)
            {
                Assert.True(connection.DatagramMaxSendLength > 0, "connection.DatagramMaxSendLength > 0");
            }
            else
            {
                Assert.Equal(0, connection.DatagramMaxSendLength);
            }
        }
    }
}