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

    [Fact]
    public Task DatagramSendDisabled_SendThrows()
    {
        var clientOptions = CreateQuicClientOptions(new IPEndPoint(IPAddress.Loopback, 0));
        clientOptions.ReceiveDatagramCallback = null;

        var serverOptions = CreateQuicServerOptions();
        serverOptions.ReceiveDatagramCallback = null;

        return RunClientServer(client =>
        {
            return Assert.ThrowsAsync<InvalidOperationException>(() => client.SendDatagramAsync(new byte[1]).AsTask());
        }, server =>
        {
            return Assert.ThrowsAsync<InvalidOperationException>(() => server.SendDatagramAsync(new byte[1]).AsTask());
        },
        clientOptions: clientOptions,
        listenerOptions: CreateQuicListenerOptions(serverOptions: serverOptions));
    }

    [Fact]
    public Task DatagramSend_Receive_Success()
    {
        TaskCompletionSource<byte[]> tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

        byte[] datagram = new byte[1000];
        Random.Shared.NextBytes(datagram);

        var clientOptions = CreateQuicClientOptions(new IPEndPoint(IPAddress.Loopback, 0));
        clientOptions.ReceiveDatagramCallback = (_, datagram) =>
        {
            tcs.TrySetResult(datagram.ToArray());
        };

        var serverOptions = CreateQuicServerOptions();
        serverOptions.ReceiveDatagramCallback = null;

        return RunClientServer(async client =>
        {
            var dgram = await tcs.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(datagram, dgram);
        }, server =>
        {
            return server.SendDatagramAsync(datagram).AsTask();
        },
        clientOptions: clientOptions,
        listenerOptions: CreateQuicListenerOptions(serverOptions: serverOptions));
    }

    [Fact]
    public Task DatagramSend_TooBig_Fails()
    {
        byte[] datagram = new byte[2000];
        Random.Shared.NextBytes(datagram);

        var clientOptions = CreateQuicClientOptions(new IPEndPoint(IPAddress.Loopback, 0));
        clientOptions.ReceiveDatagramCallback = (_, datagram) => { };

        var serverOptions = CreateQuicServerOptions();
        serverOptions.ReceiveDatagramCallback = null;

        return RunClientServer(client =>
        {
            return Task.CompletedTask;
        }, server =>
        {
            return server.SendDatagramAsync(datagram).AsTask();
        },
        clientOptions: clientOptions,
        listenerOptions: CreateQuicListenerOptions(serverOptions: serverOptions));
    }
}