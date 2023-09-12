// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Net.Quic.Implementations.Managed;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Frames;
using System.Net.Quic.Implementations.Managed.Internal.Recovery;
using System.Net.Quic.Implementations.Managed.Internal.Streams;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using AckFrame = System.Net.Quic.Tests.Harness.AckFrame;
using ConnectionCloseFrame = System.Net.Quic.Tests.Harness.ConnectionCloseFrame;
using MaxStreamDataFrame = System.Net.Quic.Tests.Harness.MaxStreamDataFrame;
using StopSendingFrame = System.Net.Quic.Tests.Harness.StopSendingFrame;
using StreamFrame = System.Net.Quic.Tests.Harness.StreamFrame;

namespace System.Net.Quic.Tests
{
    public class StreamTests : ManualTransmissionQuicTestBase
    {
        public StreamTests(ITestOutputHelper output)
            : base(output)
        {
            // all tests start after connection has been established
            EstablishConnection();
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task SimpleStreamOpen(bool unidirectional)
        {
            byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            var clientStream = await Client.OpenStream(unidirectional);
            Assert.True(clientStream.CanWrite);
            Assert.Equal(!unidirectional, clientStream.CanRead);
            clientStream.Write(data);
            clientStream.Flush();

            Intercept1RttFrame<StreamFrame>(Client, Server, frame =>
            {
                Assert.Equal(clientStream.Id, frame.StreamId);
                Assert.Equal(0u, frame.Offset);
                Assert.Equal(data, frame.StreamData);
                Assert.False(frame.Fin);
            });

            var serverStream = Server.AcceptStream();
            Assert.NotNull(serverStream);
            Assert.Equal(clientStream.Id, serverStream!.Id);
            Assert.True(serverStream.CanRead);
            Assert.Equal(!unidirectional, serverStream.CanWrite);

            var read = new byte[data.Length];
            int bytesRead = serverStream.Read(read);
            Assert.Equal(data.Length, bytesRead);
            Assert.Equal(data, read);
        }

        [Fact]
        public async Task SendsFinWithLastFrame()
        {
            byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            var clientStream = await Client.OpenStream(true);
            clientStream.Write(data);
            clientStream.Flush();
            clientStream.CompleteWrites();

            Intercept1RttFrame<StreamFrame>(Client, Server, frame =>
            {
                Assert.True(frame.Fin);
            });
        }


        [Fact]
        public async Task SendsEmptyStreamFrameWithFin()
        {
            byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            var clientStream = await Client.OpenStream(true);

            // send data before marking end of stream
            clientStream.Write(data);
            clientStream.Flush();
            Intercept1RttFrame<StreamFrame>(Client, Server, frame =>
            {
                Assert.False(frame.Fin);
            });

            // no more data to send, just the fin bit
            clientStream.CompleteWrites();
            Intercept1RttFrame<StreamFrame>(Client, Server, frame =>
            {
                Assert.Empty(frame.StreamData);
                Assert.True(frame.Fin);
            });

            // don't repeat the frame
            InterceptFlight(Client, Server, flight =>
            {
                Assert.Empty(flight.Packets);
            });
        }

        [Fact]
        public async Task ClosesConnectionWhenStreamLimitIsExceeded()
        {
            byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            var clientStream = await Client.OpenStream(true);
            clientStream.Write(data);
            clientStream.Flush();
            Intercept1RttFrame<StreamFrame>(Client, Server, frame =>
            {
                // make sure the stream id is above bounds
                frame.StreamId += ServerOptions.MaxInboundUnidirectionalStreams << 2 + 4;
            });

            Send1Rtt(Server, Client).ShouldHaveConnectionClose(
                TransportErrorCode.StreamLimitError,
                QuicTransportError.StreamsLimitViolated,
                FrameType.Stream | FrameType.StreamLenBit);
        }

        [Fact]
        public async Task ClosesConnectionWhenSendingPastMaxRepresentableOffset()
        {
            byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            var clientStream = await Client.OpenStream(true);
            clientStream.Write(data);
            clientStream.Flush();
            Intercept1RttFrame<StreamFrame>(Client, Server,
                frame => { frame.Offset = StreamHelpers.MaxStreamOffset; });

            Send1Rtt(Server, Client).ShouldHaveConnectionClose(
                TransportErrorCode.FrameEncodingError,
                QuicTransportError.UnableToDeserialize,
                FrameType.Stream | FrameType.StreamLenBit | FrameType.StreamOffBit);
        }

        [Fact]
        public async Task ClosesConnectionWhenSendingPastFin()
        {
            byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            var clientStream = await Client.OpenStream(true);
            clientStream.Write(data);
            clientStream.Flush();
            Intercept1RttFrame<StreamFrame>(Client, Server,
                frame => { frame.Offset = StreamHelpers.MaxStreamOffset; });

            Send1Rtt(Server, Client).ShouldHaveConnectionClose(
                TransportErrorCode.FrameEncodingError,
                QuicTransportError.UnableToDeserialize,
                 FrameType.Stream | FrameType.StreamLenBit | FrameType.StreamOffBit);
        }

        [Fact]
        public async Task ClosesConnectionWhenSendingInNonReadableStream()
        {
            byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            var clientStream = await Client.OpenStream(true);
            clientStream.Write(data);
            clientStream.Flush();
            Intercept1RttFrame<StreamFrame>(Client, Server, frame =>
            {
                // use the only type of stream into which client cannot send
                frame.StreamId = StreamHelpers.ComposeStreamId(StreamType.ServerInitiatedUnidirectional, 0);
            });

            Send1Rtt(Server, Client).ShouldHaveConnectionClose(
                TransportErrorCode.StreamStateError,
                QuicTransportError.StreamNotWritable,
                FrameType.Stream | FrameType.StreamLenBit);
        }

        [Fact]
        public async Task ClosesConnectionWhenSendingPastStreamMaxData()
        {
            byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            var clientStream = await Client.OpenStream(true);
            clientStream.Write(data);
            clientStream.Flush();
            Intercept1RttFrame<StreamFrame>(Client, Server,
                frame => { frame.Offset = TransportParameters.DefaultMaxStreamData - 1; });

            Send1Rtt(Server, Client).ShouldHaveConnectionClose(
                TransportErrorCode.FlowControlError,
                QuicTransportError.StreamMaxDataViolated,
                FrameType.Stream | FrameType.StreamLenBit | FrameType.StreamOffBit);
        }

        [Fact]
        public async Task ClosesConnectionWhenSendingPastConnectionMaxData()
        {
            byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            var clientStream = await Client.OpenStream(true);
            clientStream.Write(data);
            clientStream.Flush();
            Intercept1RttFrame<StreamFrame>(Client, Server,
                frame => { frame.Offset = TransportParameters.DefaultMaxData - 1; });

            Send1Rtt(Server, Client).ShouldHaveConnectionClose(
                TransportErrorCode.FlowControlError,
                QuicTransportError.MaxDataViolated,
                 FrameType.Stream | FrameType.StreamLenBit | FrameType.StreamOffBit);
        }

        [Fact]
        public async Task ResendsDataAfterLoss()
        {
            byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            var clientStream = await Client.OpenStream(true);
            clientStream.Write(data);
            clientStream.Flush();

            // lose the first packet with stream data
            Lose1RttPacketWithFrame<StreamFrame>(Client);

            clientStream.Write(data);
            clientStream.Flush();
            CurrentTimestamp += RecoveryController.InitialRtt * 1;
            // deliver second packet with more data
            Send1RttWithFrame<StreamFrame>(Client, Server);

            // send ack back, leading the client to believe that first packet was lost
            CurrentTimestamp += RecoveryController.InitialRtt * 1;
            Send1Rtt(Server, Client).ShouldHaveFrame<AckFrame>();

            // resend original data
            var frame = Send1Rtt(Client, Server).ShouldHaveFrame<StreamFrame>();
            Assert.Equal(0, frame.Offset);
            Assert.Equal(data, frame.StreamData);
        }

        [Fact]
        public async Task ClosesConnectionOnInvalidStreamId_StreamMaxDataFrame()
        {
            byte[] data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            byte[] recvBuf = new byte[data.Length];

            var senderStream = await Client.OpenStream(true);
            senderStream.Write(data);
            senderStream.Flush();
            Send1Rtt(Client, Server);

            // read data
            var receiverStream = Server.AcceptStream();
            Assert.NotNull(receiverStream);
            receiverStream!.Read(recvBuf);

            Server.Ping();
            Intercept1Rtt(Server, Client, packet =>
            {
                // make sure the id above the client-specified limit
                packet.Frames.Add(new MaxStreamDataFrame()
                {
                    StreamId = ClientOptions.MaxInboundUnidirectionalStreams * 4 + 1,
                });
            });

            Send1Rtt(Client, Server)
                .ShouldHaveConnectionClose(TransportErrorCode.StreamLimitError,
                    QuicTransportError.StreamsLimitViolated, FrameType.MaxStreamData);
        }

        // TODO: reflect API changes
        // [Fact]
        // public async Task ShutdownCompleted_Cancelled()
        // {
        //     var stream = await Client.OpenStream(true);
        //     var cts = new CancellationTokenSource();
        //     var testTask = Assert.ThrowsAsync<OperationCanceledException>(
        //         () => stream.ShutdownCompleted(cts.Token).AsTask());

        //     // signal the cancellation
        //     cts.Cancel();

        //     await testTask;
        // }

        // [Fact]
        // public async Task ShutdownCompleted_CompletedOnConnectionClose()
        // {
        //     var stream = await Client.OpenStream(true);
        //     var shutdownWriteCompletedTask = stream.ShutdownCompleted();

        //     // receiving connection close implicitly closes all streams
        //     Server.Ping();
        //     Intercept1Rtt(Server, Client, packet =>
        //     {
        //         packet.Frames.Add(new ConnectionCloseFrame()
        //         {
        //             ErrorCode = TransportErrorCode.InternalError,
        //             ReasonPhrase = "Test Error",
        //         });
        //     });

        //     await shutdownWriteCompletedTask.AsTask().WaitAsync(TimeSpan.FromMilliseconds(500));
        // }

        // [Fact]
        // public async Task ShutdownCompleted_ExceptionWhenWriteAborted()
        // {
        //     var stream = await Client.OpenStream(true);
        //     var testTask =
        //         Assert.ThrowsAsync<QuicStreamAbortedException>(async () => await stream.ShutdownCompleted());

        //     stream.AbortWrite(0);

        //     await testTask;
        // }

        [Fact]
        public async Task AbortRead_ShouldElicitStopSendingFrame()
        {
            var stream = await Client.OpenStream(false);
            long errorCode = 15;
            stream.AbortRead(errorCode);

            var frame = Send1RttWithFrame<StopSendingFrame>(Client, Server);
            Assert.Equal(stream.Id, frame.StreamId);
            Assert.Equal(errorCode, frame.ApplicationErrorCode);
        }
    }
}
