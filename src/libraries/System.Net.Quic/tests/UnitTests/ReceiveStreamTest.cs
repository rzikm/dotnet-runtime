// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Streams;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace System.Net.Quic.Tests
{
    public class ReceiveStreamTest
    {
        private ReceiveStream stream = new ReceiveStream(1000);

        private void ReceiveBytes(long offset, int count, bool end = false)
        {
            Span<byte> tmp = stackalloc byte[count];

            // generate ascending integers so that we can test for data correctness
            for (int i = 0; i < tmp.Length; i++)
            {
                tmp[i] = (byte)(offset + i);
            }

            stream.Receive(offset, tmp, end);
        }

        [Fact]
        public void ReceivesInOrderData()
        {
            ReceiveBytes(0, 10);
            var destination = new byte[10];
            Assert.Equal(10u, stream.BytesAvailable);
            stream.Deliver(destination);

            Assert.Equal(new byte[]{0,1,2,3,4,5,6,7,8,9}, destination);
            Assert.Equal(10u, stream.BytesRead);
            Assert.Equal(0u, stream.BytesAvailable);
        }

        [Fact]
        public void ReceivesOutOfOrderData()
        {
            ReceiveBytes(5, 5);
            Assert.Equal(0u, stream.BytesAvailable);
            ReceiveBytes(0, 5);
            Assert.Equal(10u, stream.BytesAvailable);

            var destination = new byte[10];
            stream.Deliver(destination);

            Assert.Equal(new byte[]{0,1,2,3,4,5,6,7,8,9}, destination);
        }

        [Fact]
        public void ReceiveDuplicateData()
        {
            ReceiveBytes(0, 5);
            ReceiveBytes(10, 5);
            ReceiveBytes(20, 5);

            ReceiveBytes(0, 25);

            Assert.Equal(25u, stream.BytesAvailable);
            var destination = new byte[25];

            stream.Deliver(destination);
            Assert.Equal(Enumerable.Range(0, 25).Select(i => (byte) i), destination);
        }

        [Fact]
        public async Task BlocksWhenNoDataAvailable()
        {
            var destination = new byte[10];
            var task = stream.DeliverAsync(destination, CancellationToken.None);
            Assert.False(task.IsCompleted);

            ReceiveBytes(0, 10);
            int written = await task.AsTask().TimeoutAfter(5_000);
            Assert.Equal(10, written);
        }

        [Fact]
        public async Task DoesNotBlockIfDataAvailable()
        {
            ReceiveBytes(0, 10);
            var destination = new byte[10];
            var task = stream.DeliverAsync(destination, CancellationToken.None);
            Assert.True(task.IsCompleted);

            int written = await task;
            Assert.Equal(10, written);
        }

        [Fact]
        public async Task DoesNotBlockIfAllDataRead()
        {
            ReceiveBytes(0, 10, true);
            var destination = new byte[10];
            stream.Deliver(destination);

            // all data has been read, and stream is finished
            Assert.Equal(0, stream.BytesAvailable);
            var task = stream.DeliverAsync(destination, CancellationToken.None);
            Assert.True(task.IsCompleted);

            Assert.Equal(0, await task);
        }

        [Fact]
        public async Task EmptyFrameWithFinUnblocksReader()
        {
            var destination = new byte[10];
            var task = stream.DeliverAsync(destination, CancellationToken.None);
            Assert.False(task.IsCompleted);

            ReceiveBytes(0, 0, true);

            int written = await task.AsTask().TimeoutAfter(100);
            Assert.Equal(0, written);
        }

        [Fact]
        public async Task OutOfOrderFinBit()
        {
            var destination = new byte[10];

            ReceiveBytes(5, 5, true);
            ReceiveBytes(0, 5);

            int read = stream.Deliver(destination);
            Assert.Equal(10, read);
            var task = stream.DeliverAsync(destination, CancellationToken.None);

            // All data have been read, no blocking is expected.
            Assert.True(task.IsCompleted);
            Assert.Equal(0, await task);
        }

        [Fact]
        public void IncreasesMaxDataAfterDelivery()
        {
            var destination = new byte[10];
            ReceiveBytes(0, 10);
            long oldMaxData = stream.MaxData;

            stream.Deliver(destination);

            Assert.Equal(oldMaxData + 10, stream.MaxData);
        }

        [Fact]
        public async Task RequestingAbortAbortsReaders()
        {
            var destination = new byte[100];

            var exnTask = Assert.ThrowsAsync<QuicStreamAbortedException>(
                () => stream.DeliverAsync(destination, CancellationToken.None).AsTask());

            stream.RequestAbort(10000);

            var exn = await exnTask.TimeoutAfter(5_000);
            Assert.Equal(10000, exn.ErrorCode);
        }
    }
}
