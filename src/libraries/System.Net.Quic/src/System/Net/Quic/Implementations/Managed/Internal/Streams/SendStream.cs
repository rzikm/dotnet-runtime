// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Managed.Internal.Streams
{
    /// <summary>
    ///     Structure for containing outbound stream data, represents sending direction of the stream.
    /// </summary>
    internal sealed class SendStream
    {
        // TODO-RZ: tie this to control flow limits
        private const int MaximumHeldChunks = 20;

        private object SyncObject => _toSendChannel;

        /// <summary>
        ///     Current state of the stream.
        /// </summary>
        internal SendStreamState StreamState { get; private set; }

        /// <summary>
        ///     True if the stream is in terminal state and no state changes are possible.
        /// </summary>
        internal bool CanReleaseFlowControl => StreamState switch
        {
            SendStreamState.DataReceived => true,
            SendStreamState.WantReset => true,
            SendStreamState.ResetSent => true,
            SendStreamState.ResetReceived => true,
            _ => false
        };

        /// <summary>
        ///     Ranges of bytes acked by the peer.
        /// </summary>
        private readonly RangeSet _acked = new RangeSet();

        /// <summary>
        ///     Ranges of bytes currently in-flight.
        /// </summary>
        private readonly RangeSet _inFlight = new RangeSet();

        /// <summary>
        ///     Ranges of bytes awaiting to be sent.
        /// </summary>
        private readonly RangeSet _pending = new RangeSet();

        /// <summary>
        ///     True if the peer has acked a frame specifying the final size of the stream.
        /// </summary>
        internal bool FinAcked { get; private set; }

        /// <summary>
        ///     Is completed when all data are sent (and acknowledged), or when stream is aborted.
        /// </summary>
        internal SingleEventValueTaskSource _writesCompleted = new SingleEventValueTaskSource();

        /// <summary>
        ///     Chunk to be filled from user data.
        /// </summary>
        private StreamChunk _toBeQueuedChunk = new StreamChunk(0, ReadOnlyMemory<byte>.Empty, QuicBufferPool.Rent());

        /// <summary>
        ///     Channel of incoming chunks of memory from the user.
        /// </summary>
        private readonly Channel<StreamChunk> _toSendChannel =
            Channel.CreateUnbounded<StreamChunk>(new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = true
            });

        /// <summary>
        ///     Individual chunks of the stream to be sent.
        /// </summary>
        private readonly List<StreamChunk> _chunks = new List<StreamChunk>();

        /// <summary>
        ///     Number of bytes dequeued from the <see cref="_toSendChannel"/>.
        /// </summary>
        private long _dequedBytes;

        /// <summary>
        ///     Error code if the stream was aborted.
        /// </summary>
        internal long? Error { get; private set; }

        /// <summary>
        ///     If true, the stream was reset by this side.
        /// </summary>
        internal bool ResetByUs { get; private set; }

        public SendStream(long maxData)
        {
            UpdateMaxData(maxData);
        }

        /// <summary>
        ///     Total number of bytes written into this stream.
        /// </summary>
        /// <remarks>
        ///     This property is updated only by the user-code thread.
        /// </remarks>
        internal long WrittenBytes { get; private set; }

        /// <summary>
        ///     Number of bytes present in <see cref="_toSendChannel" />
        /// </summary>
        private long _bytesInChannel;

        /// <summary>
        ///     Total number of bytes allowed to transport in this stream.
        /// </summary>
        internal long MaxData { get; private set; }

        /// <summary>
        ///     Index of the first byte in the stream which was never sent. Used to ensure flow control limits are met.
        /// </summary>
        internal long UnsentOffset { get; private set; }

        /// <summary>
        ///     Synchronization for avoiding overfilling the buffer.
        /// </summary>
        private readonly SemaphoreSlim _bufferLimitSemaphore = new SemaphoreSlim(MaximumHeldChunks - 1);

        /// <summary>
        ///     True if the stream is closed for further writing (no more data can be added).
        /// </summary>
        internal bool SizeKnown { get; private set; }

        /// <summary>
        ///     Returns true if buffer has anything to send, be it data or just a fin bit.
        /// </summary>
        internal bool IsFlushable => HasBytesToSend || SizeKnown && !FinAcked;

        /// <summary>
        ///     Returns true if buffer contains any sendable data below <see cref="MaxData" /> limit.
        /// </summary>
        internal bool HasBytesToSend => _pending.Count > 0 && _pending[0].Start < MaxData ||
                                     _dequedBytes < MaxData && _bytesInChannel > 0;

        /// <summary>
        ///     Requests that the outbound stream be aborted with given error code.
        /// </summary>
        /// <param name="errorCode"></param>
        /// <param name="byUs"></param>
        internal void RequestAbort(long errorCode, bool byUs)
        {
            // TODO-RZ: this function is the only way to set the state from user thread, maybe we can
            // find a way to remove the need for the lock

            if (StreamState >= SendStreamState.DataReceived)
            {
                // either terminal state, or resetting, no action
                return;
            }

            lock (SyncObject)
            {
                if (StreamState >= SendStreamState.DataReceived)
                {
                    // either terminal state, or resetting, no action
                    return;
                }

                ResetByUs = byUs;

                Debug.Assert(Error == null);
                Error = errorCode;
                StreamState = SendStreamState.WantReset;
            }

            _writesCompleted.TryCompleteException(byUs ? new QuicException(QuicError.OperationAborted, null, "Write was aborted.") : new QuicException(QuicError.StreamAborted, errorCode, "Write was aborted."));
            _toSendChannel.Writer.TryComplete();
            if (_toBeQueuedChunk.Buffer != null)
            {
                ReturnBuffer(_toBeQueuedChunk.Buffer);
                _toBeQueuedChunk = default;
            }

            // we need to release once more to make sure writers are not blocked on the semaphore
            _bufferLimitSemaphore.Release();

            // other buffered data will be dropped from socket thread once RESET_STREAM is sent.
        }

        internal void OnResetSent()
        {
            // we are past WantReset, no synchronization needed
            Debug.Assert(StreamState == SendStreamState.WantReset);
            StreamState = SendStreamState.ResetSent;

            // conveniently, also drop all buffered data.
            while (_toSendChannel.Reader.TryRead(out var chunk))
            {
                if (chunk.Buffer != null)
                {
                    ReturnBuffer(chunk.Buffer);
                }
            }
        }

        internal void OnResetAcked()
        {
            // we are past WantReset, no synchronization needed
            Debug.Assert(StreamState == SendStreamState.ResetSent);
            StreamState = SendStreamState.ResetReceived;
        }

        internal void OnResetLost()
        {
            // we are past WantReset, no synchronization needed
            Debug.Assert(StreamState == SendStreamState.ResetSent);
            StreamState = SendStreamState.WantReset;
        }

        /// <summary>
        ///     Queues the not yet full chunk of stream into flush queue, blocking when control flow limit is not
        ///     sufficient.
        /// </summary>
        internal async ValueTask<bool> FlushChunkAsync(CancellationToken cancellationToken = default)
        {
            if (_toBeQueuedChunk.Length == 0)
            {
                // nothing to do
                return false;
            }

            var buffer = await RentBufferAsync(cancellationToken).ConfigureAwait(false);
            var tmp = _toBeQueuedChunk;
            _toBeQueuedChunk = new StreamChunk(WrittenBytes, Memory<byte>.Empty, buffer);

            _toSendChannel.Writer.TryWrite(tmp);
            Interlocked.Add(ref _bytesInChannel, tmp.Length);

            return true;
        }

        /// <summary>
        ///     Queues the not yet full chunk of stream into flush queue, blocking when control flow limit is not
        ///     sufficient.
        /// </summary>
        internal bool FlushChunk()
        {
            if (_toBeQueuedChunk.Length == 0)
            {
                // nothing to do
                return false;
            }

            var buffer = RentBuffer();
            var tmp = _toBeQueuedChunk;
            _toBeQueuedChunk = new StreamChunk(WrittenBytes, Memory<byte>.Empty, buffer);

            _toSendChannel.Writer.TryWrite(tmp);
            Interlocked.Add(ref _bytesInChannel, tmp.Length);

            return true;
        }

        /// <summary>
        ///     Flushes partially full chunk into sending queue, regardless of <see cref="MaxData"/> limit.
        /// </summary>
        internal void ForceFlushPartialChunk()
        {
            if (_toBeQueuedChunk.Length == 0)
                return;

            var tmp = _toBeQueuedChunk;
            var buffer = QuicBufferPool.Rent();
            _toBeQueuedChunk = new StreamChunk(WrittenBytes, Memory<byte>.Empty, buffer);

            _toSendChannel.Writer.TryWrite(tmp);
            Interlocked.Add(ref _bytesInChannel, tmp.Length);
        }

        /// <summary>
        ///     Updates the <see cref="MaxData" /> parameter.
        /// </summary>
        /// <param name="value">Value of the parameter.</param>
        internal void UpdateMaxData(long value)
        {
            MaxData = Math.Max(MaxData, value);
        }

        internal async ValueTask<bool> EnqueueAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Debug.Assert(!SizeKnown);

            bool hasFlushed = false;

            while (buffer.Length > 0)
            {
                int toWrite = Math.Min(_toBeQueuedChunk.Buffer!.Length - _toBeQueuedChunk.Length, buffer.Length);
                buffer.Span.Slice(0, toWrite).CopyTo(_toBeQueuedChunk.Buffer!.AsSpan(_toBeQueuedChunk.Length, toWrite));
                WrittenBytes += toWrite;
                _toBeQueuedChunk = new StreamChunk(_toBeQueuedChunk.StreamOffset,
                    _toBeQueuedChunk.Buffer!.AsMemory(0, _toBeQueuedChunk.Length + toWrite), _toBeQueuedChunk.Buffer);

                if (_toBeQueuedChunk.Length == _toBeQueuedChunk.Buffer!.Length)
                {
                    hasFlushed = await FlushChunkAsync(cancellationToken).ConfigureAwait(false);
                }

                buffer = buffer.Slice(toWrite);
            }

            return hasFlushed;
        }

        /// <summary>
        ///     Copies given memory to the outbound stream to be sent.
        /// </summary>
        /// <param name="data">Data to be sent.</param>
        /// <returns>Whether new chunk was flushed down the internal pipeline.</returns>
        internal bool Enqueue(ReadOnlySpan<byte> data)
        {
            Debug.Assert(!SizeKnown);

            bool hasFlushed = false;

            while (data.Length > 0)
            {
                int toWrite = Math.Min(_toBeQueuedChunk.Buffer!.Length - _toBeQueuedChunk.Length, data.Length);
                data.Slice(0, toWrite).CopyTo(_toBeQueuedChunk.Buffer!.AsSpan(_toBeQueuedChunk.Length, toWrite));
                WrittenBytes += toWrite;
                _toBeQueuedChunk = new StreamChunk(_toBeQueuedChunk.StreamOffset,
                    _toBeQueuedChunk.Buffer!.AsMemory(0, _toBeQueuedChunk.Length + toWrite), _toBeQueuedChunk.Buffer);

                if (_toBeQueuedChunk.Length == _toBeQueuedChunk.Buffer!.Length)
                {
                    hasFlushed = FlushChunk();
                }

                data = data.Slice(toWrite);
            }

            return hasFlushed;
        }

        private void DrainIncomingChunks()
        {
            var reader = _toSendChannel.Reader;

            while (reader.TryRead(out var chunk))
            {
                Debug.Assert(_dequedBytes == chunk.StreamOffset);
                Debug.Assert(chunk.Length > 0);

                _pending.Add(chunk.StreamOffset, chunk.StreamOffset + chunk.Length - 1);
                _chunks.Add(chunk);
                _dequedBytes += chunk.Length;
                Interlocked.Add(ref _bytesInChannel, -chunk.Length);
            }
        }

        /// <summary>
        ///     Returns length of the next contiguous range of data that can be sent in the next STREAM frame,
        ///     respecting the <see cref="MaxData" /> parameter.
        /// </summary>
        /// <returns></returns>
        internal (long offset, long count) GetNextSendableRange()
        {
            DrainIncomingChunks();
            if (_pending.Count == 0) return (WrittenBytes, 0);

            long sendableLength = MaxData - _pending[0].Start;
            long count = Math.Min(sendableLength, _pending[0].Length);
            return (_pending[0].Start, count);
        }

        /// <summary>
        ///     Reads data from the stream into provided span.
        /// </summary>
        /// <param name="destination">Destination memory for the data.</param>
        internal void CheckOut(Span<byte> destination)
        {
            if (!destination.IsEmpty)
            {
                if (StreamState == SendStreamState.Ready)
                {
                    lock (SyncObject)
                    {
                        if (StreamState == SendStreamState.Ready)
                        {
                            StreamState = SendStreamState.Send;
                        }
                    }
                }

                DrainIncomingChunks();
                Debug.Assert(destination.Length <= GetNextSendableRange().count);

                long start = _pending.GetMin();
                long end = start + destination.Length - 1;

                _pending.Remove(start, end);
                _inFlight.Add(start, end);

                // skip chunks which are not interesting to us.
                int chunkIndex = 0;
                while (_chunks[chunkIndex].StreamOffset + _chunks[chunkIndex].Length < start)
                {
                    chunkIndex++;
                }

                int copied = 0;
                while (copied < destination.Length)
                {
                    var chunk = _chunks[chunkIndex];
                    int inChunkStart = (int)(start - chunk.StreamOffset) + copied;
                    int inChunkCount = Math.Min(chunk.Length - inChunkStart, destination.Length - copied);
                    chunk.Memory.Span.Slice(inChunkStart, inChunkCount).CopyTo(destination.Slice(copied));

                    copied += inChunkCount;
                    chunkIndex++;
                }

                UnsentOffset = Math.Max(UnsentOffset, end + 1);
            }

            if (SizeKnown && StreamState == SendStreamState.Send && UnsentOffset == WrittenBytes)
            {
                lock (SyncObject)
                {
                    if (StreamState == SendStreamState.Send)
                    {
                        StreamState = SendStreamState.DataSent;
                    }
                }
            }
        }

        /// <summary>
        ///     Marks the stream as finished, no more data can be added to the stream.
        /// </summary>
        internal void MarkEndOfData()
        {
            SizeKnown = true;
        }

        /// <summary>
        ///     Called to inform the buffer that transmission of given range was not successful.
        /// </summary>
        /// <param name="offset">Start of the range.</param>
        /// <param name="count">Number of bytes lost.</param>
        internal void OnLost(long offset, long count)
        {
            long end = offset + count - 1;

            Debug.Assert(_inFlight.Includes(offset, end));
            Debug.Assert(!_pending.Includes(offset, end));

            _inFlight.Remove(offset, end);
            _pending.Add(offset, end);
        }

        /// <summary>
        ///     Called to inform the buffer that transmission of given range was successful.
        /// </summary>
        /// <param name="offset">Start of the range.</param>
        /// <param name="count">Number of bytes acked.</param>
        /// <param name="fin">Whether the sent frame contained the FIN bit.</param>
        internal void OnAck(long offset, long count, bool fin = false)
        {
            if (fin)
            {
                Debug.Assert(offset + count == WrittenBytes);
                FinAcked = true;

            }

            if (count > 0)
            {
                long end = offset + count - 1;

                Debug.Assert(_inFlight.Includes(offset, end));

                _inFlight.Remove(offset, end);
                _acked.Add(offset, end);

                if (_acked[0].Start != 0)
                {
                    // do not discard data yet, as the very first data to be discared were not acked
                    return;
                }

                // release unneeded data
                long processed = _acked[0].End + 1;

                int toRemove = 0;
                for (; toRemove < _chunks.Count; toRemove++)
                {
                    var chunk = _chunks[toRemove];
                    if (chunk.StreamOffset + chunk.Length > processed)
                    {
                        // this chunk contains unsent data, stop there
                        break;
                    }

                    if (chunk.Buffer != null)
                    {
                        ReturnBuffer(chunk.Buffer);
                    }
                }

                _chunks.RemoveRange(0, toRemove);
            }

            if (FinAcked && _acked.Count > 0 && _acked[0].Length == WrittenBytes && StreamState == SendStreamState.DataSent)
            {
                lock (SyncObject)
                {
                    if (StreamState == SendStreamState.DataSent)
                    {
                        StreamState = SendStreamState.DataReceived;
                        _writesCompleted.TryComplete();
                    }
                }
            }
        }

        private byte[] RentBuffer()
        {
            _bufferLimitSemaphore.Wait();
            // throwing here is a bit ugly, but there is no way of interrupting synchronous wait on semaphore,
            // the semaphore is released when stream is aborted to make the caller writer throw
            ThrowIfAborted();
            return QuicBufferPool.Rent();
        }

        internal async ValueTask WaitForWriteCompletion(CancellationToken cancellationToken)
        {
            using CancellationTokenRegistration registration = cancellationToken.UnsafeRegister(static (s, token) =>
            {
                ((SendStream?)s)!._writesCompleted.TryCompleteException(new OperationCanceledException("Wait was canceled", token));
            }, this);

            await _writesCompleted.GetTask().ConfigureAwait(false);
        }

        private async ValueTask<byte[]> RentBufferAsync(CancellationToken cancellationToken)
        {
            await _bufferLimitSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            // throwing here is a bit ugly, but saves us from registering cancellation on the semaphore
            // the semaphore is released when stream is aborted to make the caller writer throw
            ThrowIfAborted();
            return QuicBufferPool.Rent();
        }

        private void ReturnBuffer(byte[] buffer)
        {
            QuicBufferPool.Return(buffer);
            _bufferLimitSemaphore.Release();
        }

        internal void ThrowIfAborted()
        {
            if (Error != null)
            {
                if (ResetByUs)
                {
                    throw new QuicException(QuicError.OperationAborted, null, "Operation aborted.");
                }
                else
                {
                    throw new QuicException(QuicError.StreamAborted, Error.Value, "Stream aborted");
                }
            }
        }

#pragma warning disable CA1822, IDE0060 // mark as static, remove unused parameter
        public void OnFatalException(Exception exception)
#pragma warning restore CA1822, IDE0060 // mark as static
        {
            // TODO-RZ: handle callers blocking on other async tasks
            _writesCompleted.TryCompleteException(exception);
        }
    }
}