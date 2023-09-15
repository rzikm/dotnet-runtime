// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Streams;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Quic.Implementations.Managed
{
    public sealed class ManagedQuicStream : QuicStream
    {
        /// <summary>
        ///     Node to the linked list of all flushable streams. Should be accessed only by the <see cref="StreamCollection"/> class.
        /// </summary>
        internal readonly LinkedListNode<ManagedQuicStream> _flushableListNode;

        /// <summary>
        ///     Node to the linked list of all streams needing some kind of update other than sending data. This
        ///     includes Flow Control limits update and aborts.
        /// </summary>
        internal readonly LinkedListNode<ManagedQuicStream> _updateQueueListNode;

        /// <summary>
        ///     Value task source for signalling that <see cref="ShutdownCompleted"/> has finished.
        /// </summary>
        private readonly SingleEventValueTaskSource _shutdownCompleted = new SingleEventValueTaskSource();

        /// <summary>
        ///     Value task source for signalling that this stream was successfully started (is within peer's limits);
        /// </summary>
        private readonly SingleEventValueTaskSource _started = new SingleEventValueTaskSource();

        /// <summary>
        ///     True if this instance has been disposed.
        /// </summary>
        private bool _disposed;

        /// <summary>
        ///     Connection to which this stream belongs;
        /// </summary>
        private readonly ManagedQuicConnection _connection;

        /// <summary>
        ///     If the stream can receive data, contains the receiving part of the stream. Otherwise null.
        /// </summary>
        internal ReceiveStream? ReceiveStream { get; }

        /// <summary>
        ///     If the stream can send data, contains the sending part of the stream. Otherwise null.
        /// </summary>
        internal SendStream? SendStream { get; }

        internal ManagedQuicStream(long streamId, ReceiveStream? receiveStream, SendStream? sendStream, ManagedQuicConnection connection)
            : base(true)
        {
            // trivial check whether buffer nullable combination makes sense with respect to streamId
            Debug.Assert(receiveStream != null || sendStream != null);
            Debug.Assert(StreamHelpers.IsBidirectional(streamId) == (receiveStream != null && sendStream != null));

            Id = streamId;
            ReceiveStream = receiveStream;
            SendStream = sendStream;
            _connection = connection;

            _flushableListNode = new LinkedListNode<ManagedQuicStream>(this);
            _updateQueueListNode = new LinkedListNode<ManagedQuicStream>(this);
        }

        #region Public API
        public override bool CanRead => ReceiveStream != null;
        public override bool CanWrite => SendStream != null;
        public override bool CanSeek => false;
        public override bool CanTimeout => false;

        public override long Id { get; }

        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override Task ReadsClosed => throw new NotImplementedException();
        public override int ReadTimeout { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override Task WritesClosed => throw new NotImplementedException();
        public override int WriteTimeout { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Abort(QuicAbortDirection abortDirection, long errorCode)
        {
            ThrowIfDisposed();

            if ((abortDirection & QuicAbortDirection.Read) != 0)
            {
                AbortRead(errorCode);
            }

            if ((abortDirection & QuicAbortDirection.Write) != 0)
            {
                AbortWrite(errorCode);
            }
        }

        public override void CompleteWrites()
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();

            if (CanWrite)
            {
                SendStream!.MarkEndOfData();
                SendStream!.FlushChunk();
                _connection.OnStreamDataWritten(this);
            }
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            ValidateBufferArguments(buffer, offset, count);
            return Read(buffer.AsSpan(offset, count));
        }

        public override int Read(Span<byte> buffer)
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();
            ThrowIfNotReadable();

            int result = ReceiveStream!.Deliver(buffer);
            if (result > 0)
            {
                _connection.OnStreamDataRead(this, result);
            }

            return result;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();
            ThrowIfNotReadable();

            int result = await ReceiveStream!.DeliverAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (result > 0)
            {
                _connection.OnStreamDataRead(this, result);
            }

            return result;
        }

        internal void AbortRead(long errorCode)
        {
            ThrowIfDisposed();
            ThrowIfNotReadable();

            if (ReceiveStream!.Error != null) return;

            ReceiveStream.RequestAbort(errorCode);
            _connection.OnStreamStateUpdated(this);
        }

        internal void AbortWrite(long errorCode)
        {
            ThrowIfDisposed();
            ThrowIfNotWritable();

            if (SendStream!.Error != null) return;

            SendStream.RequestAbort(errorCode, true);
            _connection.OnStreamStateUpdated(this);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            ValidateBufferArguments(buffer, offset, count);
            Write(buffer.AsSpan(offset, count));
        }

        public override void Write(ReadOnlySpan<byte> buffer) => Write(buffer, false);

        public void Write(ReadOnlySpan<byte> buffer, bool completeWrites)
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();
            ThrowIfNotWritable();
            SendStream!.Enqueue(buffer);

            if (completeWrites)
            {
                SendStream.MarkEndOfData();
                SendStream.FlushChunk();
            }

            if (SendStream.WrittenBytes - buffer.Length < SendStream.MaxData)
            {
                _connection.OnStreamDataWritten(this);
            }
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return WriteAsync(buffer, false, cancellationToken);
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, bool completeWrites, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();
            ThrowIfNotWritable();

            // TODO-RZ: optimize away some of the copying
            await WriteAsyncInternal(buffer, completeWrites, cancellationToken).ConfigureAwait(false);
            await FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask WriteAsync(ReadOnlySequence<byte> buffers, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();
            ThrowIfNotWritable();

            foreach (ReadOnlyMemory<byte> buffer in buffers)
            {
                await WriteAsyncInternal(buffer, false, cancellationToken).ConfigureAwait(false);
            }

            await FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask WriteAsync(ReadOnlySequence<byte> buffers, bool endStream, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();
            ThrowIfNotWritable();

            foreach (ReadOnlyMemory<byte> buffer in buffers)
            {
                await WriteAsyncInternal(buffer, endStream, cancellationToken).ConfigureAwait(false);
            }

            await FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        public ValueTask WriteAsync(ReadOnlyMemory<ReadOnlyMemory<byte>> buffers, CancellationToken cancellationToken = default)
        {
            return WriteAsync(buffers, false, cancellationToken);
        }

        public async ValueTask WriteAsync(ReadOnlyMemory<ReadOnlyMemory<byte>> buffers, bool endStream, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();
            ThrowIfNotWritable();

            for (int i = 0; i < buffers.Span.Length; i++)
            {
                await WriteAsyncInternal(buffers.Span[i], endStream && i == buffers.Length - 1, cancellationToken).ConfigureAwait(false);
            }

            await FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask ShutdownCompleted(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();

            SendStream!.MarkEndOfData();
            await SendStream!.FlushChunkAsync(cancellationToken).ConfigureAwait(false);
            _connection.OnStreamDataWritten(this);

            using CancellationTokenRegistration registration = cancellationToken.UnsafeRegister(static (s, token) =>
            {
                ((ManagedQuicStream?)s)!._shutdownCompleted.TryCompleteException(
                    new OperationCanceledException("Shutdown was cancelled", token));
            }, this);

            await _shutdownCompleted.GetTask().ConfigureAwait(false);
        }

        internal ValueTask WaitForWriteCompletionAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();
            ThrowIfNotWritable();

            return SendStream!.WaitForWriteCompletion(cancellationToken);
        }

        internal async ValueTask WaitForStartAsync(CancellationToken cancellationToken)
        {
            using CancellationTokenRegistration registration = cancellationToken.UnsafeRegister(static (s, token) =>
            {
                ((ManagedQuicStream?)s)!._started.TryCompleteException(new OperationCanceledException("Start was canceled", token));
            }, this);

            await _started.GetTask().ConfigureAwait(false);
        }

        public override void Flush()
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();
            ThrowIfNotWritable();

            SendStream!.FlushChunk();
            _connection.OnStreamDataWritten(this);
        }

        public override async Task FlushAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            ThrowIfConnectionError();
            ThrowIfNotWritable();

            await SendStream!.FlushChunkAsync(cancellationToken).ConfigureAwait(false);
            _connection.OnStreamDataWritten(this);
        }

        protected override void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
            {
                return;
            }

            if (CanWrite)
            {
                SendStream!.MarkEndOfData();
                SendStream!.FlushChunk();
                _connection.OnStreamDataWritten(this);
            }

            if (CanRead)
            {
                // TODO-RZ: should we use this error code?
                ReceiveStream!.RequestAbort(0);
                _connection.OnStreamStateUpdated(this);
            }

            _disposed = true;
        }

        public override async ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (CanWrite)
            {
                SendStream!.MarkEndOfData();
                await SendStream!.FlushChunkAsync().ConfigureAwait(false);
                _connection.OnStreamDataWritten(this);
            }

            if (CanRead)
            {
                // TODO-RZ: should we use this error code?
                ReceiveStream!.RequestAbort(0);
                _connection.OnStreamStateUpdated(this);
            }
        }

        #endregion

        private async ValueTask WriteAsyncInternal(ReadOnlyMemory<byte> buffer, bool completeWrites, CancellationToken cancellationToken)
        {
            await SendStream!.EnqueueAsync(buffer, cancellationToken).ConfigureAwait(false);

            if (completeWrites)
            {
                SendStream.MarkEndOfData();
                await SendStream.FlushChunkAsync(cancellationToken).ConfigureAwait(false);
            }

            if (SendStream.WrittenBytes - buffer.Length < SendStream.MaxData)
            {
                _connection.OnStreamDataWritten(this);
            }
        }

        internal void NotifyShutdownWriteCompleted()
        {
            _shutdownCompleted.TryComplete();
        }

        internal void NotifyStarted()
        {
            _started.TryComplete();
        }

        internal void OnFatalException(Exception exception)
        {
            ReceiveStream?.OnFatalException(exception);
            SendStream?.OnFatalException(exception);
        }

        internal void OnConnectionClosed(Exception exception)
        {
            // closing connection (CONNECTION_CLOSE frame) causes all streams to become closed
            NotifyShutdownWriteCompleted();

            _started.TryCompleteException(exception);
            OnFatalException(exception);
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(_disposed, typeof(ManagedQuicStream));
        }

        private void ThrowIfNotWritable()
        {
            if (!CanWrite)
            {
                throw new InvalidOperationException("Writing is not allowed on this stream.");
            }

            // SendStream not null is implied by CanWrite
            SendStream!.ThrowIfAborted();
        }

        private void ThrowIfNotReadable()
        {
            if (!CanRead)
            {
                throw new InvalidOperationException("Reading is not allowed on this stream.");
            }

            // ReceiveStream not null is implied by CanRead
            if (ReceiveStream!.Error != null)
            {
                throw new QuicException(QuicError.StreamAborted, ReceiveStream.Error.Value, "Reading was aborted on the stream");
            }
        }

        private void ThrowIfConnectionError()
        {
            _connection.ThrowIfError();
        }
    }
}
