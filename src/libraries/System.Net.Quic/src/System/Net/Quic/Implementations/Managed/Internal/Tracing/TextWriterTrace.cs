﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Net.Quic.Implementations.Managed.Internal.Frames;
using System.Net.Quic.Implementations.Managed.Internal.Recovery;
using System.Text;

namespace System.Net.Quic.Implementations.Managed.Internal.Tracing
{
    internal sealed class TextWriterTrace : IQuicTrace
    {
        private readonly TextWriter _output;
        private readonly bool _isServer;
        private readonly StringBuilder _lineBuilder = new StringBuilder();
        private readonly StringBuilder _packetContentBuilder = new StringBuilder();
        private bool _isSending;

        public TextWriterTrace(TextWriter output, bool isServer)
        {
            _output = output;
            _isServer = isServer;
        }

        private void InitLine()
        {
            _lineBuilder.Append('[');
            _lineBuilder.Append(DateTime.Now.ToString("O"));
            _lineBuilder.Append("] ");
            _lineBuilder.Append(_isServer ? "Server: " : "Client: ");
        }

        private StringBuilder GetPacketContentBuilder()
        {
            return _isSending ? _packetContentBuilder : _lineBuilder;
        }

        private void LogFrame(string message)
        {
            var sb = GetPacketContentBuilder();
            sb.Append(message);
            sb.Append(' ');
        }

        private void Log(string message)
        {
            InitLine();
            _lineBuilder.Append(message);
            FlushLine();
        }

        private void Flush(StringBuilder builder, bool newline)
        {
            lock (_output)
            {
                foreach (ReadOnlyMemory<char> chunk in builder.GetChunks())
                {
                    _output.Write(chunk.Span);
                }

                if (newline)
                {
                    _output.WriteLine();
                }
            }

            builder.Clear();
        }

        private void FlushLine(bool newline = true)
        {
            Flush(_lineBuilder, newline);
        }

        public void OnTransportParametersSet(TransportParameters parameters)
        {
        }

        public void OnKeyUpdated(ReadOnlySpan<byte> secret, EncryptionLevel level, bool isServer,
            KeyUpdateTrigger trigger, int? generation)
        {
        }

        public void OnDatagramReceived(int length)
        {
            InitLine();
            _lineBuilder.Append($"Received datagram: {length} B: ");
        }

        public void OnDatagramSent(int length)
        {
        }

        public void OnDatagramDropped(int length)
        {
            Log($"Datagram dropped ({length} B)");
        }

        public void OnStreamStateUpdated(int length)
        {
        }

        public void OnPacketReceiveStart(ReadOnlySpan<byte> scid, ReadOnlySpan<byte> dcid, PacketType packetType,
            long packetNumber,
            long payloadLength, long packetSize)
        {
            _lineBuilder.Append($"{packetType}[{packetNumber}]: ");
        }

        public void OnPacketReceiveEnd()
        {
            FlushLine();
        }

        public void OnPacketSendStart()
        {
            InitLine();
            _isSending = true;
        }

        public void OnPacketSendEnd(ReadOnlySpan<byte> scid, ReadOnlySpan<byte> dcid, PacketType packetType,
            long packetNumber, long payloadLength,
            long packetSize)
        {
            _lineBuilder.Append($"Sent {packetType}[{packetNumber}]: ");
            FlushLine(false);
            Flush(_packetContentBuilder, true);

            _isSending = false;
        }

        public void OnPacketDropped(PacketType? type, int packetSize)
        {
            Log($"Packet dropped ({type}, {packetSize} B)");
        }

        public void OnPaddingFrame(int length)
        {
            LogFrame($"Padding[{length}]");
        }

        public void OnPingFrame()
        {
            LogFrame("Ping");
        }

        public void OnAckFrame(in AckFrame frame, long ackDelayMicroseconds)
        {
            var sb = GetPacketContentBuilder();
            Span<RangeSet.Range> ranges = stackalloc RangeSet.Range[(int)frame.AckRangeCount + 1];
            sb.Append("Ack[");
            if (frame.TryDecodeAckRanges(ranges))
            {
                for (int i = 0; i < ranges.Length; i++)
                {
                    if (i > 0)
                    {
                        sb.Append(',');
                    }

                    sb.Append(ranges[i].Start);
                    if (ranges[i].Length > 1)
                    {
                        sb.Append('-');
                        sb.Append(ranges[i].End);
                    }
                }
            }
            sb.Append("] ");
        }

        public void OnResetStreamFrame(in ResetStreamFrame frame)
        {
            LogFrame($"ResetStream[{frame.StreamId}, {frame.ApplicationErrorCode}, {frame.FinalSize}]");
        }

        public void OnStopSendingFrame(in StopSendingFrame frame)
        {
            LogFrame($"StopSending[{frame.StreamId}, {frame.ApplicationErrorCode}]");
        }

        public void OnCryptoFrame(in CryptoFrame frame)
        {
            LogFrame($"Crypto[{frame.Offset}, {frame.CryptoData.Length}]");
        }

        public void OnNewTokenFrame(in NewTokenFrame frame)
        {
        }

        public void OnStreamFrame(in StreamFrame frame)
        {
            LogFrame($"Stream[{frame.StreamId}, {frame.Offset}, {frame.StreamData.Length}{(frame.Fin ? ", FIN" : "")}]");
        }

        public void OnMaxDataFrame(in MaxDataFrame frame)
        {
            LogFrame($"MaxData[{frame.MaximumData}]");
        }

        public void OnMaxStreamDataFrame(in MaxStreamDataFrame frame)
        {
            LogFrame($"MaxStreamData[{frame.StreamId}, {frame.MaximumStreamData}]");
        }

        public void OnMaxStreamsFrame(in MaxStreamsFrame frame)
        {
            LogFrame($"MaxStreams[{(frame.Bidirectional ? "Bi" : "Uni")}, {frame.MaximumStreams}]");
        }

        public void OnDataBlockedFrame(in DataBlockedFrame frame)
        {
            LogFrame($"DataBlocked[{frame.DataLimit}]");
        }

        public void OnStreamDataBlockedFrame(in StreamDataBlockedFrame frame)
        {
            LogFrame($"StreamDataBlocked[{frame.StreamId}, {frame.StreamDataLimit}]");
        }

        public void OnStreamsBlockedFrame(in StreamsBlockedFrame frame)
        {
            LogFrame($"StreamsBlocked[{(frame.Bidirectional ? "Bi" : "Uni")}, {frame.StreamLimit}]");
        }

        public void OnNewConnectionIdFrame(in NewConnectionIdFrame frame)
        {
        }

        public void OnRetireConnectionIdFrame(in RetireConnectionIdFrame frame)
        {
        }

        public void OnPathChallengeFrame(in PathChallengeFrame frame)
        {
        }

        public void OnConnectionCloseFrame(in ConnectionCloseFrame frame)
        {
            LogFrame($"ConnectionClose[{(frame.IsQuicError ? "QUIC" : "App")}, {frame.ErrorCode}]");
        }

        public void OnHandshakeDoneFrame()
        {
            LogFrame("HandshakeDone");
        }

        public void OnUnknownFrame(long frameType, int length)
        {
        }

        public void OnPacketLost(PacketType packetType, long packetNumber, PacketLossTrigger trigger)
        {
            Log($"Packet lost: {packetType}[{packetNumber}] ({trigger})");
        }

        public void OnRecoveryMetricsUpdated(RecoveryController recovery)
        {
        }

        public void OnCongestionStateUpdated(CongestionState state)
        {
        }

        public void OnLossTimerUpdated()
        {
        }

        public void OnRecoveryParametersSet(RecoveryController recovery)
        {
        }

        public void Dispose()
        {
        }
    }
}