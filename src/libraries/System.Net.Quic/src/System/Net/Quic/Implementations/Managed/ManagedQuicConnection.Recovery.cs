// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Net.Quic.Implementations.Managed.Internal;
using System.Net.Quic.Implementations.Managed.Internal.Streams;

namespace System.Net.Quic.Implementations.Managed
{
    public partial class ManagedQuicConnection
    {
        /// <summary>
        ///     Marks the connection data sent in the packet as acknowledged.
        /// </summary>
        /// <param name="packet">The acked packet.</param>
        /// <param name="pnSpace">Packet number space in which the packet was sent.</param>
        private void OnPacketAcked(SentPacket packet, PacketNumberSpace pnSpace)
        {
            foreach (var data in packet.StreamFrames)
            {
                if (data.IsCryptoStream)
                {
                    pnSpace.CryptoSendStream.OnAck(data.Offset, data.Count);
                }
                else
                {
                    // empty frames are sent only to send the FIN bit
                    Debug.Assert(data.Count > 0 || data.Fin);

                    var stream = GetStream(data.StreamId);
                    if (stream == null) continue;

                    var buffer = stream.SendStream!;

                    buffer.OnAck(data.Offset, data.Count, data.Fin);

                    if (buffer.StreamState == SendStreamState.DataReceived)
                    {
                        if (stream.ReceiveStream?.CanReleaseFlowControl ?? true)
                        {
                            ReleaseStream(stream);
                        }

                        stream.NotifyShutdownWriteCompleted();
                    }
                }
            }

            foreach (var frame in packet.MaxStreamDataFrames)
            {
                var stream = GetStream(frame.StreamId);
                if (stream == null) continue;

                Debug.Assert(stream.ReceiveStream != null);
                stream.ReceiveStream.UpdateRemoteMaxData(frame.MaximumStreamData);
            }

            foreach (long streamId in packet.StreamsReset)
            {
                var stream = GetStream(streamId);
                if (stream == null) continue;

                stream.SendStream!.OnResetAcked();
                if (stream.SendStream!.CanReleaseFlowControl && (stream.ReceiveStream?.CanReleaseFlowControl ?? true))
                {
                    ReleaseStream(stream);
                }
            }

            if (packet.MaxDataFrame != null)
            {
                MaxDataFrameSent = false;
                _receiveLimitsAtPeer.UpdateMaxData(packet.MaxDataFrame.Value.MaximumData);
            }

            if (packet.MaxStreamsUni != null)
            {
                _receiveLimitsAtPeer.UpdateMaxStreamsUni(packet.MaxStreamsUni!.Value);
            }

            if (packet.MaxStreamsBidi != null)
            {
                _receiveLimitsAtPeer.UpdateMaxStreamsBidi(packet.MaxStreamsBidi!.Value);
            }

            if (packet.HandshakeDoneSent)
            {
                // the handshake completion has been confirmed
                _handshakeDoneReceived = true;
            }

            // Since we know the acks arrived, we don't want to send acks sent by this packet anymore.
            pnSpace.UnackedPacketNumbers.Remove(packet.AckedRanges);
        }

        /// <summary>
        ///     Marks all connection data sent in the packet as lost, so they are retransmitted later if necessary.
        /// </summary>
        /// <param name="packet">The lost packet.</param>
        /// <param name="pnSpace">The packet number space in which the packet was sent.</param>
        private void OnPacketLost(SentPacket packet, PacketNumberSpace pnSpace)
        {
            // if we lost acks, make sure we send them again.
            // if the timestamps do not match, then we already sent the same ack ranges in some other packet
            if (packet.AckedRanges.Count > 0 && pnSpace.LastAckSentTimestamp == packet.TimeSent)
            {
                pnSpace.AckElicited = true;
            }

            foreach (var data in packet.StreamFrames)
            {
                if (data.IsCryptoStream)
                {
                    pnSpace.CryptoSendStream.OnLost(data.Offset, data.Count);
                }
                else
                {
                    var stream = GetStream(data.StreamId);
                    if (stream == null) continue;

                    // empty stream frames are only sent to send the Fin bit
                    Debug.Assert(data.Count > 0 || data.Fin);
                    if (data.Count > 0)
                    {
                        stream.SendStream!.OnLost(data.Offset, data.Count);
                    }

                    _streams.MarkFlushable(stream);
                }
            }

            foreach (var frame in packet.MaxStreamDataFrames)
            {
                var stream = GetStream(frame.StreamId);
                if (stream == null) continue;

                if (frame.MaximumStreamData > stream.ReceiveStream!.RemoteMaxData)
                {
                    _streams.MarkForUpdate(stream);
                }
            }

            foreach (long streamId in packet.StreamsReset)
            {
                var stream = GetStream(streamId);
                if (stream == null) continue;

                stream.SendStream!.OnResetLost();
                _streams.MarkForUpdate(stream);
            }

            foreach (long streamId in packet.StreamsStopped)
            {
                var stream = GetStream(streamId);
                if (stream == null) continue;

                stream.ReceiveStream!.OnStopSendingLost();
                _streams.MarkForUpdate(stream);
            }

            if (packet.MaxDataFrame != null)
            {
                MaxDataFrameSent = false;
            }

            // if we lost packet with highest value, bump the value down to trigger sending the frame again
            if (packet.MaxStreamsUni != null && packet.MaxStreamsUni == MaxStreamsUniFrameSent)
            {
                MaxStreamsUniFrameSent--;
            }
            if (packet.MaxStreamsBidi != null && packet.MaxStreamsBidi == MaxStreamsBidiFrameSent)
            {
                MaxStreamsBidiFrameSent--;
            }
        }
    }
}