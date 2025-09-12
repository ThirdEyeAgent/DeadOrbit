using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DeadOrbitCapture.Services
{
    // Minimal DNS server that answers A-records for target domains with the local IPv4.
    // Logs every query regardless of domain.
    public class DnsServer
    {
        private readonly Action<string> _logger;
        private UdpClient? _udp;
        private readonly IPEndPoint _listenEndPoint = new IPEndPoint(IPAddress.Any, 53);
        private IPAddress _advertisedIp = IPAddress.Loopback;

        // Expanded target domains — wildcard match for any subdomain
        private readonly string[] _targets =
        {
            "destinygame.com",
            "bungie.net",
            "deadorbit.net",
            "gravityshavings.net",
            "demonware.net"
        };

        public DnsServer(Action<string> logger)
        {
            _logger = logger;
        }

        public IPAddress GetAdvertisedIPv4() => _advertisedIp;

        public void Start()
        {
            Stop();
            _advertisedIp = NetworkUtil.GetLocalIPv4();
            _logger($"[DNS] Advertising IP: {_advertisedIp}");

            try
            {
                _udp = new UdpClient(_listenEndPoint);
            }
            catch (SocketException ex)
            {
                _logger($"[DNS][ERROR] Failed to bind UDP/53: {ex.Message}. Run as Administrator and ensure no other DNS service is running.");
                return;
            }

            BeginReceive();
        }

        public void Stop()
        {
            try { _udp?.Close(); } catch { }
            _udp = null;
        }

        private void BeginReceive()
        {
            if (_udp == null) return;
            try { _udp.BeginReceive(OnReceive, null); } catch { }
        }

        private void OnReceive(IAsyncResult ar)
        {
            if (_udp == null) return;
            IPEndPoint remote = new IPEndPoint(IPAddress.Any, 0);
            byte[] req = Array.Empty<byte>();

            try { req = _udp.EndReceive(ar, ref remote); } catch { }
            finally { try { _udp?.BeginReceive(OnReceive, null); } catch { } }

            if (req.Length < 12) return;

            ushort id = (ushort)(req[0] << 8 | req[1]);
            ushort qdCount = (ushort)(req[4] << 8 | req[5]);
            if (qdCount == 0) return;

            int offset = 12;
            string qname = ReadQName(req, ref offset);
            if (offset + 4 > req.Length) return;
            ushort qtype = (ushort)(req[offset] << 8 | req[offset + 1]); offset += 2;
            ushort qclass = (ushort)(req[offset] << 8 | req[offset + 1]); offset += 2;

            bool isA = qtype == 1 && qclass == 1;
            bool target = MatchesTarget(qname);

            _logger($"[DNS] Query from {remote}: {qname} (type {qtype})");

            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            // Header
            bw.Write((byte)(id >> 8));
            bw.Write((byte)(id & 0xFF));
            byte rd = (byte)(req[2] & 0x01);
            bw.Write((byte)(0x80 | 0x40 | rd)); // QR=1, AA=1
            bw.Write((byte)0x80);               // RA=1
            bw.Write((byte)(qdCount >> 8));
            bw.Write((byte)(qdCount & 0xFF));
            ushort an = (ushort)(isA && target ? 1 : 0);
            bw.Write((byte)(an >> 8));
            bw.Write((byte)(an & 0xFF));
            bw.Write((byte)0x00); bw.Write((byte)0x00); // NSCOUNT
            bw.Write((byte)0x00); bw.Write((byte)0x00); // ARCOUNT

            // Question
            bw.Write(req, 12, offset - 12);

            if (an == 1)
            {
                bw.Write((byte)0xC0); bw.Write((byte)0x0C);
                bw.Write((byte)0x00); bw.Write((byte)0x01); // TYPE=A
                bw.Write((byte)0x00); bw.Write((byte)0x01); // CLASS=IN
                bw.Write((byte)0x00); bw.Write((byte)0x00); bw.Write((byte)0x00); bw.Write((byte)0x1E); // TTL=30
                bw.Write((byte)0x00); bw.Write((byte)0x04); // RDLENGTH
                var bytes = _advertisedIp.GetAddressBytes();
                if (bytes.Length != 4) bytes = new byte[] { 127, 0, 0, 1 };
                bw.Write(bytes);
                _logger($"[DNS] Answered {qname} -> {_advertisedIp}");
            }
            else
            {
                _logger($"[DNS] No answer for {qname}");
            }

            try
            {
                var resp = ms.ToArray();
                _udp?.Send(resp, resp.Length, remote);
            }
            catch (Exception ex)
            {
                _logger($"[DNS][ERROR] Send failed: {ex.Message}");
            }
        }

        private static string ReadQName(byte[] packet, ref int offset)
        {
            var sb = new StringBuilder();
            while (offset < packet.Length)
            {
                byte len = packet[offset++];
                if (len == 0) break;
                if (offset + len > packet.Length) break;
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(packet, offset, len));
                offset += len;
            }
            return sb.ToString().ToLowerInvariant();
        }

        private bool MatchesTarget(string qname)
        {
            foreach (var t in _targets)
            {
                if (qname == t) return true;
                if (qname.EndsWith("." + t)) return true;
            }
            return false;
        }
    }
}
