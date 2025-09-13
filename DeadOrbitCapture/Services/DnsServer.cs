// File: Services/DnsServer.cs

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DeadOrbitCapture.Services
{
    public class DnsServer
    {
        private readonly Action<string> _logger;
        private UdpClient? _udp;
        private readonly IPEndPoint _listenEP = new(IPAddress.Any, 53);
        private IPAddress _advertisedIp = IPAddress.Loopback;

        // We spoof ALL these domains to our local proxy
        private readonly string[] _targets =
        {
            "destinygame.com",
            "bungie.net",
            "demonware.net",
            "deadorbit.net",
            "gravityshavings.net"
        };

        public DnsServer(Action<string> logger) => _logger = logger;

        public IPAddress GetAdvertisedIPv4() => _advertisedIp;

        public void Start()
        {
            Stop();
            _advertisedIp = NetworkUtil.GetLocalIPv4();
            _logger($"[DNS] Advertising IP: {_advertisedIp}");

            try
            {
                _udp = new UdpClient(_listenEP);
                _udp.BeginReceive(OnReceive, null);
            }
            catch (Exception ex)
            {
                _logger($"[DNS][ERROR] Failed to bind UDP/53: {ex.Message}");
            }
        }

        public void Stop()
        {
            try { _udp?.Close(); } catch { }
            _udp = null;
        }

        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                if (_udp == null) return;

                var remote = new IPEndPoint(IPAddress.Any, 0);
                byte[] req = _udp.EndReceive(ar, ref remote);

                // Re-arm immediately so we never miss packets
                _udp.BeginReceive(OnReceive, null);

                if (req.Length < 12) return;
                HandleRequest(req, remote);
            }
            catch (Exception ex)
            {
                _logger($"[DNS][ERROR] Receive failed: {ex.Message}");
                try { _udp?.BeginReceive(OnReceive, null); } catch { }
            }
        }

        private void HandleRequest(byte[] req, IPEndPoint remote)
        {
            try
            {
                // Parse header
                ushort id      = (ushort)((req[0] << 8) | req[1]);
                ushort qdCount = (ushort)((req[4] << 8) | req[5]);
                if (qdCount == 0) return;

                // Read question name
                int offset = 12;
                string name = ReadQName(req, ref offset);
                if (offset + 4 > req.Length) return;

                // Type/class
                ushort qtype  = (ushort)((req[offset]   << 8) | req[offset+1]);
                ushort qclass = (ushort)((req[offset+2] << 8) | req[offset+3]);
                bool isA      = qtype == 1 && qclass == 1;
                bool isTarget = _targets.Any(t =>
                    name.Equals(t, StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith("." + t, StringComparison.OrdinalIgnoreCase)
                );

                _logger($"[DNS] Query from {remote}: {name} (Type={qtype})");

                // STUN queries → real DNS so "Connecting…" finishes
                if (name.StartsWith("destiny-stun.", StringComparison.OrdinalIgnoreCase) ||
                    (name.StartsWith("stun", StringComparison.OrdinalIgnoreCase)
                     && name.Contains(".signon.", StringComparison.OrdinalIgnoreCase)))
                {
                    ForwardReal(name, id, req, remote);
                    return;
                }

                // Spoof all other A‐records for our targets
                if (isA && isTarget)
                {
                    SendResponse(id, req, remote, new[] { _advertisedIp });
                    _logger($"[DNS] Spoofed {name} → {_advertisedIp}");
                }
                else
                {
                    ForwardReal(name, id, req, remote);
                }
            }
            catch (Exception ex)
            {
                _logger($"[DNS][ERROR] Handle failed: {ex.Message}");
            }
        }

        private void ForwardReal(string hostname, ushort id, byte[] req, IPEndPoint remote)
        {
            try
            {
                var ips = Dns.GetHostAddresses(hostname)
                            .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                            .ToArray();
                if (ips.Length > 0)
                {
                    SendResponse(id, req, remote, ips);
                    var txt = string.Join(", ", ips.Select(a => a.ToString()));
                    _logger($"[DNS] Real A-record for {hostname} → {txt}");
                }
                else
                {
                    _logger($"[DNS] No real A-record for {hostname}");
                }
            }
            catch (Exception ex)
            {
                _logger($"[DNS][ERROR] real lookup failed for {hostname}: {ex.Message}");
            }
        }

        private void SendResponse(ushort id, byte[] req, IPEndPoint remote, IPAddress[] addrs)
        {
            try
            {
                using var ms = new MemoryStream();
                using var bw = new BinaryWriter(ms);

                // TXID
                bw.Write((byte)(id >> 8));
                bw.Write((byte)(id & 0xFF));

                // Flags: QR=1, AA=1, RD preserved, RA=1
                byte rd = (byte)(req[2] & 0x01);
                bw.Write((byte)(0x80 | 0x40 | rd));
                bw.Write((byte)0x80);

                // QDCOUNT
                bw.Write(req[4]); bw.Write(req[5]);

                // ANCOUNT
                bw.Write((byte)(addrs.Length >> 8));
                bw.Write((byte)(addrs.Length & 0xFF));

                // NS/ARCOUNT = 0
                bw.Write((byte)0); bw.Write((byte)0);
                bw.Write((byte)0); bw.Write((byte)0);

                // Copy question
                int qOff = 12;
                while (req[qOff] != 0) qOff++;
                qOff += 5; // null + QTYPE + QCLASS
                bw.Write(req, 12, qOff - 12);

                // Answers
                foreach (var ip in addrs)
                {
                    bw.Write((byte)0xC0); bw.Write((byte)0x0C);
                    bw.Write((byte)0x00); bw.Write((byte)0x01);
                    bw.Write((byte)0x00); bw.Write((byte)0x01);
                    bw.Write((byte)0x00); bw.Write((byte)0x00);
                    bw.Write((byte)0x00); bw.Write((byte)0x1E);
                    bw.Write((byte)0x00); bw.Write((byte)0x04);
                    bw.Write(ip.GetAddressBytes());
                }

                var resp = ms.ToArray();
                _udp?.Send(resp, resp.Length, remote);
            }
            catch (Exception ex)
            {
                _logger($"[DNS][ERROR] SendResponse failed: {ex.Message}");
            }
        }

        private static string ReadQName(byte[] pkt, ref int offset)
        {
            var sb = new StringBuilder();
            while (offset < pkt.Length && pkt[offset] != 0)
            {
                int len = pkt[offset++];
                sb.Append(Encoding.ASCII.GetString(pkt, offset, len));
                offset += len;
                if (pkt[offset] != 0) sb.Append('.');
            }
            offset++; // skip terminator
            return sb.ToString().ToLowerInvariant();
        }
    }
}
