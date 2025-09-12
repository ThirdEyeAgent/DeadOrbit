using System;
using System.IO;
using System.Net;
using System.Text;
using DeadOrbitCapture.Models;

namespace DeadOrbitCapture.Services
{
    public enum SignatureStrategy
    {
        Zero,
        Echo,
        Random
    }

    public class HttpCaptureService
    {
        private HttpListener? _listener;
        private readonly int _port;
        private readonly Action<RequestLogEntry> _onLog;
        private readonly Action<string> _info;
        private readonly SignatureStrategy _sigStrategy;
        private volatile bool _running;

        public HttpCaptureService(int port, Action<RequestLogEntry> onLog, Action<string> info, SignatureStrategy strategy)
        {
            _port = port;
            _onLog = onLog;
            _info = info;
            _sigStrategy = strategy;
        }

        public void Start()
        {
            Stop();
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://*:{_port}/");
            try
            {
                _listener.Start();
            }
            catch (HttpListenerException ex)
            {
                _info($"[HTTP][ERROR] Failed to bind :{_port}. Run as Administrator. {ex.Message}");
                return;
            }

            _running = true;
            _info($"[HTTP] Listening on :{_port}");
            try { _listener.BeginGetContext(OnRequest, null); } catch { }
        }

        public void Stop()
        {
            _running = false;
            try { _listener?.Stop(); } catch { }
            try { _listener?.Close(); } catch { }
            _listener = null;
        }

        private void OnRequest(IAsyncResult ar)
        {
            if (!_running || _listener == null || !_listener.IsListening) return;

            HttpListenerContext? context = null;
            try { context = _listener.EndGetContext(ar); } catch { }
            finally
            {
                if (_running && _listener?.IsListening == true)
                {
                    try { _listener.BeginGetContext(OnRequest, null); } catch { }
                }
            }
            if (context == null) return;

            var req = context.Request;
            var entry = new RequestLogEntry
            {
                Timestamp = DateTime.Now,
                Method = req.HttpMethod,
                Url = req.Url?.ToString() ?? "",
                Headers = req.Headers?.Count > 0
                    ? string.Join("\n", Array.ConvertAll(req.Headers.AllKeys, k => $"{k}: {req.Headers[k]}"))
                    : ""
            };

            byte[] rawBody = Array.Empty<byte>();
            if (req.HasEntityBody)
            {
                using var ms = new MemoryStream();
                req.InputStream.CopyTo(ms);
                rawBody = ms.ToArray();

                var safeName = MakeSafeFileName($"{DateTime.Now:yyyy-MM-dd_HH-mm-ss-fff}_{req.Url?.Host}_{req.Url?.AbsolutePath}.bin");
                var savePath = Path.Combine(AppContext.BaseDirectory, "Logs", safeName);
                Directory.CreateDirectory(Path.GetDirectoryName(savePath)!);
                File.WriteAllBytes(savePath, rawBody);

                entry.Body = BuildHexAsciiDump(rawBody);
            }

            try
            {
                HandleRoute(req, rawBody, ref entry, context);
            }
            catch (Exception ex)
            {
                _info($"[HTTP][ERROR] Route handling failed: {ex.Message}");
                entry.StatusCode = 500;
                entry.ContentType = "application/json";
                entry.ResponseBody = "{\"error\":\"internal\"}";
                TryWriteJson(context, entry.StatusCode, entry.ResponseBody);
            }

            _onLog(entry);
        }

        private void HandleRoute(HttpListenerRequest req, byte[] rawBody, ref RequestLogEntry entry, HttpListenerContext context)
        {
            var path = req.Url?.AbsolutePath ?? "";

            if (path.EndsWith("/Sign.On", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith("/SignOn", StringComparison.OrdinalIgnoreCase))
            {
                _info($"[HTTP] Handling binary sign-on for {path} [LOOSE+STRUCTURE, SIG={_sigStrategy}]");

                DumpNamedFields(rawBody, _info);
                DumpLikelyTlvs(rawBody, _info);

                var fakeResponse = BuildLooseStructuredResponse(rawBody, _sigStrategy);

                entry.StatusCode = 200;
                entry.ContentType = "application/octet-stream";
                entry.ResponseBody = $"[Binary payload: {fakeResponse.Length} bytes]";

                try
                {
                    context.Response.StatusCode = entry.StatusCode;
                    context.Response.ContentType = entry.ContentType;
                    context.Response.ContentLength64 = fakeResponse.Length;
                    context.Response.OutputStream.Write(fakeResponse, 0, fakeResponse.Length);
                    context.Response.OutputStream.Flush();
                }
                catch (Exception ex)
                {
                    _info($"[HTTP][ERROR] Response send failed: {ex.Message}");
                }
                finally
                {
                    try { context.Response.Close(); } catch { }
                }
                return;
            }

            entry.StatusCode = 200;
            entry.ContentType = "application/json";
            entry.ResponseBody = "{}";
            TryWriteJson(context, entry.StatusCode, entry.ResponseBody);
        }

        private void TryWriteJson(HttpListenerContext context, int status, string json)
        {
            try
            {
                var buf = Encoding.UTF8.GetBytes(json);
                context.Response.StatusCode = status;
                context.Response.ContentType = "application/json";
                context.Response.ContentLength64 = buf.Length;
                context.Response.OutputStream.Write(buf, 0, buf.Length);
                context.Response.OutputStream.Flush();
            }
            catch (Exception ex)
            {
                _info($"[HTTP][ERROR] JSON send failed: {ex.Message}");
            }
            finally
            {
                try { context.Response.Close(); } catch { }
            }
        }

        // Always Loose+Structure: copy framing, overwrite token, adjust signature per strategy, update timestamp
        private byte[] BuildLooseStructuredResponse(byte[] request, SignatureStrategy strategy)
        {
            var resp = new byte[request.Length];
            Buffer.BlockCopy(request, 0, resp, 0, request.Length);

            // Status OK
            resp[0] = 0x00;

            // Overwrite token at 0x00B0..0x00CF (0x20 bytes)
            WriteAsciiFill(resp, 0x00B0, ("SVR-" + Guid.NewGuid().ToString("N")).AsSpan(), 0x00D0 - 0x00B0);

            // Adjust signature blob 0x00F0..0x015F (0x70 bytes) per strategy
            switch (strategy)
            {
                case SignatureStrategy.Echo:
                    // Keep as copied from request (already copied above)
                    break;
                case SignatureStrategy.Random:
                    Random.Shared.NextBytes(resp.AsSpan(0x00F0, 0x0160 - 0x00F0));
                    break;
                case SignatureStrategy.Zero:
                default:
                    FillZeros(resp, 0x00F0, 0x0160 - 0x00F0);
                    break;
            }

            // Update timestamp near end (overwrite 4 bytes ~12 from end)
            var ts = BitConverter.GetBytes((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            if (resp.Length >= 12)
            {
                int tOff = resp.Length - 12;
                Buffer.BlockCopy(ts, 0, resp, tOff, Math.Min(4, resp.Length - tOff));
            }

            return resp;
        }

        private static void DumpNamedFields(byte[] data, Action<string> log)
        {
            // Token 0x00B0..0x00CF (32 bytes ASCII-ish)
            var token = SafeSliceString(data, 0x00B0, 0x20);
            log($"[SignOn] Token @0x00B0..0x00CF: \"{token}\"");

            // Signature blob 0x00F0..0x015F (0x70 bytes)
            var sigHex = HexRange(data, 0x00F0, 0x0160 - 0x00F0);
            log($"[SignOn] Signature @0x00F0..0x015F ({0x0160 - 0x00F0} bytes): {sigHex}");

            // Build/version string near 0x0136..0x015F (fits within signature zone in request)
            var buildStr = SafeSliceString(data, 0x0136, Math.Max(0, 0x0160 - 0x0136));
            log($"[SignOn] BuildStr ~0x0136: \"{buildStr}\"");

            // Region string around 0x01A6 (ends before end of buffer)
            if (data.Length > 0x01A6)
            {
                var max = Math.Min(32, data.Length - 0x01A6);
                var region = SafeSliceString(data, 0x01A6, max);
                log($"[SignOn] Region ~0x01A6: \"{region}\"");
            }

            // Trailing timestamp (first 4 bytes out of last 12)
            if (data.Length >= 12)
            {
                int tOff = data.Length - 12;
                uint ts = BitConverter.ToUInt32(data, tOff);
                log($"[SignOn] Trailing time at [-12..-9]: {ts} (unix)");
            }
        }

        private static void DumpLikelyTlvs(byte[] data, Action<string> log)
        {
            // Heuristic TLV scanner based on captures; tolerant to noise
            int i = 0;
            int limit = data.Length;
            log("[TLV] Scan start");
            while (i + 3 <= limit)
            {
                byte t = data[i];
                byte l0 = data[i + 1];
                int len = l0;
                int header = 2;

                // Heuristic: many blocks look like 0x?? 0x?? 0x00 (16-bit LE)
                if (i + 2 < limit && data[i + 2] == 0x00)
                {
                    len = data[i + 1] | (data[i + 2] << 8);
                    header = 3;
                }

                // Basic sanity
                if (len < 0 || i + header + len > limit)
                {
                    i++;
                    continue;
                }

                string range = $"{i:X4}..{(i + header + len - 1):X4}";
                log($"[TLV] T=0x{t:X2} L={len} Range={range}");

                i += header + len;
            }
            log("[TLV] Scan end");
        }

        private static string SafeSliceString(byte[] data, int offset, int count)
        {
            if (offset < 0 || count <= 0 || offset >= data.Length) return "";
            int actual = Math.Min(count, data.Length - offset);
            var span = new ReadOnlySpan<byte>(data, offset, actual);
            // Trim trailing zeros for readability
            int end = actual;
            while (end > 0 && span[end - 1] == 0x00) end--;
            return Encoding.ASCII.GetString(span.Slice(0, end));
        }

        private static string HexRange(byte[] data, int offset, int count)
        {
            if (offset < 0 || count <= 0 || offset >= data.Length) return "";
            int actual = Math.Min(count, data.Length - offset);
            var sb = new StringBuilder(actual * 3);
            for (int i = 0; i < actual; i++)
            {
                sb.AppendFormat("{0:X2}", data[offset + i]);
                if (i + 1 < actual) sb.Append(' ');
            }
            return sb.ToString();
        }

        private static bool ContainsAscii(byte[] data, string ascii)
        {
            if (string.IsNullOrEmpty(ascii)) return false;
            try
            {
                var hay = Encoding.ASCII.GetString(data);
                return hay.IndexOf(ascii, StringComparison.Ordinal) >= 0;
            }
            catch
            {
                return false;
            }
        }

        private static void WriteAsciiFill(byte[] buffer, int offset, ReadOnlySpan<char> text, int width)
        {
            if (offset < 0 || offset >= buffer.Length || width <= 0) return;
            var bytes = Encoding.ASCII.GetBytes(text.ToString());
            int count = Math.Min(width, Math.Min(bytes.Length, buffer.Length - offset));
            Buffer.BlockCopy(bytes, 0, buffer, offset, count);
            int pad = Math.Min(width, buffer.Length - offset) - count;
            if (pad > 0) Array.Clear(buffer, offset + count, pad);
        }

        private static void FillZeros(byte[] buffer, int offset, int count)
        {
            if (offset < 0 || count <= 0) return;
            int actual = Math.Min(count, Math.Max(0, buffer.Length - offset));
            if (actual > 0) Array.Clear(buffer, offset, actual);
        }

        private static string BuildHexAsciiDump(byte[] data)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < data.Length; i += 16)
            {
                var hex = new StringBuilder();
                var ascii = new StringBuilder();
                for (int j = 0; j < 16 && i + j < data.Length; j++)
                {
                    byte b = data[i + j];
                    hex.AppendFormat("{0:X2} ", b);
                    ascii.Append(b >= 32 && b <= 126 ? (char)b : '.');
                }
                sb.AppendFormat("{0:X4}  {1,-48}  {2}\n", i, hex.ToString(), ascii.ToString());
            }
            return sb.ToString();
        }

        private static string MakeSafeFileName(string name)
        {
            foreach (var c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return name;
        }
    }
}
