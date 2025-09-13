// File: Services/HttpCaptureService.cs

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using DeadOrbitCapture.Models;

namespace DeadOrbitCapture.Services
{
    public class HttpCaptureService
    {
        private readonly HttpListener _listener;
        private readonly Action<RequestLogEntry> _onLog;
        private readonly Action<string> _info;
        private int _signOnCount;

        private const string BungieIp   = "208.81.26.45";
        private const int    BungiePort = 80;

        public HttpCaptureService(int port,
                                  Action<RequestLogEntry> onLog,
                                  Action<string> info)
        {
            _onLog   = onLog;
            _info    = info;
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://*:{port}/");
        }

        public void Start()
        {
            try
            {
                _listener.Start();
                _info($"[HTTP] Listening on {string.Join(", ", _listener.Prefixes)}");
                _listener.BeginGetContext(OnContext, null);
            }
            catch (Exception ex)
            {
                _info($"[HTTP][ERROR] Start failed: {ex.Message}");
            }
        }

        public void Stop()
        {
            try { _listener.Stop(); } catch { }
        }

        private void OnContext(IAsyncResult ar)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = _listener.EndGetContext(ar);
            }
            catch
            {
                return;
            }
            finally
            {
                if (_listener.IsListening)
                    _listener.BeginGetContext(OnContext, null);
            }

            var req = ctx.Request;
            // 1) Log every HTTP request
            _info($"[HTTP] ▶ {req.HttpMethod} {req.RawUrl}   Host: {req.Headers["Host"]}");

            var entry = new RequestLogEntry
            {
                Timestamp = DateTime.Now,
                Method    = req.HttpMethod,
                Url       = req.Url?.AbsoluteUri ?? ""
            };

            byte[] body = Array.Empty<byte>();
            if (req.HasEntityBody)
            {
                using var ms = new MemoryStream();
                req.InputStream.CopyTo(ms);
                body = ms.ToArray();
                var reqFile = Path.Combine(AppContext.BaseDirectory, "Logs",
                    $"{DateTime.UtcNow:yyyyMMdd_HHmmssfff}_req.bin");
                Directory.CreateDirectory(Path.GetDirectoryName(reqFile)!);
                File.WriteAllBytes(reqFile, body);
                _info($"[HTTP] Saved request → {Path.GetFileName(reqFile)}");
            }

            try
            {
                HandleAsync(req, body, entry, ctx).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                // On any unhandled proxy error, return a minimal stub so the game can continue
                _info($"[HTTP][ERROR] Unhandled: {ex.Message}");
                const string stub = "{}";
                var buf = Encoding.UTF8.GetBytes(stub);
                ctx.Response.StatusCode      = 200;
                ctx.Response.ContentType     = "application/json";
                ctx.Response.ContentLength64 = buf.Length;
                ctx.Response.OutputStream.Write(buf, 0, buf.Length);
                ctx.Response.Close();

                entry.StatusCode   = 200;
                entry.ResponseBody = stub;
            }

            _onLog(entry);
        }

        private async Task HandleAsync(HttpListenerRequest req,
                                       byte[] body,
                                       RequestLogEntry entry,
                                       HttpListenerContext ctx)
        {
            var path   = req.Url?.AbsolutePath ?? "";
            bool isSign = path.EndsWith("/SignOn", StringComparison.OrdinalIgnoreCase)
                       || path.EndsWith("/Sign.On", StringComparison.OrdinalIgnoreCase);

            if (!isSign)
            {
                // Non-sign-on calls → simple JSON stub
                const string stub = "{}";
                var buf = Encoding.UTF8.GetBytes(stub);
                ctx.Response.StatusCode      = 200;
                ctx.Response.ContentType     = "application/json";
                ctx.Response.ContentLength64 = buf.Length;
                ctx.Response.OutputStream.Write(buf, 0, buf.Length);
                ctx.Response.Close();

                entry.StatusCode   = 200;
                entry.ResponseBody = stub;
                return;
            }

            // SIGN-ON CALL
            _signOnCount++;
            var hostHdr = (req.Headers["Host"] ?? "")
                .Replace("deadorbit.net", "gravityshavings.net", StringComparison.OrdinalIgnoreCase);

            _info($"[HTTP] SignOn #{_signOnCount} → {hostHdr}@{BungieIp}");

            // Build raw POST
            var sb = new StringBuilder();
            sb.AppendLine($"{req.HttpMethod} {req.RawUrl} HTTP/1.1");
            sb.AppendLine($"Host: {hostHdr}");
            sb.AppendLine("User-Agent: DestinyPS3");
            sb.AppendLine("Connection: close");
            sb.AppendLine("Content-Type: application/octet-stream");
            sb.AppendLine($"Content-Length: {body.Length}");
            sb.AppendLine();

            byte[] headerBytes = Encoding.ASCII.GetBytes(sb.ToString());

            // Proxy via raw TCP so RPCS3’s sys_net_bnet_recvfrom never sees an RST
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(BungieIp, BungiePort);
            using var network = tcp.GetStream();

            // Send headers + body
            await network.WriteAsync(headerBytes, 0, headerBytes.Length);
            if (body.Length > 0)
                await network.WriteAsync(body, 0, body.Length);

            // Read status line
            var reader = new StreamReader(network, Encoding.ASCII, false, 1024, true);
            string status = await reader.ReadLineAsync() ?? "HTTP/1.1 200 OK";

            // Read headers until blank line
            var responseHeaders = new WebHeaderCollection();
            string line;
            while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync()))
            {
                var idx = line.IndexOf(':');
                if (idx > 0)
                    responseHeaders.Add(line[..idx], line[(idx + 1)..].Trim());
            }

            // Determine content length
            int contentLen = 0;
            if (int.TryParse(responseHeaders["Content-Length"], out var cl))
                contentLen = cl;

            // Read exact body bytes
            var responseBody = new byte[contentLen];
            int readTotal = 0;
            while (readTotal < contentLen)
            {
                int chunk = await network.ReadAsync(responseBody, readTotal, contentLen - readTotal);
                if (chunk <= 0) break;
                readTotal += chunk;
            }

            // Log the raw SignOn response
            var rspFile = Path.Combine(AppContext.BaseDirectory, "Logs",
                $"{DateTime.UtcNow:yyyyMMdd_HHmmssfff}_SignOn_rsp.bin");
            File.WriteAllBytes(rspFile, responseBody);
            _info($"[HTTP] Logged real SignOn response → {Path.GetFileName(rspFile)}");

            // Relay the response back to RPCS3
            ctx.Response.StatusCode = ParseStatusCode(status);
            foreach (var key in responseHeaders.AllKeys)
                ctx.Response.AddHeader(key, responseHeaders[key]);

            await ctx.Response.OutputStream.WriteAsync(responseBody, 0, readTotal);
            ctx.Response.Close();

            entry.StatusCode   = ctx.Response.StatusCode;
            entry.ResponseBody = $"[Real SignOn: {readTotal} bytes]";
        }

        private int ParseStatusCode(string statusLine)
        {
            // e.g. "HTTP/1.1 200 OK"
            var parts = statusLine.Split(' ');
            if (parts.Length >= 2 && int.TryParse(parts[1], out var code))
                return code;
            return 200;
        }
    }
}
