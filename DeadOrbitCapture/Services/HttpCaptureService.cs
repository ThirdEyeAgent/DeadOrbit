using System;
using System.IO;
using System.Net;
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

        // Pre-captured server stubs (must exist next to your exe)
        private const string FirstStubFile  = "firstSignOnStub.bin";
        private const string SecondStubFile = "secondSignOnStub.bin";

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
                _info($"[HTTP][ERROR] Start: {ex.Message}");
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
            _info($"[HTTP] ▶ {req.HttpMethod} {req.RawUrl}   Host: {req.Headers["Host"]}");

            var entry = new RequestLogEntry
            {
                Timestamp = DateTime.Now,
                Method    = req.HttpMethod,
                Url       = req.Url?.AbsoluteUri ?? ""
            };

            // Read & log request body
            byte[] body = Array.Empty<byte>();
            if (req.HasEntityBody)
            {
                using var ms = new MemoryStream();
                req.InputStream.CopyTo(ms);
                body = ms.ToArray();
                var file = Path.Combine(AppContext.BaseDirectory, "Logs",
                    $"{DateTime.UtcNow:yyyyMMdd_HHmmssfff}_req.bin");
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                File.WriteAllBytes(file, body);
                _info($"[HTTP] Saved request → {Path.GetFileName(file)}");
            }

            try
            {
                HandleSignOn(req, body, entry, ctx).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                _info($"[HTTP][ERROR] Unhandled: {ex.Message}");
                // On any failure, send a minimal empty-TLV stub so game doesn’t hang
                SendStub(ctx, entry, new byte[]{0x10,0x01,0,0,0,0,0,0});
            }

            _onLog(entry);
        }

        private async Task HandleSignOn(HttpListenerRequest req,
                                        byte[] body,
                                        RequestLogEntry entry,
                                        HttpListenerContext ctx)
        {
            var path  = req.Url?.AbsolutePath ?? "";
            bool isSo = path.EndsWith("/SignOn", StringComparison.OrdinalIgnoreCase)
                     || path.EndsWith("/Sign.On", StringComparison.OrdinalIgnoreCase);

            if (!isSo)
            {
                // Non-SignOn → stub JSON
                SendJson(ctx, entry, "{}");
                return;
            }

            _signOnCount++;
            _info($"[HTTP] SignOn #{_signOnCount}");

            // Parse & log incoming TLV fields
            LogTlvFields(body);

            // Choose stub file
            string stubFile = _signOnCount == 1 ? FirstStubFile : SecondStubFile;
            byte[] stub;
            var stubPath = Path.Combine(AppContext.BaseDirectory, stubFile);
            if (File.Exists(stubPath))
            {
                stub = File.ReadAllBytes(stubPath);
                _info($"[HTTP] Loaded stub '{stubFile}' ({stub.Length} bytes)");
            }
            else
            {
                throw new FileNotFoundException($"Missing stub file: {stubFile}");
            }

            // Return stub directly
            ctx.Response.StatusCode      = 200;
            ctx.Response.ContentType     = "application/octet-stream";
            ctx.Response.ContentLength64 = stub.Length;
            await ctx.Response.OutputStream.WriteAsync(stub, 0, stub.Length);
            ctx.Response.Close();

            entry.StatusCode   = 200;
            entry.ResponseBody = $"[Stubbed SignOn #{_signOnCount}: {stub.Length} bytes]";
        }

        private void SendStub(HttpListenerContext ctx,
                              RequestLogEntry entry,
                              byte[] stub)
        {
            ctx.Response.StatusCode      = 200;
            ctx.Response.ContentType     = "application/octet-stream";
            ctx.Response.ContentLength64 = stub.Length;
            ctx.Response.OutputStream.Write(stub, 0, stub.Length);
            ctx.Response.Close();

            entry.StatusCode   = 200;
            entry.ResponseBody = $"[Fallback stub: {stub.Length} bytes]";
        }

        private void SendJson(HttpListenerContext ctx,
                              RequestLogEntry entry,
                              string json)
        {
            var buf = Encoding.UTF8.GetBytes(json);
            ctx.Response.StatusCode      = 200;
            ctx.Response.ContentType     = "application/json";
            ctx.Response.ContentLength64 = buf.Length;
            ctx.Response.OutputStream.Write(buf, 0, buf.Length);
            ctx.Response.Close();

            entry.StatusCode   = 200;
            entry.ResponseBody = json;
        }

        private void LogTlvFields(byte[] data)
        {
            int offset = 0;
            _info($"[TLV] Parsing {data.Length}-byte request...");
            while (offset + 8 <= data.Length)
            {
                ushort t  = (ushort)((data[offset]<<8)|(data[offset+1]));
                // ushort pad = (ushort)((data[offset+2]<<8)|(data[offset+3]));
                uint   len = (uint)((data[offset+4]<<24)|(data[offset+5]<<16)|(data[offset+6]<<8)|(data[offset+7]));
                offset += 8;
                if (offset + len > data.Length) break;
                _info($"[TLV] Type=0x{t:X4}, Length={len}");
                offset += (int)len;
            }
        }
    }
}
