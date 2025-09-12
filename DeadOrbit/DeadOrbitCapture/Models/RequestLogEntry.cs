using System;

namespace DeadOrbitCapture.Models
{
    public class RequestLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string Method { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public string Headers { get; set; } = string.Empty;
        public string Body { get; set; } = string.Empty;
        public int StatusCode { get; set; }
        public string ContentType { get; set; } = string.Empty;
        public string ResponseBody { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string Display { get; set; } = string.Empty;
    }
}
