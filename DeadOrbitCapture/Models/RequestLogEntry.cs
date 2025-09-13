using System;

namespace DeadOrbitCapture.Models
{
    public class RequestLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string Method { get; set; } = "";
        public string Url { get; set; } = "";
        public int StatusCode { get; set; }
        public string Body { get; set; } = "";
        public string ResponseBody { get; set; } = "";
        public string Display { get; set; } = "";
        public string? FilePath { get; set; }
    }
}
