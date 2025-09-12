using System;
using System.IO;
using DeadOrbitCapture.Models;

namespace DeadOrbitCapture.Services
{
    public class FileLogger
    {
        public string LogDirectory { get; }

        public FileLogger()
        {
            LogDirectory = Path.Combine(AppContext.BaseDirectory, "Logs");
            Directory.CreateDirectory(LogDirectory);
        }

        public string Save(RequestLogEntry entry)
        {
            try
            {
                var safeName = MakeSafeFileName($"{DateTime.Now:yyyy-MM-dd_HH-mm-ss-fff}_{entry.Method}_{entry.Url}");
                var filePath = Path.Combine(LogDirectory, safeName + ".txt");

                using var sw = new StreamWriter(filePath);
                sw.WriteLine($"[{entry.Timestamp:O}] {entry.Method} {entry.Url}");
                if (!string.IsNullOrWhiteSpace(entry.Headers))
                {
                    sw.WriteLine("Headers:");
                    sw.WriteLine(entry.Headers);
                }
                if (!string.IsNullOrWhiteSpace(entry.Body))
                {
                    sw.WriteLine("Body:");
                    sw.WriteLine(entry.Body);
                }
                if (!string.IsNullOrWhiteSpace(entry.ResponseBody))
                {
                    sw.WriteLine("Response:");
                    sw.WriteLine(entry.ResponseBody);
                }

                return filePath;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string MakeSafeFileName(string name)
        {
            foreach (var c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return name;
        }
    }
}
