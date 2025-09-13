using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Windows;
using DeadOrbitCapture.Models;
using DeadOrbitCapture.Services;

namespace DeadOrbitCapture
{
    public partial class MainWindow : Window
    {
        private DnsServer?           _dns;
        private HttpCaptureService? _http;
        private readonly string     _logDir = Path.Combine(AppContext.BaseDirectory, "Logs");

        public ObservableCollection<RequestLogEntry> Entries { get; } = new();

        public MainWindow()
        {
            InitializeComponent();
            LogList.ItemsSource = Entries;
        }

        private void Start_Click(object sender, RoutedEventArgs e)
        {
            Entries.Clear();
            Directory.CreateDirectory(_logDir);

            _dns?.Stop();
            _dns = new DnsServer(LogInfo);
            _dns.Start();

            _http?.Stop();
            _http = new HttpCaptureService(80, OnRequest, LogInfo);
            _http.Start();

            var ip = _dns.GetAdvertisedIPv4();
            IpText.Text = $"DNS → {ip}";
            Title     = $"DeadOrbit Capture — DNS: {ip}";

            LogInfo("[INFO] Services started.");
        }

        private void Stop_Click(object sender, RoutedEventArgs e)
        {
            _dns?.Stop();
            _http?.Stop();
            LogInfo("[INFO] Services stopped.");
        }

        private void ExportLog_Click(object sender, RoutedEventArgs e)
        {
            var file = Path.Combine(_logDir,
                $"SessionLog_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.txt");
            using var sw = new StreamWriter(file);
            foreach (var entry in Entries)
            {
                sw.WriteLine($"[{entry.Timestamp:O}] {entry.Display}");
                if (!string.IsNullOrWhiteSpace(entry.Body))
                    sw.WriteLine($"Body:\n{entry.Body}");
                if (!string.IsNullOrWhiteSpace(entry.ResponseBody))
                    sw.WriteLine($"Response:\n{entry.ResponseBody}");
                sw.WriteLine();
            }

            try
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{file}\"")
                { UseShellExecute = true });
            }
            catch { }

            LogInfo($"[INFO] Log exported: {file}");
        }

        private void ShowIfaces_Click(object sender, RoutedEventArgs e)
        {
            LogInfo("[INFO] Network Interfaces:");
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                LogInfo($" • {ni.Name} | {ni.NetworkInterfaceType} | {ni.OperationalStatus}");
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    LogInfo($"   - {ua.Address.AddressFamily} {ua.Address}");
            }
        }

        private void OnRequest(RequestLogEntry entry)
        {
            entry.Display = $"[{entry.Timestamp:HH:mm:ss}] {entry.Method} {entry.Url} ({entry.StatusCode})";
            Dispatcher.Invoke(() => Entries.Add(entry));
        }

        private void LogInfo(string msg)
        {
            var info = new RequestLogEntry
            {
                Timestamp = DateTime.Now,
                Method    = "INFO",
                Display   = msg
            };
            Dispatcher.Invoke(() => Entries.Add(info));
        }
    }
}
