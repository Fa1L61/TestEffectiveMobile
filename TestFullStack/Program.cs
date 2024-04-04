using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace IpRangeAnalyzer
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string[] parameters = Console.ReadLine().Split();
                

                // Получение параметров из командной строки, конфигурационного файла и переменных среды
                var (logFilePath, outputFilePath, addressStart, addressMask) = GetParameters(parameters);

                // Чтение логов из файла
                var ipLogs = ReadIpLogs(logFilePath);

                // Фильтрация по диапазону адресов
                var filteredIpLogs = FilterByIpRange(ipLogs, addressStart, addressMask);

                // Подсчет количества обращений для каждого адреса
                var ipCounts = CountIpRequests(filteredIpLogs);

                // Запись результата в файл
                WriteOutputFile(outputFilePath, ipCounts);

                Console.WriteLine("Анализ завершен, результат записан в файл.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Произошла ошибка: {ex.Message}");
            }
        }

        static (string, string, IPAddress, string) GetParameters(string[] args)
        {
            string logFilePath = null;
            string outputFilePath = null;
            IPAddress addressStart = null;
            string addressMask = null;

            // Получение параметров из командной строки
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--file-log":
                        logFilePath = args[++i];
                        break;
                    case "--file-output":
                        outputFilePath = args[++i];
                        break;
                    case "--address-start":
                        addressStart = IPAddress.Parse(args[++i]);
                        break;
                    case "--address-mask":
                        addressMask = args[++i];
                        break;
                }
            }

            // Получение параметров из конфигурационного файла
            if (string.IsNullOrEmpty(logFilePath))
            {
                logFilePath = ConfigurationManager.AppSettings["logFilePath"];
            }

            if (string.IsNullOrEmpty(outputFilePath))
            {
                outputFilePath = ConfigurationManager.AppSettings["outputFilePath"];
            } 

            if (addressStart == null)
            {
                var addressStartStr = ConfigurationManager.AppSettings["addressStart"];
                if (!string.IsNullOrEmpty(addressStartStr))
                {
                    addressStart = IPAddress.Parse(addressStartStr);
                }
            }

            if (string.IsNullOrEmpty(addressMask))
            {
                addressMask = ConfigurationManager.AppSettings["addressMask"];
            }

            // Получение параметров из переменных среды
            if (string.IsNullOrEmpty(logFilePath))
            {
                logFilePath = Environment.GetEnvironmentVariable("LOG_FILE_PATH");
            }
                

            if (string.IsNullOrEmpty(outputFilePath))
            {
                outputFilePath = Environment.GetEnvironmentVariable("OUTPUT_FILE_PATH");
            }
                

            if (addressStart == null)
            {
                var addressStartStr = Environment.GetEnvironmentVariable("ADDRESS_START");
                if (!string.IsNullOrEmpty(addressStartStr))
                {
                    addressStart = IPAddress.Parse(addressStartStr);
                }
                    
            }

            if (string.IsNullOrEmpty(addressMask))
            {
                addressMask = Environment.GetEnvironmentVariable("ADDRESS_MASK");
            }

            // Проверка обязательных параметров
            if (string.IsNullOrEmpty(logFilePath) || string.IsNullOrEmpty(outputFilePath))
            {
                throw new ArgumentException("Не указаны обязательные параметры --file-log или --file-output.");
            }
                
            // Если задана маска, но не задан диапазон адресов, выводим ошибку
            if (!string.IsNullOrEmpty(addressMask) && addressStart == null)
            {
                throw new ArgumentException("Если задана маска подсети, то необходимо указать диапазон адресов.");
            }
                
            return (logFilePath, outputFilePath, addressStart, addressMask);
        }

        static List<(IPAddress, DateTime)> ReadIpLogs(string filePath)
        {
            var ipLogs = new List<(IPAddress, DateTime)>();
            var regex = new Regex(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ([\d-]+\s[\d:]+)");

            try
            {
                foreach (var line in File.ReadLines(filePath))
                {
                    var match = regex.Match(line);
                    if (match.Success)
                    {
                        var ip = IPAddress.Parse(match.Groups[1].Value);
                        var time = DateTime.Parse(match.Groups[2].Value);
                        ipLogs.Add((ip, time));
                    }
                }
            }
            catch (IOException ex)
            {
                Console.WriteLine($"Ошибка при чтении входного файла: {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Произошла неизвестная ошибка при чтении входного файла: {ex.Message}");
                throw;
            }

            return ipLogs;
        }

        static List<(IPAddress, DateTime)> FilterByIpRange(List<(IPAddress, DateTime)> ipLogs, IPAddress addressStart, string addressMask)
        {
            if (addressStart == null && string.IsNullOrEmpty(addressMask))
            {
                return ipLogs;
            }

            var filteredIpLogs = new List<(IPAddress, DateTime)>();

            try
            {
                if (!string.IsNullOrEmpty(addressMask))
                {
                    var mask = IPAddress.Parse(addressMask);
                    foreach (var (ip, time) in ipLogs)
                    {
                        if ((ip.Address & mask.Address) >= (addressStart.Address & mask.Address))
                        {
                            filteredIpLogs.Add((ip, time));
                        }
                    }
                }
                else if (addressStart != null)
                {
                    foreach (var (ip, time) in ipLogs)
                    {
                        if (ip.Equals(addressStart))
                        {
                            filteredIpLogs.Add((ip, time));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Произошла ошибка при фильтрации IP-адресов: {ex.Message}");
                throw;
            }

            return filteredIpLogs;
        }

        static Dictionary<IPAddress, int> CountIpRequests(List<(IPAddress, DateTime)> ipLogs)
        {
            var ipCounts = new Dictionary<IPAddress, int>();

            foreach (var (ip, _) in ipLogs)
            {
                if (ipCounts.ContainsKey(ip))
                {
                    ipCounts[ip]++;
                }
                else
                {
                    ipCounts[ip] = 1;
                }
            }

            return ipCounts;
        }
        static void WriteOutputFile(string filePath, Dictionary<IPAddress, int> ipCounts)
        {
            try
            {
                using (var writer = new StreamWriter(filePath))
                {
                    foreach (var (ip, count) in ipCounts.OrderByDescending(x => x.Value))
                    {
                        writer.WriteLine($"{ip} - {count}");
                    }
                }
            }
            catch (IOException ex)
            {
                Console.WriteLine($"Ошибка при записи в выходной файл: {ex.Message}");
                throw;
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"Ошибка доступа к выходному файлу: {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Произошла неизвестная ошибка при записи в выходной файл: {ex.Message}");
                throw;
            }
        }
    }
}