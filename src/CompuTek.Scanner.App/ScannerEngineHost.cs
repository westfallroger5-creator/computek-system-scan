using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace CompuTek.Scanner.App
{
    internal sealed class EngineOutputEventArgs : EventArgs
    {
        public EngineOutputEventArgs(string text, bool isError)
        {
            Text = text;
            IsError = isError;
        }

        public string Text { get; private set; }
        public bool IsError { get; private set; }
    }

    internal sealed class EnginePromptEventArgs : EventArgs
    {
        public EnginePromptEventArgs(string prompt) { Prompt = prompt; }
        public string Prompt { get; private set; }
    }

    internal sealed class EngineExitedEventArgs : EventArgs
    {
        public EngineExitedEventArgs(int exitCode) { ExitCode = exitCode; }
        public int ExitCode { get; private set; }
    }

    internal sealed class ScannerEngineHost : IDisposable
    {
        private const string PromptPrefix = "__COMPUTEK_PROMPT__:";
        private readonly object sync = new object();
        private Process process;

        public event EventHandler<EngineOutputEventArgs> OutputReceived;
        public event EventHandler<EnginePromptEventArgs> PromptReceived;
        public event EventHandler<EngineExitedEventArgs> Exited;

        public bool IsRunning
        {
            get
            {
                lock (sync) { return process != null && !process.HasExited; }
            }
        }

        public void Start(string powerShellPath, string scriptPath, IEnumerable<string> arguments, string workingDirectory)
        {
            lock (sync)
            {
                if (process != null) throw new InvalidOperationException("A scanner is already running.");

                List<string> commandArguments = new List<string>();
                commandArguments.Add("-NoLogo");
                commandArguments.Add("-NoProfile");
                commandArguments.Add("-ExecutionPolicy");
                commandArguments.Add("Bypass");
                commandArguments.Add("-File");
                commandArguments.Add(scriptPath);
                commandArguments.AddRange(arguments);

                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = powerShellPath;
                startInfo.Arguments = JoinArguments(commandArguments);
                startInfo.WorkingDirectory = workingDirectory;
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = true;
                startInfo.RedirectStandardInput = true;
                startInfo.RedirectStandardOutput = true;
                startInfo.RedirectStandardError = true;
                startInfo.StandardOutputEncoding = Encoding.UTF8;
                startInfo.StandardErrorEncoding = Encoding.UTF8;
                startInfo.EnvironmentVariables["COMPUTEK_SCANNER_APP"] = "1";
                startInfo.EnvironmentVariables["COMPUTEK_SCANNER_PORTABLE_ROOT"] = AppDomain.CurrentDomain.BaseDirectory;

                process = new Process();
                process.StartInfo = startInfo;
                process.EnableRaisingEvents = true;
                process.OutputDataReceived += HandleOutput;
                process.ErrorDataReceived += HandleError;
                process.Exited += HandleExited;
                try
                {
                    if (!process.Start())
                        throw new InvalidOperationException("Windows PowerShell could not be started.");
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                }
                catch
                {
                    process.Dispose();
                    process = null;
                    throw;
                }
            }
        }

        public void SendInput(string value)
        {
            lock (sync)
            {
                if (process == null || process.HasExited)
                    throw new InvalidOperationException("The scanner is not waiting for input.");
                process.StandardInput.WriteLine(value ?? String.Empty);
                process.StandardInput.Flush();
            }
        }

        private void HandleOutput(object sender, DataReceivedEventArgs args)
        {
            if (args.Data == null) return;
            if (args.Data.StartsWith(PromptPrefix, StringComparison.Ordinal))
            {
                EventHandler<EnginePromptEventArgs> handler = PromptReceived;
                if (handler != null) handler(this, new EnginePromptEventArgs(args.Data.Substring(PromptPrefix.Length)));
                return;
            }
            EventHandler<EngineOutputEventArgs> output = OutputReceived;
            if (output != null) output(this, new EngineOutputEventArgs(args.Data, false));
        }

        private void HandleError(object sender, DataReceivedEventArgs args)
        {
            if (args.Data == null) return;
            EventHandler<EngineOutputEventArgs> output = OutputReceived;
            if (output != null) output(this, new EngineOutputEventArgs(args.Data, true));
        }

        private void HandleExited(object sender, EventArgs args)
        {
            int exitCode = -1;
            Process completed;
            lock (sync) { completed = process; }
            if (completed != null)
            {
                completed.WaitForExit();
                exitCode = completed.ExitCode;
            }
            EventHandler<EngineExitedEventArgs> handler = Exited;
            if (handler != null) handler(this, new EngineExitedEventArgs(exitCode));
        }

        private static string JoinArguments(IEnumerable<string> arguments)
        {
            StringBuilder builder = new StringBuilder();
            foreach (string argument in arguments)
            {
                if (builder.Length > 0) builder.Append(' ');
                builder.Append(QuoteArgument(argument));
            }
            return builder.ToString();
        }

        private static string QuoteArgument(string value)
        {
            if (String.IsNullOrEmpty(value)) return "\"\"";
            if (value.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '\"' }) < 0) return value;

            StringBuilder result = new StringBuilder();
            result.Append('\"');
            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\')
                {
                    backslashes++;
                }
                else if (character == '\"')
                {
                    result.Append('\\', backslashes * 2 + 1);
                    result.Append('\"');
                    backslashes = 0;
                }
                else
                {
                    result.Append('\\', backslashes);
                    backslashes = 0;
                    result.Append(character);
                }
            }
            result.Append('\\', backslashes * 2);
            result.Append('\"');
            return result.ToString();
        }

        public void Dispose()
        {
            lock (sync)
            {
                if (process != null && process.HasExited)
                {
                    process.Dispose();
                    process = null;
                }
            }
        }
    }
}
