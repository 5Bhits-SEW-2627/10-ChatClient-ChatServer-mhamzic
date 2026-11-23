
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

class SocketServer
{
    static void Main()
    {
        // Port, über den der Server erreichbar ist
        int port = 6851;

        // Der Server akzeptiert Verbindungen über alle Netzwerkschnittstellen
        IPAddress ipAddress = IPAddress.Any;

        // PKCS#12-Zertifikat laden
        // Das Passwort wurde beim Erstellen der server.p12-Datei vergeben
        X509Certificate2 zertifikat = new X509Certificate2(
            "server.p12",
            "Rumejsa110208!"
        );

        // TCP-Server erstellen und starten
        TcpListener server = new TcpListener(ipAddress, port);
        server.Start();

        Console.WriteLine($"Server gestartet auf Port {port}.");

        while (true)
        {
            // Auf eine neue Client-Verbindung warten
            TcpClient client = server.AcceptTcpClient();

            Console.WriteLine("Client verbunden!");

            // Für jeden Client einen eigenen Thread starten
            // Dadurch können mehrere Clients gleichzeitig verbunden sein
            Thread clientThread = new Thread(HandleClient);

            // Client und Zertifikat an die Methode übergeben
            clientThread.Start(new object[] { client, zertifikat });
        }
    }

    static void HandleClient(object obj)
    {
        // Übergebene Daten auslesen
        object[] daten = (object[])obj;

        TcpClient client = (TcpClient)daten[0];
        X509Certificate2 zertifikat = (X509Certificate2)daten[1];

        try
        {
            // SSL/TLS-Verbindung auf Basis der TCP-Verbindung erstellen
            using (SslStream sslStream = new SslStream(client.GetStream(), false))
            {
                // Server authentifiziert sich mit seinem Zertifikat
                // TLS 1.2 wird für die Verschlüsselung verwendet
                sslStream.AuthenticateAsServer(
                    zertifikat,
                    false,
                    System.Security.Authentication.SslProtocols.Tls12,
                    false
                );

                // StreamReader liest Nachrichten vom Client
                StreamReader reader = new StreamReader(sslStream, Encoding.UTF8);

                // StreamWriter sendet Nachrichten an den Client
                StreamWriter writer = new StreamWriter(sslStream, Encoding.UTF8)
                {
                    AutoFlush = true
                };

                Console.WriteLine("TLS-Verbindung hergestellt!");

                while (true)
                {
                    // Nachricht vom Client lesen
                    // ReadLine wartet bis zum Zeilenumbruch
                    string receivedMessage = reader.ReadLine();

                    // Wenn keine Nachricht mehr kommt, wurde die Verbindung beendet
                    if (receivedMessage == null)
                        break;

                    Console.WriteLine($"Empfangen: {receivedMessage}");

                    // Nachricht als Antwort zurücksenden
                    writer.WriteLine("Server: " + receivedMessage);
                }
            }
        }
        catch (Exception ex)
        {
            // Fehler bei der Verbindung oder Verschlüsselung ausgeben
            Console.WriteLine($"Fehler: {ex.Message}");
        }
        finally
        {
            // Verbindung zum Client schließen
            client.Close();
            Console.WriteLine("Client getrennt.");
        }
    }
}
