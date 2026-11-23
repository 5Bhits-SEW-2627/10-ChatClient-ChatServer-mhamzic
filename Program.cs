
using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

class SocketClient
{
    static void Main()
    {
        // IP-Adresse und Port des Servers
        string serverIp = "192.168.56.1";
        int port = 6851;

        try
        {
            // Öffentliches Zertifikat des Servers laden
            // Damit kann der Client überprüfen, ob er dem Server vertrauen kann
            X509Certificate2 vertrauensZertifikat = new X509Certificate2("server.crt");

            // TCP-Verbindung zum Server herstellen
            using (TcpClient client = new TcpClient(serverIp, port))

            // TLS-Verbindung auf Basis der TCP-Verbindung erstellen
            using (SslStream sslStream = new SslStream(
                client.GetStream(),
                false,

                // Diese Methode überprüft das Zertifikat des Servers
                (sender, certificate, chain, errors) =>
                {
                    // Wenn kein Zertifikat vorhanden ist, Verbindung ablehnen
                    if (certificate == null)
                        return false;

                    // Zertifikat des Servers auslesen
                    using (X509Certificate2 serverZertifikat =
                        new X509Certificate2(certificate))
                    {
                        // Fingerabdrücke vergleichen
                        // Dadurch wird überprüft, ob es unser Zertifikat ist
                        if (serverZertifikat.Thumbprint != vertrauensZertifikat.Thumbprint)
                            return false;

                        // Überprüfen, ob der Servername zur IP-Adresse passt
                        if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                            return false;

                        // Überprüfen, ob das Zertifikat verfügbar ist
                        if ((errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
                            return false;

                        // Zertifikat wurde akzeptiert
                        return true;
                    }
                }))
            {
                // TLS-Verbindung aufbauen und Server authentifizieren
                sslStream.AuthenticateAsClient(serverIp);

                // Nachrichten über die verschlüsselte Verbindung lesen und schreiben
                using (StreamReader reader = new StreamReader(sslStream, Encoding.UTF8))
                using (StreamWriter writer = new StreamWriter(sslStream, Encoding.UTF8)
                {
                    AutoFlush = true
                })
                {
                    Console.WriteLine("TLS-Verbindung hergestellt!");

                    while (true)
                    {
                        // Benutzer nach einer Nachricht fragen
                        Console.Write("Deine Nachricht: ");
                        string message = Console.ReadLine();

                        // Bei leerer Eingabe wird die Verbindung beendet
                        if (string.IsNullOrEmpty(message))
                            break;

                        // Nachricht an den Server senden
                        writer.WriteLine(message);

                        // Antwort vom Server empfangen
                        string response = reader.ReadLine();

                        Console.WriteLine(response);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // Fehler anzeigen, falls die Verbindung nicht funktioniert
            Console.WriteLine($"Fehler: {ex.Message}");
        }

        Console.WriteLine("Verbindung getrennt.");
    }
}
