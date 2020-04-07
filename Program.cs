using System;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Net.Mail;
using System.IO;

namespace serverSAF
{
    class Program
    {
        static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);

        static RSAParameters privKey;

        static RSAParameters pubKey;

        static string pubKeyStr;

        static TcpClient server;

        static ASCIIEncoding asen = new ASCIIEncoding();
        
        static TcpListener listen;

        static NetworkStream stm;

        static string mailCode;

        static string mailPassword;

        static byte[] b;

        #region RSAstuff
        static void RSASETUP()
        {
            privKey = csp.ExportParameters(true);
            pubKey = csp.ExportParameters(false);
            var sw = new System.IO.StringWriter();
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, pubKey);
            pubKeyStr = sw.ToString();
            //MessageBox.Show(pubKeyStr);
        }

        static string StripControlChars(string arg)
        {
            char[] arrForm = arg.ToCharArray();
            StringBuilder buffer = new StringBuilder(arg.Length);//This many chars at most

            foreach (char ch in arrForm)
                if (!Char.IsControl(ch)) buffer.Append(ch);//Only add to buffer if not a control char

            return buffer.ToString();
        }

        static string StripExtended(string arg)
        {
            StringBuilder buffer = new StringBuilder(arg.Length); //Max length
            foreach (char ch in arg)
            {
                UInt16 num = Convert.ToUInt16(ch);//In .NET, chars are UTF-16
                //The basic characters have the same code points as ASCII, and the extended characters are bigger
                if ((num >= 32u) && (num <= 126u)) buffer.Append(ch);
            }
            return buffer.ToString();
        }
        #endregion

        #region loginHandle
        static bool loginReq()
        {

            sendResponse(pubKeyStr);

            Console.WriteLine("server->client: <sent server's public RSA key[c101]>; now expecting client to execute c102");

            b = new byte[1024];

            while(true)
            {
                string mailAndPWString;
                try { mailAndPWString = readFromClient(); }
                catch (Exception) { Console.WriteLine("Exception occured in loginReq() while reading from socket stream!"); break; }

                //Console.WriteLine("client->server: " + mailAndPWString);

                var bytesCypherText = Convert.FromBase64String(mailAndPWString);
                csp.ImportParameters(privKey);
                var bytesPlainTextData = csp.Decrypt(bytesCypherText, false);
                var plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);

                string mail, pw;
                Console.WriteLine("server: extracting password and mail from " + plainTextData);
                ExtractPWandMAIL(plainTextData,out mail, out pw);
                if (!checkIFUserExists(mail + pw))
                    return false;
            }


            return false;
        }
        static bool checkIFUserExists(string entry)
        {
            char[] ceasarRing = new char[222];

            //creating ceasarRing:
            int num = 0;
            for(int i = 33; i <= 254; i++)
            {
                ceasarRing[num++] = (char) i;
            }

            //encoding the given string into ceasarText:
            int SHIFT = 70;
            string encodedEntry = "";

            foreach(char c in entry)
            {
                encodedEntry += (char)((((int)c) + SHIFT)%222);
            }

            Console.WriteLine("encEntry: " + encodedEntry);

            string[] lines = System.IO.File.ReadAllLines("../../../loginBase.data");

            foreach(string s in lines)
            {
                if (string.Equals(encodedEntry, s))
                    return true;
            }
            return false;
        }
        static void ExtractPWandMAIL(string plainTextData,out string mail, out string pw)
        {
            mail = new String("");
            pw = new String("");

            string[] array = plainTextData.Split(new char[] { '$' }, 2);

            mail = array[0];
            pw = array[1];
            return;
        }

        #endregion

        #region registerHandler
        static void sendMail(string address)
        {
            try
            {
                MailMessage mail = new MailMessage();
                SmtpClient SmtpServer = new SmtpClient("smtp.gmail.com");

                mail.From = new MailAddress("safeaf.noreply@gmail.com");
                mail.To.Add(address);
                mail.Subject = "Registration code";
                mail.Body = File.ReadAllText("../../../Resources/niceMail.html").Replace("[CODEPLACEHOLDER]", mailCode);
                mail.IsBodyHtml = true;
                SmtpServer.Port = 587;
                SmtpServer.Credentials = new System.Net.NetworkCredential("safeaf.noreply@gmail.com", mailPassword);
                SmtpServer.EnableSsl = true;

                SmtpServer.Send(mail);
                Console.WriteLine("mail Sent");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        static bool sendCode()
        {
            
            sendResponse(pubKeyStr);  //maybe put it in while(client.Available == 0){} here
            string mailCypher = readFromClient();
            Random random = new Random();
            int randomCode = random.Next(0, 9999);
            mailCode = randomCode.ToString();
            var bytesCypherText = Convert.FromBase64String(mailCypher);
            csp.ImportParameters(privKey);
            
            var bytesPlainTextData = csp.Decrypt(bytesCypherText, false);
            var plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);

            Console.WriteLine("Rec mail:" + plainTextData);
            sendMail(plainTextData.Replace('$',' '));
            return false;
        }
        #endregion

        #region comms
        static void sendResponse(string responseCode, bool stopCW = false)
        {
            b = asen.GetBytes(responseCode);
            stm.Write(b, 0, b.Length);
            if(!stopCW)
                Console.WriteLine("server->client: " + responseCode);
        }
        static string readFromClient(int size=1024, bool stopCW = false)
        {
            if (server.Available == 0)
                Console.WriteLine("NOTHING TO READ");
            b = new byte[size];
            stm.Read(b, 0, b.Length);
            if(!stopCW)
                Console.WriteLine("client->server: " + StripControlChars(Encoding.Default.GetString(b)));
            return StripControlChars(Encoding.Default.GetString(b));
        }
        #endregion
        static void Main(string[] args)
        {
            RSASETUP();
            listen = new TcpListener(IPAddress.Any, 1234);
            listen.Start();
            Console.WriteLine("please input server's mail password");
            mailPassword = Console.ReadLine();
            Console.WriteLine("Started the server at the port 1234. Current time: " + DateTime.Now);

            while (true) {

                server = listen.AcceptTcpClient();
                stm = server.GetStream();

                Console.WriteLine("Connection accepted from " + server.Client.RemoteEndPoint);
                
                while(server.Connected){
                    if (server.Available == 0)
                        continue;
                    String requestRaw = readFromClient(4);
                    Console.WriteLine("client->server: (request_EOC) =" + requestRaw +"_EOC");

                    if (String.Equals(requestRaw,"c100"))
                    { 
                        if(loginReq())
                            sendResponse("c105");
                        else
                            sendResponse("c104");
                    }
                    else if(String.Equals(requestRaw,"e100"))
                    {
                        stm.Close();
                        server.Close();
                    }
                    else if(String.Equals(requestRaw,"r110"))
                    {
                        sendCode();
                    }
                }
                Console.WriteLine("=======END of communication==========");
                stm.Close();
                server.Close();
            }
        }
    }
}
