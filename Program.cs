﻿using System;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Net.Mail;
using System.IO;
using System.Collections.Generic;

namespace serverSAF
{
    class Program
    {
        static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);

        static RSAParameters privKey;

        static RSAParameters pubKey;
        
        static char[] ceasarRing;

        static string pubKeyStr;

        static TcpClient server;

        static ASCIIEncoding asen = new ASCIIEncoding();
        
        static TcpListener listen;

        static NetworkStream stm;

        static string mailCode;

        static string mailPassword;

        static byte[] b;

        static string recentMail;

        static string recentIP;
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

            sendResponse(pubKeyStr,stopCW:true);

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

                recentMail = mail;

                if (!checkIFUserExists(mail + "$" + pw))
                    return false;
                else
                    return true;
            }


            return false;
        }

        static void createCeasar()
        {
            ceasarRing = new char[222];
            //creating ceasarRing:
            int num = 0;
            for (int i = 33; i <= 254; i++)
            {
                ceasarRing[num++] = (char)i;
            }
        }
        static bool checkIFUserExists(string entry)
        {
            if (ceasarRing == null)
                createCeasar();

            //encoding the given string into ceasarText:
            int SHIFT = 70;

            string[] lines = System.IO.File.ReadAllLines("../../../loginBase.data");
            Console.WriteLine("WHOLE DATABASE:");
            foreach(string s in lines)
            {
                string decoded = "";
                foreach(char c in s)
                    decoded += (char)((((int)c) - SHIFT) % 222);
                if (string.Equals(entry, decoded))
                {
                    Console.WriteLine("OKAY");
                    return true;
                }
            }
            return false;
        }
        //gets called from main
        static void getUserData()
        {
           
            if (!loginReq())
                sendResponse("c104");
            else
                sendResponse("c102");

            Console.WriteLine("ok im in");
            sendResponse("g101");

            List<string[]> temp = readAllSiteMailPassword(recentMail);

            temp.ForEach(delegate (string[] del)
            {
                Console.WriteLine("=========");
                sendResponse(del[0], true);
                string temp = readFromClient();
                Console.WriteLine("========="+temp);
                sendResponse(del[1], true);
                temp = readFromClient();
                Console.WriteLine("=========");
                sendResponse(del[2], true);
                temp = readFromClient();
                Console.WriteLine("=========");
            });
            sendResponse("g300");

        }

        static void newPw()
        {
            sendResponse("n101");
            string site = readFromClient();
            sendResponse("ok");
            string mail = readFromClient();
            sendResponse("ok");
            string password = readFromClient();
            sendResponse("ok");

            appendPasswordListForUser(recentMail, site, mail, password);
        }

        static void appendPasswordListForUser(string usermail, string site, string mail, string password)
        {
            string encryptCeasar(string str, int shift)
            {
                if (ceasarRing == null)
                    createCeasar();
                string newStr = "";
                foreach (char c in str)
                {
                    newStr += (char)((((int)c) + shift) % 222);
                }
                return newStr;
            }

            using (StreamWriter sw = File.AppendText("../../../DATABASE/"+usermail+".data"))
            {
                sw.WriteLine(encryptCeasar(site,70));
                sw.WriteLine(encryptCeasar(mail, 70));
                sw.WriteLine(encryptCeasar(password, 70));
            }
        }

        static List<string[]> readAllSiteMailPassword(string usermail)
        {
            string decryptCeasar(string str, int shift)
            {
                if (ceasarRing == null)
                    createCeasar();

                string newStr = "";
                foreach (char c in str)
                {
                    int temp = (((int)c) - shift);
                    if (temp < 0)
                        temp = 221 - temp; //mzd 222
                    newStr += (char)temp;
                }
                return newStr;
            }

            List<string[]> data = new List<string[]>();

            int counter = 0;

            string[] tempArr = new string[3];
            IEnumerable<string> lines = null;
            if (File.Exists("../../../DATABASE/" + usermail + ".data"))
            { 
                 lines = File.ReadLines("../../../DATABASE/" + usermail + ".data");
                foreach (var line in lines)
                {
                    if (counter == 0)
                        tempArr = new string[3];

                    tempArr[counter++] = decryptCeasar(line,70);

                    if(counter == 3)
                    {
                        counter = 0;
                        data.Add(tempArr);
                    }
                }
            }

            /*
            data.ForEach(delegate(string[] pair)
            {
                Console.WriteLine("########");
                Console.WriteLine(decryptCeasar(pair[0], 70));
                Console.WriteLine(decryptCeasar(pair[1], 70));
                Console.WriteLine(decryptCeasar(pair[2], 70));
            });
            */

            return data;
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

        static bool HandleRegisterRequest()
        {
            //
            var bytesCypherText = Convert.FromBase64String(readFromClient(size: 1024));
            Console.WriteLine("rec1");
            csp.ImportParameters(privKey);
            var bytesPlainTextData = csp.Decrypt(bytesCypherText, false);
            string newData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);

            Console.WriteLine(newData);

            String newMail = "";
            String newCode = "";
            String newPw = "";
            int i = 0;
            for (; i<newData.Length;i++)
            {
                if (newData[i] == '$')
                    break;
                newMail += newData[i];
            }
            for (i++; i < newData.Length; i++)
            {
                if (newData[i] == '$')
                    break;
                newCode += newData[i];
            }
            for (i++; i < newData.Length; i++)
            {
                newPw += newData[i];
            }
            recentMail = newMail;
            Console.WriteLine("newMail: "+newMail);
            Console.WriteLine("newCode: " + newCode);
            Console.WriteLine("newPw: "+ newPw);

            if (ceasarRing == null)
                createCeasar();


            if(newCode == mailCode)
            {
                string newUser = "";
                int SHIFT = 70;

                foreach (char c in newMail+"$"+newPw)
                {
                    newUser += (char)((((int)c) + SHIFT) % 222);
                }

                using (StreamWriter sw = File.AppendText("../../../loginBase.data"))
                { 
                    sw.WriteLine(newUser);
                }
                sendResponse("r200");
                logToRecentUser("Successfull registration from "+recentIP);
            }
            else
            {
                sendResponse("r300");
            }


            return true;
        }

        static void readAndSendLogs()
        {
            string text = File.ReadAllText("../../../DATABASE/"+recentMail+".logs");
            sendResponse(text);
        }


        static void logToRecentUser(string what)
        {
            using (StreamWriter sw = File.AppendText("../../../DATABASE/" + recentMail + ".logs"))
            {
                sw.WriteLine("[{0,0}] {1}" ,DateTime.Now,what);
            }
        }
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
                Console.WriteLine("mail Sent with code: "+ mailCode);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        static bool sendCode()
        {
            Random random = new Random();
            int randomCode = random.Next(1000, 9999);
            mailCode = randomCode.ToString();

            sendResponse(pubKeyStr,stopCW:true);
            Console.WriteLine("server->client: <sent server's public RSA key[r110]>; now expecting client to execute r112");
            string mailCypher = readFromClient(size:1024);
            var bytesCypherText = Convert.FromBase64String(mailCypher);
            csp.ImportParameters(privKey);
            
            var bytesPlainTextData = csp.Decrypt(bytesCypherText, false);
            var plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);

            Console.WriteLine("Rec mail:" + plainTextData);
            sendMail(plainTextData);
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
        static string readFromClient(int size=1024,bool decrypt = false, bool stopCW = false)
        {
            
            b = new byte[size];
            stm.Read(b, 0, b.Length);
            if(!stopCW)
                Console.WriteLine("client->server: " + StripControlChars(Convert.ToBase64String(b)));

            if(decrypt)
            {
                csp.ImportParameters(privKey);
                Console.WriteLine("returning:");
                return Encoding.Default.GetString(csp.Decrypt(b, false));
            }
            else
                return StripExtended(StripControlChars(Encoding.Default.GetString(b)));
        } 
        #endregion
        static void Main(string[] args)
        {
            //List<string[]> temp = readAllSiteMailPassword("petar@mail.com");
            //appendPasswordListForUser("petar@mail.com", "facebook", "pm1@aa.com", "pw1");
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
                recentIP = server.Client.RemoteEndPoint.ToString();
                while (server.Connected){
                    if (server.Available == 0)
                        continue;
                    Console.WriteLine("waiting for new request");
                    String requestRaw = readFromClient(4);
                    Console.WriteLine("client->server: (request_EOC) =" + requestRaw +"_EOC");

                    if (String.Equals(requestRaw, "c100"))
                    {
                        if (loginReq()) //sends server PUB key
                        { 
                            sendResponse("c105");
                            logToRecentUser("Successfull login from " + recentIP);
                        }
                        else
                        { 
                            sendResponse("c104");
                            logToRecentUser("Attempted login from " + recentIP);
                        }
                    }
                    else if (String.Equals(requestRaw, "e100"))
                    {
                        stm.Close();
                        server.Close();
                    }
                    else if (String.Equals(requestRaw, "r110"))
                    {
                        sendCode(); //sends server PUB key
                    }
                    else if (String.Equals(requestRaw, "r120"))
                    {
                        HandleRegisterRequest(); // DOESN'T SEND SERVER PUB KEY AS IT IS PART OF r110
                    }
                    else if (String.Equals(requestRaw, "g100"))
                    {
                        getUserData();
                    }
                    else if (String.Equals(requestRaw, "n100"))
                    {
                        newPw();
                    }
                    else if (String.Equals(requestRaw, "l100"))
                    {
                        readAndSendLogs();
                    }
                }
                Console.WriteLine("=======END of communication==========");
                stm.Close();
                server.Close();
            }
        }
    }
}
