using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using CERTENROLLLib;

namespace ADCSWebApi2
{
    

    public partial class _default : System.Web.UI.Page
    {
        private const string EventLogName = "Application";
        

        private static bool CheckSourceExists(string source)
        {
            if (EventLog.SourceExists(source))
            {
                EventLog evLog = new EventLog { Source = source };
                if (evLog.Log != EventLogName)
                {
                    EventLog.DeleteEventSource(source);
                }
            }

            if (!EventLog.SourceExists(source))
            {
                EventLog.CreateEventSource(source, EventLogName);
                EventLog.WriteEntry(source, String.Format("Event Log Created '{0}'/'{1}'", EventLogName, source), EventLogEntryType.Information);
            }

            return EventLog.SourceExists(source);
        }

        private void WriteEventLog(string source, int EventID, string EventMessage, EventLogEntryType type)
        {
            if (CheckSourceExists(source))
            {
                EventLog.WriteEntry(source, EventMessage, type, EventID);
            }
        }

        private void PersistInitialCSR(string reqid)
        {
            if (ConfigurationManager.AppSettings["VerboseLogging"] == "True")
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1004, "In NewCertificateFromRequest", EventLogEntryType.Information);

            string certreq = new StreamReader(Context.Request.InputStream).ReadToEnd();

            if (ConfigurationManager.AppSettings["VerboseLogging"] == "True")
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1005, "Certificate request:" + certreq, EventLogEntryType.Information);

            Console.WriteLine(certreq);

            // build name for cert req file

            string baseName = ConfigurationManager.AppSettings["Scratch"] + reqid;

            if (ConfigurationManager.AppSettings["VerboseLogging"] == "True")
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1006, "Writing Certificate request to file:" + baseName, EventLogEntryType.Information);




            using (System.IO.StreamWriter file = new StreamWriter(baseName + ".req"))
            {
                file.WriteLine(certreq);
            }
        }
        private void GenerateDNSInfFile(string reqid)
        {
            string dNSName = Context.Request.Headers["DNSName"];

            using (System.IO.StreamWriter file = new StreamWriter(ConfigurationManager.AppSettings["Scratch"] + reqid + ".inf"))
            {
                file.WriteLine("[Extensions]");
                if (ConfigurationManager.AppSettings["DNSName"] == "True" && (dNSName != null && dNSName != ""))
                {
                    file.WriteLine("2.5.29.17 = \"{ text}\"");
                    file.WriteLine("_continue_ = \"DNS=" + dNSName + "\"");
                }
            }
        }

        private int ExecuteCertReq(string args)
        {
            // request the certificate
            ProcessStartInfo start = new ProcessStartInfo();            

            if (ConfigurationManager.AppSettings["VerboseLogging"] == "True")
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1017, "ResignRequestWithSAN: Command line args:" + args, EventLogEntryType.Information);


            start.Arguments = args;
            start.FileName = ConfigurationManager.AppSettings["CertReq"];

            if (ConfigurationManager.AppSettings["VerboseLogging"] == "True")
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1018, "ResignRequestWithSAN: Command:" + start.FileName, EventLogEntryType.Information);

            start.WindowStyle = ProcessWindowStyle.Hidden;
            start.CreateNoWindow = true;           

            // Run the external process & wait for it to finish
            using (Process proc = Process.Start(start))
            {
                proc.WaitForExit();

                // Retrieve the app's exit code
                return proc.ExitCode;
            }
        }

        private void ResignRequestWithSAN(string reqid)
        {
            string baseName = ConfigurationManager.AppSettings["Scratch"] + reqid;

            // request the certificate
            ProcessStartInfo start = new ProcessStartInfo();

            // arguments
            string args = "-policy -q -f";
            args += " -cert " + ConfigurationManager.AppSettings["CertID"];
            args += " -config \"" + ConfigurationManager.AppSettings["CAConfig"] + "\"";
            args += " " + baseName + ".req";
            args += " " + baseName + ".inf";
            args += " " + baseName + "-ea.req";

            if (ConfigurationManager.AppSettings["VerboseLogging"] == "True")
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1017, "ResignRequestWithSAN: Command line args:" + args, EventLogEntryType.Information);

            int exitCode = ExecuteCertReq(args);
            
            if (ConfigurationManager.AppSettings["VerboseLogging"] == "True")
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1019, "ResignRequestWithSAN: exit code:" + exitCode, EventLogEntryType.Information);
           

        }

        private void ResignRequest(string reqid)
        {            
            GenerateDNSInfFile(reqid);            
            PersistInitialCSR(reqid);
            ResignRequestWithSAN(reqid);
           
        }

        private void SubmitRequestToCA(string reqid)
        {
            string baseName = ConfigurationManager.AppSettings["Scratch"] + reqid;           
            
            // arguments
            string args = "-Submit -q -f";
            args += " -attrib \"CertificateTemplate:" + ConfigurationManager.AppSettings["Template"] + "\"";
            args += " -config \"" + ConfigurationManager.AppSettings["CAConfig"] + "\"";
            args += " " + baseName + ".req";
            args += " " + baseName + ".cer";

            if (ConfigurationManager.AppSettings["VerboseLogging"] == "True")
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1007, "Command line args:" + args, EventLogEntryType.Information);

            int exitCode = ExecuteCertReq(args);

            if (ConfigurationManager.AppSettings["VerboseLogging"] == "True")
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1009, "exit code:" + exitCode, EventLogEntryType.Information);


        }

        private string GetIssuedCertificateAndCleanScreatchArea(string reqid)
        {
            string baseName = ConfigurationManager.AppSettings["Scratch"] + reqid;
            //we should now have a certificate in the scratch area           
            if (File.Exists(baseName + ".cer"))
            {
                // cert is present, return it
                string cert = File.ReadAllText(baseName + ".cer");

                // delete the files
                string[] certfiles = Directory.GetFiles(ConfigurationManager.AppSettings["Scratch"], reqid + ".*");
                foreach (string f in certfiles)
                {
                    File.Delete(f);
                }


                return cert;
            }
            else
            {
                // something wrong happended and no cert is present
                return "";
            }
        }

        private string NewCertificateFromRequest(string reqid)
        {            
            ResignRequest(reqid);
            SubmitRequestToCA(reqid);
            return GetIssuedCertificateAndCleanScreatchArea(reqid);                        
        }

        private string GetSubjectDNFromRequest()
        {
            CX509CertificateRequestPkcs10 req = new CX509CertificateRequestPkcs10();
            string csr = new StreamReader(Context.Request.InputStream).ReadToEnd();
            req.InitializeDecode(csr, EncodingType.XCN_CRYPT_STRING_BASE64_ANY);
            req.CheckSignature();

            return ((CX500DistinguishedName)req.Subject).Name;
        }

        private Stream ProcessRequest(Stream body)
        {
            if (ConfigurationManager.AppSettings["VerboseLogging"] == "True")
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1003, "In ProcessComputerRequest", EventLogEntryType.Information);

            string requestType = Context.Request.Headers["REQUEST_TYPE"];
            if (requestType == "" || requestType == null)
            {
                //EventLogHandler.LogEvent(3007, string.Format(ServerMessages.Error_WebApi_InvalidRequestType, requestType),
                //                         LoggingCategories.General, TraceEventType.Error);
                return ReturnWebResult("Missing REQUEST_TYPE", HttpStatusCode.BadRequest);
            }            

            string subjectDN = Context.Request.Headers["SUBJECT_DN"];

            if (subjectDN == null || subjectDN == "")
                subjectDN = GetSubjectDNFromRequest();
            
            switch (requestType)
            {
                case "CREATE":
                case "RENEW":
                    try
                    {
                        // base name for files related to request
                        Guid g = Guid.NewGuid();
                        string reqid = g.ToString();

                        
                        string cert = this.NewCertificateFromRequest(reqid);
                        if (cert != "")
                        {
                            WriteEventLog( ConfigurationManager.AppSettings["EventSource"], 3008, "Certificate issued to: '" + subjectDN + "'", EventLogEntryType.Information);
                            return ReturnWebResult(cert, HttpStatusCode.OK);
                        }
                        else
                        {
                            WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 3009, "Failed issuing certificate to: '" + subjectDN + "'", EventLogEntryType.Error);                            
                            return ReturnWebResult("Failure creating certificate", HttpStatusCode.InternalServerError);
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 3009, "Failed issuing certificate to: '" + subjectDN + "'", EventLogEntryType.Error);
                        return ReturnWebResult(ex.Message, HttpStatusCode.InternalServerError);
                    }

                //case "REVOKE":  // revoke is handled by ProcessADSSRequest
                //    {
                //        return ReturnWebResult("Revoked", HttpStatusCode.OK);
                //    }

                default:
                    {
                        WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 3009, "Invalid request type: '" + requestType + "'", EventLogEntryType.Error);                        
                        return ReturnWebResult("Invalid REQUEST_TYPE", HttpStatusCode.BadRequest);
                    }


            }
        }

        private Stream ProcessRevokeRequest()
        {
            return ReturnWebResult("Revoked", HttpStatusCode.OK);
        }

        private Stream ReturnWebResult(string result, HttpStatusCode status)
        {
            Context.Response.ContentType = "text/plain; charset=utf-8";
            Context.Response.StatusCode = (int)status;            
            byte[] bytes = Encoding.UTF8.GetBytes(result);
            return (Stream)new MemoryStream(bytes);
        }
        protected Stream ProcessCertificateRequest(Stream body)
        {
            string certificatePurpose = Context.Request.Headers["CERTIFICATE_PURPOSE"];
            string requestType = Context.Request.Headers["REQUEST_TYPE"];

            if (ConfigurationManager.AppSettings["VerboseLogging"] == "True")
            {
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1001, "Certificate purpose " + certificatePurpose, EventLogEntryType.Information);
                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 1002, "Request type " + requestType, EventLogEntryType.Information);
            }


            switch (requestType)
            {
                case "CREATE":
                case "RENEW":
                    if (certificatePurpose == "" || certificatePurpose == null)
                    {
                        //EventLogHandler.LogEvent(3004, string.Format(ServerMessages.Error_WebApi_InvalidCertificatePurpose, certificatePurpose),
                        // LoggingCategories.General, TraceEventType.Error);
                        WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 3004, "Invalid certificate purpose", EventLogEntryType.Error);
                        return ReturnWebResult("Invalid CERTIFICATE_PURPOSE", HttpStatusCode.BadRequest);

                    }

                    switch (certificatePurpose)
                    {                        
                        case "COMPUTER":
                            return this.ProcessRequest(body);

                        default:
                            {
                                WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 3004, "Invalid certificate purpose: '" + certificatePurpose + "'", EventLogEntryType.Error);                               
                                return ReturnWebResult("Invalid CERTIFICATE_PURPOSE", HttpStatusCode.BadRequest);

                            }
                    }

                case "REVOKE":
                    // convert the serialnumber to hex value
                    return ProcessRevokeRequest();

                default:
                    {
                        WriteEventLog(ConfigurationManager.AppSettings["EventSource"], 3004, "Invalid certificate purpose: '" + certificatePurpose + "'", EventLogEntryType.Error);
                        return ReturnWebResult("Invalid REQUEST_TYPE", HttpStatusCode.BadRequest);
                    }

            }            
        }
        protected void Page_Load(object sender, EventArgs e)
        {
            

            //string body = Context.Request;

            switch (Context.Request.HttpMethod)
            {
                case "GET":

                    break;

                case "POST":

                    ProcessCertificateRequest(Context.Request.InputStream).CopyTo(Context.Response.OutputStream);
                    break;

                default:
                    break;
            }
            

        }
    }
}