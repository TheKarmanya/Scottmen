using ScottmenMainApi.Models.BLayer;
using ScottmenMainApi.Models.DLayer;
using System.ComponentModel;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Text.Json;

namespace BaseClass
{
    public class Email
    {
        private string _senderEmail;
        private string _password;
        private string _hostUrl;
        private int _port;
        private bool mailSent = false;
        private string error = "";
        readonly string emailSenderUrl;
        public Email()
        {
            try
            {
                this._senderEmail = Utilities.GetAppSettings("EmailConfiguration", "SenderEmail").message;
                this._password = Utilities.GetAppSettings("EmailConfiguration", "Password").message;
                this._hostUrl = Utilities.GetAppSettings("EmailConfiguration", "HostUrl").message;
                this._port = Convert.ToInt32(Utilities.GetAppSettings("EmailConfiguration", "Port").message);
                this.emailSenderUrl = Utilities.GetAppSettings("EmailConfiguration", "senderURL").message;
            }
            catch { throw; }
        }
        public async Task<ReturnClass.ReturnBool> SendAsync(string ToAddres, string emailSubject, string emailBody, List<Attachment> Attachments)
        {
            ReturnClass.ReturnBool rb = new();
            MailMessage message = new();
            SmtpClient smtp = new();
            try
            {
                ServicePointManager.ServerCertificateValidationCallback += (s, ce, ca, p) => true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                message.From = new MailAddress(_senderEmail);
                message.To.Add(new MailAddress(ToAddres));
                message.Subject = emailSubject;
                message.IsBodyHtml = true; //to make message body as html  
                message.Body = emailBody;
                smtp.Port = _port;
                smtp.Host = _hostUrl;
                smtp.UseDefaultCredentials = false;
                smtp.EnableSsl = true;
                smtp.DeliveryMethod = SmtpDeliveryMethod.Network;
                smtp.Credentials = new NetworkCredential(_senderEmail, _password);

                #region Attachments
                try
                {
                    if (Attachments is not null && Attachments.Count > 0)
                    {
                        foreach (Attachment attachment in Attachments)
                            message.Attachments.Add(attachment);
                    }
                }
                catch { }
                #endregion

                await smtp.SendMailAsync(message);
                smtp.SendCompleted += new SendCompletedEventHandler(SendCompletedCallback);
                if (error != "")
                {
                    rb.status = false;
                    WriteLog.Error("EmailSentError - " + error);
                }
                else
                {
                    rb.status = true;
                    rb.message = "Email Sent Successfully";
                }
            }
            catch (Exception ex)
            {
                rb.message = "Failed to send email";
                WriteLog.Error("email(error)", ex);
            }
            finally
            {
                smtp.Dispose();
                message.Dispose();
            }
            return rb;
        }
        public async Task<ReturnClass.ReturnBool> SendAsync(string ToAddres, string emailSubject, string emailBody, List<Attachment> Attachments, string ccAddress)
        {
            ReturnClass.ReturnBool rb = new();
            try
            {
                MailMessage message = new();
                SmtpClient smtp = new();
                message.From = new MailAddress(_senderEmail);
                message.To.Add(new MailAddress(ToAddres));
                message.CC.Add(new MailAddress(ccAddress));
                message.Subject = emailSubject;
                message.IsBodyHtml = true; //to make message body as html  
                message.Body = emailBody;
                smtp.Port = _port;
                smtp.Host = _hostUrl;
                smtp.UseDefaultCredentials = false;
                smtp.EnableSsl = false;
                smtp.EnableSsl = true;
                smtp.DeliveryMethod = SmtpDeliveryMethod.Network;
                smtp.Credentials = new NetworkCredential(_senderEmail, _password);

                #region Attachments
                try
                {
                    if (Attachments is not null && Attachments.Count > 0)
                    {
                        foreach (Attachment attachment in Attachments)
                            message.Attachments.Add(attachment);
                    }
                }
                catch { }
                #endregion

                await smtp.SendMailAsync(message);
                smtp.SendCompleted += new SendCompletedEventHandler(SendCompletedCallback);
                if (error != "")
                {
                    rb.status = false;
                    WriteLog.Error("EmailSentError - " + error);
                }
                else
                {
                    rb.status = true;
                    rb.message = "Email Sent Successfully";
                }
            }
            catch (Exception ex)
            {
                rb.message = "Failed to send email";
                WriteLog.Error("email(error)", ex);
            }
            return rb;
        }


        public async Task<ReturnClass.ReturnBool> SendEmailViaURLAsync(emailSenderClass emailsend)
        {
            ReturnClass.ReturnBool rb = new();
            try
            {
                Uri url = new Uri(emailSenderUrl);
                HttpClient client = new();
                client.BaseAddress = url;
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));   //ACCEPT header         
                HttpResponseMessage response = await client.PostAsJsonAsync(url, emailsend);
                response.EnsureSuccessStatusCode(); // throws if not 200-299
                var contentStream = await response.Content.ReadAsStreamAsync();
                rb = await JsonSerializer.DeserializeAsync<ReturnClass.ReturnBool>(contentStream);
            }
            catch (Exception ex)
            {
                rb.message = "Failed to send email";
                WriteLog.Error("email(error)", ex);
            }


            return rb;
        }
        //senderURL


        private void SendCompletedCallback(object sender, AsyncCompletedEventArgs e)
        {
            string? token = e.UserState as string;

            //if (e.Cancelled)
            //{
            //    Console.WriteLine("[{0}] Send canceled.", token);
            //}
            if (e.Error != null)
            {
                //Console.WriteLine("[{0}] {1}", token, e.Error.ToString());
                error = token + " " + e.Error.Message;
            }
            //else
            //{
            //    Console.WriteLine("Message sent.");
            //}
            mailSent = true;
        }
    }
}