namespace BaseClass
{
    public class WriteLog
    {
        public WriteLog()
        {
            //
            // TODO: Add constructor logic here
            //
        }

        /// <summary>
        /// Writes error log on log.txt with method name
        /// </summary>
        /// <param name="sMethod_Name">Methodname in which error occurs</param>
        /// <param name="e">Exception</param>
        public static void Error(string sMethod_Name, Exception e)
        {
            string sFile = AppDomain.CurrentDomain.BaseDirectory + "log.txt";
            try
            {
                using (StreamWriter w = File.AppendText(sFile))
                {
                    w.Write("{0}-{1}->", DateTime.Now.ToShortDateString(),
                    DateTime.Now.ToLongTimeString());
                    if (sMethod_Name != null)
                        w.Write(sMethod_Name + "-");
                    if (e != null)
                        w.Write(e.Message);
                    w.WriteLine();
                    w.Flush();
                    w.Close();
                }
            }
            catch
            {
                throw;
            }
        }
        /// <summary>
        /// Write error msessage without method
        /// </summary>
        /// <param name="error"></param>
        public static void Error(string error)
        {
            string sFile = AppDomain.CurrentDomain.BaseDirectory + "log.txt";
            try
            {
                using (StreamWriter w = File.AppendText(sFile))
                {
                    w.Write("{0}-{1}->", DateTime.Now.ToShortDateString(),
                    DateTime.Now.ToLongTimeString());
                    if (error != null)
                        w.Write(error);
                    w.WriteLine();
                    w.Flush();
                    w.Close();
                }
            }
            catch
            {
                throw;
            }
        }
        /// <summary>
        /// Writes custom logs on user specified txt file name
        /// </summary>
        /// <param name="message"></param>
        /// <param name="fileName"></param>
        public static void CustomLog(string message, string fileName)
        {
            string sFile = AppDomain.CurrentDomain.BaseDirectory + fileName + ".txt";
            try
            {
                using (StreamWriter w = File.AppendText(sFile))
                {
                    w.Write("{0}-{1}->", DateTime.Now.ToShortDateString(),
                    DateTime.Now.ToLongTimeString());
                    if (message != null)
                        w.Write(message);
                    w.WriteLine();
                    w.Flush();
                    w.Close();
                }
            }
            catch
            {
                throw;
            }
        }
    }
}