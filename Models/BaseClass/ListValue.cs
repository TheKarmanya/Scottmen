namespace BaseClass
{
    public class ListValue
    {
        public string? value { get; set; }
        public string? name { get; set; }
        public string? label { get; set; }
        public string? nameHindi { get; set; }
        public string? type { get; set; }
        public string? extraField1 { get; set; }
    }
    public class ListData
    {
        public string? value { get; set; }
        public string? name { get; set; }
        public string? label { get; set; }        
        public string? type { get; set; }
        public string? actionOrder { get; set; }
    }
    public class BrowserContext
    {
        public string BrowserName { get; set; } = "";
        public string OS { get; set; } = "";
        public string OsFamily { get; set; } = "";
        public bool isMobileDevice { get; set; } = false;
        public bool isBrowserDetected { get; set; } = false;
        public string message { get; set; } = "";
    }
    public class CaptchaReturnType
    {
        public string captchaID { get; set; } = "";
        //public byte[] captchaData { get; set; }
        //public string captchaCode { get; set; } = "";
        public string userEnteredCaptcha { get; set; } = "";
        //public bool isValidProject { get; set; } = false;
        //public string message { get; set; } = "";
    }
}