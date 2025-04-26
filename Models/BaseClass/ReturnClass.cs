using System.Data;

namespace BaseClass
{
    /// <summary>
    /// Summary description for ReturnClass
    /// </summary>
    public class ReturnClass
    {
        public class ReturnDataTable
        {
            public string type { get; set; }
            public bool status { get; set; }
            public string json { get; set; }
            public string message { get; set; }
            public DataTable table { get; set; }
            public string file_name { get; set; }
            public string value { get; set; }
            public ReturnDataTable()
            {
                status = false;
                message = "";
                file_name = "";
                json = "[]";
                table = new DataTable();
                value = "";
                type = "";
            }
        }

        public class ReturnDataSet
        {
            public bool status { get; set; }
            public string message { get; set; }
            public DataSet dataset { get; set; }
            public string file_name { get; set; }
            public string json { get; set; }
            public string value { get; set; }
            public ReturnDataSet()
            {
                status = false;
                message = "";
                file_name = "";
                json = "[]";
                dataset = new DataSet();
                value = "";
            }
        }
        public class ReturnBool
        {
            public bool status { get; set; }
            public string message { get; set; }
            public string message1 { get; set; }
            public string error { get; set; }
            public string? value { get; set; }
            public ReturnBool()
            {
                status = false;
                message = "";
                message1 = "";
                error = "";
            }
        }
        public class ReturnString
        {
            public bool status { get; set; }
            public string message { get; set; }
            public string value { get; set; }
            public string msgId { get; set; }
            public long id { get; set; }
            public string secondryId { get; set; } // you can pass any user_id or office_id as you want
            public ReturnString()
            {
                status = false;
                message = "";
                value = "";
                msgId = "";
                secondryId = "";
            }
        }
        public class ReturnReportName
        {
            public bool status { get; set; }
            public string message { get; set; }
            public string file_name { get; set; }
            public ReturnReportName()
            {
                status = false;
                message = "";
                file_name = "";
            }
        }
        public class ReturnKeyPair
        {
            public string Key { get; set; } = "";
            public string Value { get; set; } = "";
        }
        public class data
        {
            public string reqid { get; set; } = "";            
        }

            public class SandeshResponse
            {
                public string status { get; set; }
                public string notice { get; set; }
                public string code { get; set; }
                public string message { get; set; }            
                public data data { get; set; }
            
            }
    }
}