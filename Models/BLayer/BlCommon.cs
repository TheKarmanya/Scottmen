using BaseClass;
using System.Xml.Linq;

namespace ScottmenMainApi.Models.BLayer
{
    public class BlCommon
    {
        public BlCommon()
        {

        }
        private int smsValidity;


        /// <summary>
        /// Validity in Minutes
        /// </summary>
        public int smsvalidity
        {
            get { return this.smsValidity; }
        }
        public class EventLog
        {
            public string logDescription { get; set; } = "";
            public EventLogCategory logCategory { get; set; }
            public EventLogLevel logLevel { get; set; }
            public long sessionId { get; set; }
            public long userId { get; set; }
            public string clientIp { get; set; } = "";
            public string clientOs { get; set; } = "";
            public string clientBrowser { get; set; } = "";
            public string userAgent { get; set; } = "";
        }
        public class ActivitySearch
        {
            public Int16? activityId { get; set; }
            public string activityName { get; set; }
            public Int64? userId { get; set; }
            public string? clientIp { get; set; }
           
        }
        public class BlDocumentNew
        {
            public long documentId { get; set; }
            public Int32 documentNumber { get; set; }
            public int amendmentNo { get; set; }
            public DocumentType documentType { get; set; }
            public string? documentName { get; set; }
            public string? documentExtension { get; set; }
            public string? documentMimeType { get; set; }
            public string? documentTag { get; set; } = "";
            public string? documentDisplayLabel { get; set; } = "";
            public string? clientIp { get; set; }
            public Int16 stateId { get; set; }
            /// <summary>
            /// Refrenced for dpt_table_id 
            /// </summary>
            public DocumentImageGroup documentImageGroup { get; set; }
            public string? userId { get; set; }
            public Int64 fileId { get; set; }
            public string? displayText { get; set; } = "";
            public int currentYear { get; set; }
            public int idTypeCode { get; set; }
            public List<string>? documentInByteS { get; set; }
            public YesNo isDocumentSharedByUser { get; set; } = YesNo.No;
            public Int16? uploaded { get; set; }
            public Int16? deleted { get; set; }
            public long? swsApplicationId { get; set; }
            public int? swsActionId { get; set; }
        }

    }
}
