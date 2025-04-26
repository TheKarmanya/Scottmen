using BaseClass;

namespace ScottmenMainApi.Models.BLayer
{
    public class BlDocument
    {
        public List<IFormFile>? files { get; set; }
        public Int64? documentId { get; set; }
        public Int32? documentNumber { get; set; }
        public Int16? amendmentNo { get; set; } = 0;
        public DocumentType documentType { get; set; }
        public string? documentName { get; set; } = "";
        public string? documentExtension { get; set; } = "";
        public string? documentMimeType { get; set; } = "";
        /// <summary>
        /// Comma seperated document tag
        /// </summary>
        public string? documentTag { get; set; } = "";
        public string? documentDisplayLabel { get; set; } = "";
        public string? clientIp { get; set; } = "";
        public int? stateId { get; set; } = 0;
        /// <summary>
        /// Refrenced for dpt_table_id 
        /// </summary>
        public DocumentImageGroup documentImageGroup { get; set; }
        public string? userId { get; set; } = "";
        public Int64 fileId { get; set; }=0;
        public string? displayText { get; set; } = "";
        public int? currentYear { get; set; } = 0;
        public int? idTypeCode { get; set; }
        public List<DocumentBody>? documentList { get; set; }
        public byte[]? documentInByte { get; set; }
        public YesNo isDocumentShared { get; set; } = YesNo.No;
        public long? swsApplicationId { get; set; }
        public int? swsActionId { get; set; }
        public Int16? uploaded { get; set; }

    }
    public class BlDocumentDoc
    {
        public Int64? documentId { get; set; } = 0;
        public DocumentType documentType { get; set; }
        public string? documentExtension { get; set; } = "";
        public string? documentMimeType { get; set; } = "";
        public string? documentTag { get; set; } = "";
        public int? stateId { get; set; } = 22;
        public DocumentImageGroup documentImageGroup { get; set; }
        public YesNo isDocumentShared { get; set; } = YesNo.No;
        public long? swsApplicationId { get; set; }
        public int? swsActionId { get; set; }
        public string? userId { get; set; } = "";
        public Int16? uploaded { get; set; }
        public List<DocumentBody>? documentList { get; set; }
        public byte[]? documentInByte { get; set; }
        public string? documentName { get; set; } = "";

    }
    public class DocumentBody
    {
        public byte[]? documentInByte { get; set; }
        public string? documentLabel { get; set; } = "";
    }

    public class BlUploadLogo
    {        
        //public Int64? swsProjectId { get; set; }
        public Int64? documentId { get; set; }
        public Int32? documentNumber { get; set; } = 0;
        public Int16? amendmentNo { get; set; } = 0;
        public DocumentType documentType { get; set; }
        public string? documentName { get; set; } = "";
        public string? documentExtension { get; set; } = "";
        public string? documentMimeType { get; set; } = "";       
        public string? clientIp { get; set; } = "";       
        public long? userId { get; set; } 
        public List<DocumentBody>? documentList { get; set; }
        public byte[]? documentInByte { get; set; }
        public Int16? status { get; set; }
        public Int16? isActive { get; set; }
        public int? dptTableId { get; set; } = 0;

        public Int32 actionId { get; set; }
        public Int32 chargeMappingKey { get; set; }
        public Int32 actionOrder { get; set; }
        public long? userIdOfVerificationOfficer { get; set; }
        public DateTime? VerifyDate { get; set; }
        public long? receivedOfficeMappingId { get; set; }
        public long? officeMappingId { get; set; }
        public Int16 stateId { get; set; } = 22;
        public DocumentImageGroup documentImageGroup { get; set; }

    }

}
