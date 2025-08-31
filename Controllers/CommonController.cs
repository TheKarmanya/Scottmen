using BaseClass;
using Microsoft.AspNetCore.Mvc;
using ScottmenMainApi.Models.DLayer;
using System.Net;
using static ScottmenMainApi.Models.BLayer.BlCommon;

namespace ScottmenMainApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CommonController : ControllerBase
    {
        readonly DlCommon dl = new();
        [HttpGet("state/{language?}")]
        public async Task<List<ListValue>> State(LanguageSupported language = LanguageSupported.English)
        {
            List<ListValue> lv = await dl.GetStateAsync(language);
            return lv;
        }
        /// <summary>
        /// Get List of District based on State value, Default Language is Set to English (value 2)
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="language"></param>
        /// <returns></returns>
        [HttpGet("district/{sid}/{language?}")]
        public async Task<List<ListValue>> District(int sid = (int)StateId.DefaultState, LanguageSupported language = LanguageSupported.English)
        {
            List<ListValue> lv = await dl.GetDistrictAsync(sid, language: language);
            return lv;
        }
        /// <summary>
        /// Get List of Base Departments of a State, Default Language is Set to English (value 2)
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="language"></param>
        /// <returns></returns>
        [HttpGet("basedepartment/{sid}/{language?}")]
        public async Task<List<ListValue>> BaseDepartment(int sid = (int)StateId.DefaultState, LanguageSupported language = LanguageSupported.English)
        {
            List<ListValue> lv = await dl.GetBaseDepartmentAsync(sid, language: language);
            return lv;
        }
        /// <summary>
        /// Get Common List based on Category
        /// </summary>
        /// <param name="category"></param>
        /// <param name="language">Hindi = 1, English = 2</param>
        /// <returns></returns>
        [HttpGet("CommonList/{category}/{language?}")]
        public async Task<List<ListValue>> GetCommonListPublicAsync(string category, LanguageSupported language = LanguageSupported.English)
        {
            List<ListValue> lv = await dl.GetCommonListAsync(category: category, language: language);
            return lv;
        }
        /// <summary>
        /// Get Common List based on Category
        /// </summary>
        /// <param name="category"></param>
        /// <param name="id"></param>
        /// <param name="language"></param>
        /// <returns></returns>
        [HttpGet("sublist/{category}/{id}/{language?}")]
        public async Task<List<ListValue>> GetSubCommonListPublicAsync(string category, string id, LanguageSupported language = LanguageSupported.English)
        {
            List<ListValue> lv = await dl.GetSubCommonListAsync(category: category, id: id, language: language);
            return lv;
        }

        /// <summary>
        /// Get Project List 
        /// </summary>
        /// <param name="language"></param>
        /// <returns></returns>
        [HttpGet("projectlist/{language?}")]
        public async Task<List<ListValue>> GetSubCommonListPublicAsync(LanguageSupported language = LanguageSupported.English)
        {
            List<ListValue> lv = await dl.GetProjecttList(language: language);
            return lv;
        }
        /// <summary>
        /// Get Activity List 
        /// </summary>
        /// <param name="language"></param>
        /// <returns></returns>
        [HttpPost("activitylist")]
        public async Task<List<ListData>> GetActivityListAsync(ActivitySearch activitySearch)
        {
            return await dl.GetActivityList(activitySearch);
        }

        /// <summary>
        /// Get Source of Energy List 
        /// </summary>
        /// <param name="language"></param>
        /// <returns></returns>
        [HttpGet("sourceofenergy/{language?}")]
        public async Task<List<ListValue>> GetSourceOfEnergy(LanguageSupported language = LanguageSupported.English)
        {
            List<ListValue> lv = await dl.GetSourceOfEnergy(language: language);
            return lv;
        }
        /// <summary>
        /// Get HSN/SAC List
        /// </summary>
        /// <param name="language"></param>
        /// <returns></returns>
        [HttpPost("hsnsaclist")]
        public async Task<List<ListValue>> GetHSNSACListAsync(ActivitySearch activitySearch)
        {
            return await dl.GetHSNList(activitySearch);
        }
        /// <summary>
        /// Get List of ULB based on District value, Default Language is Set to English (value 2)
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="language"></param>
        /// <returns></returns>
        [HttpGet("ulb/{did}/{language?}")]
        public async Task<List<ListValue>> ULBlist(int did, LanguageSupported language = LanguageSupported.English)
        {
            List<ListValue> lv = await dl.GetULBAsync(did, language: language);
            return lv;
        }
        /// <summary>
        /// Get List of Tehsil based on District value, Default Language is Set to English (value 2)
        /// </summary>
        /// <param name="did"></param>
        /// <param name="language"></param>
        /// <returns></returns>
        [HttpGet("tehsil/{did}/{language?}")]
        public async Task<List<ListValue>> Tehsil(int did, LanguageSupported language = LanguageSupported.English)
        {
            List<ListValue> lv = await dl.GetTehsilAsync(did, language: language);
            return lv;
        }
        /// <summary>
        /// Get List of Village based on District and Tehsil value, Default Language is Set to English (value 2)
        /// </summary>
        /// <param name="did"></param>
        /// <param name="tid"></param>
        /// <param name="language"></param>
        /// <returns></returns>
        [HttpGet("village/{did}/{tid}/{language?}")]
        public async Task<List<ListValue>> Village(int did, int tid, LanguageSupported language = LanguageSupported.English)
        {
            List<ListValue> lv = await dl.GetVillageAsync(did, tid, language: language);
            return lv;
        }
        /// <summary>
        /// Get Common List based on Category With Extra Information
        /// </summary>
        /// <param name="category"></param>
        /// <param name="language">Hindi = 1, English = 2</param>
        /// <returns></returns>
        [HttpGet("Commondata/{category}/{language?}")]
        public async Task<List<ListData>> GetCommonPublicAsync(string category, LanguageSupported language = LanguageSupported.English)
        {
            List<ListData> lv = await dl.GetCommonDataAsync(category: category, language: language);
            return lv;
        }
       
        [HttpGet("myip")]
        public ReturnClass.ReturnString GetMyIP()
        {
            ReturnClass.ReturnString rs = new();
            rs.message = Utilities.GetRemoteIPAddress(this.HttpContext, true);

            string addr = this.HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (addr != null)
            {
                string[] parts = addr.Split(':');
                if (parts.Length != 2)
                {
                    //return ip
                }
                else if (IPAddress.TryParse(parts[0], out IPAddress ip))
                {
                    rs.secondryId = ip.ToString(); ;
                }

            }
            //rs.value = "Context - " + this.HttpContext.Request.Headers[];
            foreach (var header in this.HttpContext.Request.Headers)
            {
                string headerValue = "";
                foreach (var val in header.Value)
                    headerValue += (val.ToString() ?? "") + ", ";
                rs.value += "Key: " + header.Key + ", Value : " + headerValue;
                //string headerName = header.Key;
                //string headerContent = string.Join(",", header.Value.ToArray());
                // Do something with headerName and headerContent
            }
            return rs;
        }

        /// <summary>
        /// </summary>
        /// <param name="category"></param>
        /// <param name="language">Hindi = 1, English = 2</param>
        /// <returns></returns>
        [HttpGet("CommonListIndustry/{category}")]
        public async Task<List<ListValue>> GetCommonListIndustryAsync(string category)
        {
            List<ListValue> lv = await dl.GetCommonListIndustryAsync(category: category);
            return lv;
        }

        [HttpGet("CommonListProdIndustry/{category}")]
        public async Task<List<ListValue>> GetCommonListIndustryProdAsync(string category)
        {
            List<ListValue> lv = await dl.GetCommonListIndustryProdAsync(category: category);
            return lv;
        }
        [HttpGet("DistrictProdIndustry/{userId?}")]
        public async Task<List<ListValue>> GetDistrict(Int64 userId = 0)
        {
            List<ListValue> lv = await dl.GetDistrict(userId);
            return lv;
        }
        /// <summary>
        /// Get Common List based on Category
        /// </summary>
        /// <param name="category"></param>
        /// <param name="language">Hindi = 1, English = 2</param>
        /// <returns></returns>
        [HttpGet("Commongraphs/{category}/{language?}")]
        public async Task<List<ListData>> GetCommonGraphsPublicAsync(string category, LanguageSupported language = LanguageSupported.English)
        {
            List<ListData> lv = await dl.GetCommonListChartAsync(category: category, language: language);
            return lv;
        }


    }
}
