using BaseClass;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ScottmenMainApi.Models.DLayer;
using System.Net;
using System.Security.Claims;
namespace ScottmenMainApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    
    public class HomeController : Controller
    {
        readonly DlCommon dl = new();
        [HttpGet("state/{language?}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<List<ListValue>> State(LanguageSupported language = LanguageSupported.English)
        {
            long userId = Convert.ToInt64(User.FindFirst("userId")?.Value);
            int roleId = Convert.ToInt16(User.FindFirstValue(ClaimTypes.Role));
            string clientIp = Utilities.GetRemoteIPAddress(this.HttpContext, true);
            List<ListValue> lv = await dl.GetStateAsync(language);
            return lv;
        }
    }
}
