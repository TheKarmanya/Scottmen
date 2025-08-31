using BaseClass;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ScottmenMainApi.Models.BLayer;
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
        [HttpPost("calculatedensity")]
        //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ReturnClass.ReturnBool> CalculateDensity(SpiritDensity spiritDensity)
        {

            return await dl.CalculateDensity(spiritDensity);
        }
    }
}
