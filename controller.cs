using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using TokenTest.db;

namespace TokenTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly dbcon _db;

        public AuthController(IConfiguration configuration,dbcon db)
        {
            _configuration = configuration;
            _db = db;

        }

        [HttpGet]
        [Route("get/data")]
        public List<UserRegister> get()
        {        

            var res = _db.userRegisters.ToList();


            return res;

        }

       
      
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserRegister Request)
        {
            User tt = new User();


            CreatePasswordHash(Request.Password, out byte[] PasswordHash, out byte[] PasswordSault);
            tt.UserName = Request.UserName;
            tt.PasswordHash = PasswordHash;
            tt.PasswordSault = PasswordSault; 

            _db.users.Add(tt);  
            _db.SaveChanges();

            return Ok(tt);    
        }

        [HttpPost("login")]
        public async  Task<ActionResult<string>> Login(UserRegister obj)
        {
            

           var res = _db.users.Where(i=>i.UserName == obj.UserName).FirstOrDefault();

            if (res == null)
            {
                return BadRequest("user not found !!");
            }


            if (!VerifyPasswordhash(obj.Password, res.PasswordHash, res.PasswordSault))
            {
                return BadRequest("wrong password");
            }

            string token = CreateToken(res);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));
            var cred = new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims:claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred);
                var jwt = new JwtSecurityTokenHandler().WriteToken(token);        

            return jwt;
        }

        private void CreatePasswordHash(string Password ,out byte[] PasswordHash,out byte[] PasswordSault)
        {
            using(var hmac = new HMACSHA512())
            {
                PasswordSault = hmac.Key;
                PasswordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password));

            }
        }

        private bool VerifyPasswordhash(string password, byte[] PasswordHash ,byte[] PasswordSault)
        {
            using(var hmac = new HMACSHA512(PasswordSault))
            {
                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

                return computeHash.SequenceEqual(PasswordHash); 

            }  

        }
    }
}
