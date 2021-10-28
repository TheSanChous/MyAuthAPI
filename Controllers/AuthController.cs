using Common;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MyAuthAPI.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace MyAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public readonly AuthOptions authOptions;
        public readonly IConfiguration configuration; 
        public List<User> users => new List<User>
        { 
            new User
            {
                Id = 1,
                Email = "user@mail.com",
                Password = "user",
                Roles = new Role[] { Role.User }
            },
            new User
            {
                Id = 2,
                Email = "admin@mail.com",
                Password = "admin",
                Roles = new Role[] { Role.Admin }
            },
        };

        public AuthController(IConfiguration configuration, AuthOptions authOptions)
        {
            this.authOptions = authOptions;
            this.configuration = configuration;
        }

        [Route("login")]
        [HttpPost]
        public IActionResult Login([FromBody] Login login)
        {
            var user = AuthenticateUser(login.Email, login.Password);

            if (user == null)
            {
                return Unauthorized();
            }

            var token = GenerateJWT(user);

            return Ok( new
            {
                access_token = token
            });

        }

        private User AuthenticateUser(string email, string password)
        {
            return users.SingleOrDefault(u => u.Email == email && u.Password == password);
        }

        private string GenerateJWT(User user)
        {
            var authParams = authOptions;

            var securityKey = AuthOptions.GetSymmetricSecurityKey(configuration.GetValue<string>("Auth:Secret"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.AuthTime, authOptions.TokenLifetime.ToString()),
            };

            foreach(var role in user.Roles)
            {
                claims.Add(new Claim("role", role.ToString()));
            }

            var token = new JwtSecurityToken (
                authParams.Issuer,
                authParams.Audience,
                claims,
                expires: DateTime.Now.AddSeconds(authParams.TokenLifetime),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
