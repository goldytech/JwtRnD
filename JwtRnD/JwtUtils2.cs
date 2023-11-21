using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;

namespace JwtRnD;

public class JwtUtils2
{
    public static async Task<TokenResponse> RequestTokenAsync(SigningCredentials signingCredentials)
        {
            var client = new HttpClient();

            var disco = await client.GetDiscoveryDocumentAsync("https://demo.duendesoftware.com");
            if (disco.IsError) throw new Exception(disco.Error);

            var clientToken = CreateClientToken(signingCredentials,"m2m.jwt", disco.TokenEndpoint);
            var response = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = disco.TokenEndpoint,

                ClientAssertion =
                {
                    Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                    Value = clientToken
                },
                
                Scope = "api"
            });

            if (response.IsError) throw new Exception(response.Error);
            return response;
        }
        
        private static string CreateClientToken(SigningCredentials credential, string clientId, string audience)
        {
            var now = DateTime.UtcNow;

            var token = new JwtSecurityToken(
                clientId,
                audience,
                new List<Claim>()
                {
                    new Claim(JwtClaimTypes.JwtId, Guid.NewGuid().ToString()),
                    new Claim(JwtClaimTypes.Subject, clientId),
                    new Claim(JwtClaimTypes.IssuedAt, now.ToEpochTime().ToString(), ClaimValueTypes.Integer64)
                },
                now,
                now.AddMinutes(60),
                credential
            );

            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);
        }

        // static async Task CallServiceAsync(string token)
        // {
        //     var client = new HttpClient
        //     {
        //         BaseAddress = new Uri(Urls.SampleApi)
        //     };
        //
        //     client.SetBearerToken(token);
        //     var response = await client.GetStringAsync("identity");
        //
        //     "\n\nService claims:".ConsoleGreen();
        //     Console.WriteLine(response.PrettyPrintJson());
        // }
}