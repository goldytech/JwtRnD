using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using JsonWebAlgorithmsKeyTypes = IdentityModel.Jwk.JsonWebAlgorithmsKeyTypes;
using JsonWebKey = IdentityModel.Jwk.JsonWebKey;

namespace JwtRnD;

public class JwtUtils
{
    public bool IsJwtValid(string jwt)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(jwt);
        return token.ValidTo > DateTime.UtcNow;
    }
    
    public JwtSecurityToken DecodeJwt(string jwt)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(jwt);
        return token;
    }

    public async Task<string?> GetAccessTokenFromDuendeIdentityServer()
    {
        var client = new HttpClient();
        var disco = await client.GetDiscoveryDocumentAsync("https://demo.duendesoftware.com");
        if (disco.IsError)
        {
            Console.WriteLine(disco.Error);
            return string.Empty;
        }

        var tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            ClientId = "m2m",
            ClientSecret = "secret",
            Scope = "api"
        });

        if (tokenResponse.IsError)
        {
            Console.WriteLine(tokenResponse.Error);
            return string.Empty;
        }

        Console.WriteLine(tokenResponse.Json);
        return tokenResponse.AccessToken;

    }
    
    public RsaSecurityKey GenerateRsaSecurityKey()
    {
        using var rsa = RSA.Create();
        rsa.KeySize = 2048;
        var rsaParameters = rsa.ExportParameters(true);
        var key = new RsaSecurityKey(rsaParameters) {KeyId = Guid.NewGuid().ToString()};
        return key;
    }
    
    public Tuple<string, JsonWebKey> GetJsonWebKey(RsaSecurityKey rsaSecurityKey)
    {
        var jsonWebKey = new JsonWebKey
        {
            Kty = JsonWebAlgorithmsKeyTypes.RSA,
            Use = "sig",
            Kid = rsaSecurityKey.KeyId,
            E = Base64UrlEncoder.Encode(rsaSecurityKey.Rsa?.ExportParameters(false).Exponent),
            N = Base64UrlEncoder.Encode(rsaSecurityKey.Rsa?.ExportParameters(false).Modulus)
        };
        // Serialize the JWK to JSON format
        var jwkJson = JsonSerializer.Serialize(jsonWebKey, new JsonSerializerOptions {WriteIndented = true});
        return Tuple.Create(jwkJson, jsonWebKey);
    }

    public string CreateJWKFromRSA()
    {
        using RSA rsa = RSA.Create();
        // Export the public and private key as parameters
        RSAParameters rsaParameters = rsa.ExportParameters(true);

        // Create a JWK
        var jwk = new
        {
            kty = "RSA",
            n = Base64UrlEncoder.Encode(rsaParameters.Modulus),
            e = Base64UrlEncoder.Encode(rsaParameters.Exponent),
            d = Base64UrlEncoder.Encode(rsaParameters.D),
            p = Base64UrlEncoder.Encode(rsaParameters.P),
            q = Base64UrlEncoder.Encode(rsaParameters.Q),
            dp = Base64UrlEncoder.Encode(rsaParameters.DP),
            dq = Base64UrlEncoder.Encode(rsaParameters.DQ),
            qi = Base64UrlEncoder.Encode(rsaParameters.InverseQ)
        };

        // Serialize the JWK to JSON format
        string jwkJson = JsonSerializer.Serialize(jwk, new JsonSerializerOptions { WriteIndented = true });

        return jwkJson;
    }
    
    public async Task<string?> GetAccessTokenFromDuendeIdentityServer2(string jwk)
    {
        var client = new HttpClient();
        var disco = await client.GetDiscoveryDocumentAsync("https://demo.duendesoftware.com");
        if (disco.IsError)
        {
            Console.WriteLine(disco.Error);
            return string.Empty;
        }

        var tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            ClientId = "m2m.jwt",
            ClientSecret = jwk,
            Scope = "api"
        });

        if (tokenResponse.IsError)
        {
            Console.WriteLine(tokenResponse.Error);
            return string.Empty;
        }

        Console.WriteLine(tokenResponse.Json);
        return tokenResponse.AccessToken;

    }
}

