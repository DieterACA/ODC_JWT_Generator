using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace OutSystems.JwtGenerator
{
    public class JwtGenerator : IJwtGenerator
    {
        public string GenerateJwt(string base64SaKeyFile, string saEmail, string audience, int expiryLength, string scope)
        {
            var now = DateTime.UtcNow;
            var expTime = now.AddSeconds(expiryLength);

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                IssuedAt = now,
                Expires = expTime,
                Issuer = saEmail,
                Audience = audience,
                Subject = new System.Security.Claims.ClaimsIdentity(new[] { new System.Security.Claims.Claim("email", saEmail) }),
            };

            tokenDescriptor.Claims ??= new Dictionary<string, object>();
            tokenDescriptor.Claims.Add("scope", scope);

            var rsaKey = GetRsaKeyFromBase64(base64SaKeyFile);
            tokenDescriptor.SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsaKey), SecurityAlgorithms.RsaSha256Signature);

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        private static RSACryptoServiceProvider GetRsaKeyFromBase64(string base64SaKeyFile)
        {
            byte[] keyBytes = Convert.FromBase64String(base64SaKeyFile);
            RSAParameters rsaParams = ParseRsaPrivateKey(keyBytes);
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider();
            rsaKey.ImportParameters(rsaParams);
            return rsaKey;
        }

        private static RSAParameters ParseRsaPrivateKey(byte[] keyBytes)
        {
            using var stream = new MemoryStream(keyBytes);
            using var reader = new StreamReader(stream);

            var pemReader = new PemReader(reader);
            var privateKeyParams = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();

            RSAParameters rsaParams = new RSAParameters
            {
                Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned(),
                Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned(),
                D = privateKeyParams.Exponent.ToByteArrayUnsigned(),
                P = privateKeyParams.P.ToByteArrayUnsigned(),
                Q = privateKeyParams.Q.ToByteArrayUnsigned(),
                DP = privateKeyParams.DP.ToByteArrayUnsigned(),
                DQ = privateKeyParams.DQ.ToByteArrayUnsigned(),
                InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned()
            };

            return rsaParams;
        }
    }
}