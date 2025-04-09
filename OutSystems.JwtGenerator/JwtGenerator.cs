using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace OutSystems.JwtGenerator
{
    public class JwtGenerator : IJwtGenerator
    {
        public string GenerateJwtFromBase64(string base64SaKeyFile, string saEmail, string audience, int expiryLength, string scope)
        {
            try
            {
                string pem = Encoding.UTF8.GetString(Convert.FromBase64String(base64SaKeyFile));
                return GenerateJwtInternal(pem, saEmail, audience, expiryLength, scope);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("The base64-encoded private key is not valid base64.", ex);
            }
        }

        public string GenerateJwtFromPemString(string pemString, string saEmail, string audience, int expiryLength, string scope)
        {
            return GenerateJwtInternal(pemString, saEmail, audience, expiryLength, scope);
        }

        public bool ValidatePublicKeyMatchesPrivate(string privateKeyPem, string publicKeyPem)
        {
            using var privateRsa = GetRsaFromPem(privateKeyPem);
            using var publicRsa = GetRsaFromPem(publicKeyPem);

            var privateParams = privateRsa.ExportParameters(false); // Only public part
            var publicParams = publicRsa.ExportParameters(false);

            return AreRsaParametersEqual(privateParams, publicParams);
        }

        private static bool AreRsaParametersEqual(RSAParameters a, RSAParameters b)
        {
            return ByteArraysEqual(a.Modulus, b.Modulus) && ByteArraysEqual(a.Exponent, b.Exponent);
        }

        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        private string GenerateJwtInternal(string pemKey, string saEmail, string audience, int expiryLength, string scope)
        {
            var now = DateTimeOffset.UtcNow;
            var exp = now.AddSeconds(expiryLength);

            try
            {
                var rsa = GetRsaFromPem(pemKey);
                var credentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

                var header = new JwtHeader(credentials);

                var jwtPayload = new JwtPayload(
                    issuer: saEmail,
                    audience: audience,
                    claims: null,
                    notBefore: null,
                    expires: exp.UtcDateTime,
                    issuedAt: now.UtcDateTime
                );

                // Add additional claims: scope 
                jwtPayload.Add("scope", scope);

                 // Create the JWT token
                var token = new JwtSecurityToken(header, jwtPayload);
                var jwtString = new JwtSecurityTokenHandler().WriteToken(token);

                ValidateJwtStructure(jwtString, requiredClaims: new[] { "iss", "scope", "aud", "exp", "iat" });

                return jwtString;
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to generate or validate JWT: " + ex.Message, ex);
            }
        }


        private void ValidateJwtStructure(string jwt, string[] requiredClaims)
        {
            var handler = new JwtSecurityTokenHandler();

            if (!handler.CanReadToken(jwt))
                throw new ArgumentException("Generated token is not a valid JWT format.");

            JwtSecurityToken token;
            try
            {
                token = handler.ReadJwtToken(jwt);
            }
            catch (Exception ex)
            {
                throw new Exception("Token structure is invalid: " + ex.Message, ex);
            }

            foreach (var claim in requiredClaims)
            {
                if (!token.Payload.ContainsKey(claim))
                    throw new Exception($"Missing required claim: '{claim}' in generated token.");
            }

            if (string.IsNullOrWhiteSpace(token.RawSignature))
                throw new Exception("JWT is missing a signature.");
        }

        private static RSA GetRsaFromPem(string pem)
        {
            try
            {
                using var reader = new StringReader(pem);
                var pemReader = new PemReader(reader);
                var keyObject = pemReader.ReadObject();

                RsaPrivateCrtKeyParameters privateKeyParams = keyObject switch
                {
                    AsymmetricCipherKeyPair keyPair => (RsaPrivateCrtKeyParameters)keyPair.Private,
                    RsaPrivateCrtKeyParameters rsaKey => rsaKey,
                    _ => throw new ArgumentException($"Unsupported key format or type: {keyObject?.GetType().Name}")
                };

                var rsaParams = new RSAParameters
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

                var rsa = RSA.Create();
                rsa.ImportParameters(rsaParams);
                return rsa;
            }
            catch (PemException ex)
            {
                throw new ArgumentException("The provided PEM could not be parsed. Ensure the key is in PKCS#1 or PKCS#8 format and includes headers like 'BEGIN RSA PRIVATE KEY'.", ex);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to parse RSA private key from PEM: " + ex.Message, ex);
            }
        }
    }
}
