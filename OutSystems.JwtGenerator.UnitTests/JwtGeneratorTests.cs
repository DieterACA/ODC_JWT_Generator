
using Xunit;

namespace OutSystems.JwtGenerator.UnitTests;

public class JwtGeneratorTests
{
    [Fact]
    public void JwtGenerator()
    {
        var jwtGenerator = new JwtGenerator();

        var bytes = File.ReadAllBytes("/JwtGenerator/private-key.pem");
        
        var base64SaKeyFile = Convert.ToBase64String(bytes);
        var saEmail = string.Empty;
        var audience = string.Empty;
        var expiryLength = 1000;
        var scope = string.Empty;

        var jwt = jwtGenerator.GenerateJwtFromBase64(base64SaKeyFile, saEmail, audience, expiryLength, scope);
        Assert.NotNull(jwt);
    }


}