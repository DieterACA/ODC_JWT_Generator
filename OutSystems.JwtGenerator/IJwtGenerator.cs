using OutSystems.ExternalLibraries.SDK;

namespace OutSystems.JwtGenerator {
    /// <summary>
    /// The JwtGenerator interface defines the methods (exposed as server actions)
    /// 
    /// </summary>
    [OSInterface(Description = "Enables creation of a valid & signed token based on a SA key file in OutSystems Developer Cloud (ODC).", IconResourceName = "OutSystems.JwtGenerator.resources.JWT.png")]

public interface IJwtGenerator { 
        /// <summary>
        /// Create a JWT token based from a PEM key.
        /// This method is exposed as a server action to your ODC apps and libraries.
        /// </summary>
        /// <param name="base64SaKeyFile">Key file in base 64 format. Should contain private key marked with -----BEGIN PRIVATE KEY-----</param>
        /// <param name="saEmail">Email to be included in token</param>
        /// <param name="audience">Audience to be included in token</param>
        /// <param name="expiryLength">Validity of token in seconds</param>
       /// <param name="scope">Scope to be included in token</param>
       /// <returns>A JWT token in string format</returns>
     [OSAction(Description = "Generate new JWT token signed with Sa key. The Key file needs to be in base 64 format and should contain private key marked with -----BEGIN PRIVATE KEY-----", ReturnName = "JwtToken")]
    
        public string GenerateJwt(string base64SaKeyFile, string saEmail, string audience, int expiryLength, string scope);
        
    }
}