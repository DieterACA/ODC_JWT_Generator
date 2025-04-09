JwtGenerator: Basic version
---------------------------

### Overview

Enables creation of a valid & signed token based on a SA key file in OutSystems Developer Cloud (ODC).
Supported format: base64 and text string.

This component can be used together with other libraries such as;

-Google Calendar Integration Service

-Google Drive Integration
-...
to generate the needed token for authentication.



To sign the token a SA key file is needed which contains the private key in the following format:
-----BEGIN PRIVATE KEY-----
your private key
-----END PRIVATE KEY-----



### Prerequisites for component adaptation

*   .NET 8.0 SDK installed.
*   An IDE that supports building .NET 8 projects. For example, Visual Studio, Visual Studio Code,... .
*   Basic knowledge of C# programming concepts.

### Component adaptation

1.  Load the C# project file, `OutSystems.JwtGenerator.csproj`, using a supported IDE.
    
    Files in the project:
    
    *   **IJwtGenerator.cs**: Defines a public interface named `IJwtGenerator`, decorated with the `OSInterface` attribute. The interface has a method named `GenerateJwtFromBase64`, which takes an PEM key file in base 64 string value, a saEmail in string value, a audience in string value, a expirylength in integer value and a scope in string value as input and returns an `JWT token` string. And method named `GenerateJwtFromPemString` which has the same funcationality but frome a Pem key in string value. Both `GenerateJwt` functions are exposed as server actions to your ODC apps and libraries.
        
    *   **JwtGenerator.cs**: Defines a public class named `JwtGenerator` that implements the `JwtGenerator` interface. The class is a convenient wrapper for several cyrptographic librarys, that provide functionality for generating a valid Jwt token. The class has a public action named `GenerateJwtFromBase64` and `GenerateJwtFromPemString`, which is an instance of the `IJwtGenerator` interface.
        
2.  Edit the code to meet your use case. If your project requires unit tests, modify the examples found in `../OutSystems.JwtGenerator.UnitTests/JwtGeneratorTests.cs` accordingly.
    
3.  Run the Powershell script `generate_upload_package.ps1` to generate `ExternalLibrary.zip`. Rename as required.
    
4.  Upload the generated ZIP file to the ODC Portal. See the [External Logic feature documentation](https://www.outsystems.com/goto/external-logic-upload) for guidance on how to do this.
    

_(Excerpted from the [main README of the External Libraries SDK](https://www.outsystems.com/goto/external-logic-readme), please refer to that document for additional guidance.)_
