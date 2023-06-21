using System.Text;
using System.Text.Json;
using System.Security.Cryptography;

namespace Security.Jwt;

public class JwtService : IJwtService
{
    IPasswordProvider provider;
    public JwtService(IPasswordProvider provider)
    {
        this.provider = provider;
    }
    public string GetToken<T>(T obj)
    {
        var json = JsonSerializer.Serialize(obj);

        var header = getJsonHeader();
        var payload = this.jsonToBase64(json);

        var signature = this.getSignature(header, payload);
        
        return $"{header}.{payload}.{signature}";

    }

    public T Validate<T>(string jwt)
    {
        throw new NotImplementedException();
    }

    private string getSignature(string header, string payload)
    {
        var password = this.provider.ProvidePassword();
        var data = header + payload + password;
        var signature = this.applyHash(data);
        return signature;
    }

    private string applyHash(string str)
    {
        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(str);
        var hashBytes = sha.ComputeHash(bytes);
        var hash = Convert.ToBase64String(hashBytes);
        var unpadHash = this.removePading(hash);
        return unpadHash;
    }

    private string getJsonHeader()
    {
        string header = """
            {
            "alg": "HS256",
            "typ": "JWT"
            }
            """;
        var base64 = this.jsonToBase64(header);
        return base64;
    }

    private string jsonToBase64(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var base64 = Convert.ToBase64String(bytes);
        var unpadBase64 = this.removePading(base64);
        return unpadBase64;
    }

    private string removePading(string base64)
    {
        var unpaddingBase64 = base64.Replace("=", "");
        return unpaddingBase64;
    }
}