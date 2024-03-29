namespace Security.Jwt;

public class FilePasswordProvider : IPasswordProvider
{
    string password;
    public FilePasswordProvider(string path)
    {
        if(File.Exists(path))
            throw new FileNotFoundException("Password file not founs.");

        this.password = File.ReadAllText(path);
    }

    public string ProvidePassword()
        => this.password;
}