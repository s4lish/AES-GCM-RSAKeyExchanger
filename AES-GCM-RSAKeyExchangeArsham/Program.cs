using Microsoft.AspNetCore.Http.HttpResults;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();



app.MapGet("/generateprivatepublickey/{keysize}", (int keysize) =>
{

    var cryptoServiceProvider = new RSACryptoServiceProvider(keysize); //2048 - Długość klucza
    var privateKey = cryptoServiceProvider.ToXmlString(true); //Generowanie klucza prywatnego
    var publicKey = cryptoServiceProvider.ToXmlString(false); //Generowanie klucza publiczny        return Results.Ok(new

    return Results.Ok(new
    {
        privateKey = privateKey,
        publicKey = publicKey
    });

});


app.MapPost("/aesgcmencrypt", (iputEncrypt enc) =>
{

    var aes = new AesGcmService();
    var encrypted = aes.Encrypt(enc.input);
    return Results.Ok(new
    {
        encrypted = encrypted,
        key = aes.Keybytes.RsaEncryptWithPublic(enc.rsapublickey),
    });
});


app.MapPost("/aesgcmdecypt", (iputDecrypt inp) =>
{
    var key = inp.key.RsaDecryptWithPrivate(inp.privatekey, true);
    var aes = new AesGcmService(key);

    var strout = aes.Decrypt(inp.encinput);

    return Results.Ok(strout);


});

app.Run();




internal record iputEncrypt(string input, string rsapublickey);
internal record iputDecrypt(string encinput, string key, string privatekey);


public static class extentions
{

    public static string GetKeyString(this RSAParameters publicKey)
    {
        var stringWriter = new System.IO.StringWriter();
        var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
        xmlSerializer.Serialize(stringWriter, publicKey);
        return stringWriter.ToString();
    }

    public static byte[] RsaDecryptWithPrivate(this string strText, string privateKey, bool returnByte = true)
    {
        var testData = Encoding.UTF8.GetBytes(strText);

        using (var rsa = new RSACryptoServiceProvider())
        {
            try
            {
                var base64Encrypted = strText;

                // server decrypting data with private key                    
                rsa.FromXmlString(privateKey);

                var resultBytes = Convert.FromBase64String(base64Encrypted);
                var decryptedBytes = rsa.Decrypt(resultBytes, true);
                return decryptedBytes;
            }
            finally
            {
                rsa.PersistKeyInCsp = false;
            }
        }
    }

    public static string RsaEncryptWithPublic(this byte[] clearText, string publicKey)
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            try
            {
                rsa.FromXmlString(publicKey);

                //byte[] dataToEncrypt = Encoding.UTF8.GetBytes(stringDataToEncrypt);
                // client encrypting data with public key issued by server                    
                var encryptedData = rsa.Encrypt(clearText, true);
                var base64Encrypted = Convert.ToBase64String(encryptedData);

                return base64Encrypted;
            }
            finally
            {
                rsa.PersistKeyInCsp = false;
            }
        }

    }
}

public class AesGcmService : IDisposable
{
    private readonly AesGcm _aes;
    public readonly string KeyBase64;
    public readonly byte[] Keybytes;
    public AesGcmService(byte[] key = null)
    {
        if (key == null)
        {
            var rnd = new RNGCryptoServiceProvider();
            var b = new byte[32];
            rnd.GetNonZeroBytes(b);
            key = b;
        }
        // Derive key
        // AES key size is 16 bytes
        // We use a fixed salt and small iteration count here; the latter should be increased for weaker passwords
        //byte[] key = new Rfc2898DeriveBytes(password, new byte[8], 1000).GetBytes(32);

        KeyBase64 = Convert.ToBase64String(key);
        Keybytes = key;
        // Initialize AES implementation
        _aes = new AesGcm(key);
    }

    public string Encrypt(string plain)
    {
        // Get bytes of plaintext string
        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);

        // Get parameter sizes
        int nonceSize = AesGcm.NonceByteSizes.MaxSize;
        int tagSize = AesGcm.TagByteSizes.MaxSize;
        int cipherSize = plainBytes.Length;

        // We write everything into one big array for easier encoding
        int encryptedDataLength = 4 + nonceSize + 4 + tagSize + cipherSize;
        Span<byte> encryptedData = encryptedDataLength < 1024 ? stackalloc byte[encryptedDataLength] : new byte[encryptedDataLength].AsSpan();

        // Copy parameters
        BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(0, 4), nonceSize);
        BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4), tagSize);
        var nonce = encryptedData.Slice(4, nonceSize);
        var tag = encryptedData.Slice(4 + nonceSize + 4, tagSize);
        var cipherBytes = encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize);

        // Generate secure nonce
        RandomNumberGenerator.Fill(nonce);

        // Encrypt
        _aes.Encrypt(nonce, plainBytes.AsSpan(), cipherBytes, tag);

        // Encode for transmission
        return Convert.ToBase64String(encryptedData);
    }

    public string Decrypt(string cipher)
    {
        // Decode
        Span<byte> encryptedData = Convert.FromBase64String(cipher).AsSpan();

        // Extract parameter sizes
        int nonceSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(0, 4));
        int tagSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4));
        int cipherSize = encryptedData.Length - 4 - nonceSize - 4 - tagSize;

        // Extract parameters
        var nonce = encryptedData.Slice(4, nonceSize);
        var tag = encryptedData.Slice(4 + nonceSize + 4, tagSize);
        var cipherBytes = encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize);

        // Decrypt
        Span<byte> plainBytes = cipherSize < 1024 ? stackalloc byte[cipherSize] : new byte[cipherSize];
        _aes.Decrypt(nonce, cipherBytes, tag, plainBytes);

        // Convert plain bytes back into string
        return Encoding.UTF8.GetString(plainBytes);
    }

    public void Dispose()
    {
        _aes.Dispose();
    }
}

