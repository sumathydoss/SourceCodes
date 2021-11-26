using System.Net;
using System.Text;  // For class Encoding
using System.IO;    // For StreamReader
using System;
using System.Collections.Generic;
using System.Configuration;
using Jose;
using System.Security.Cryptography;
using System.Web;
using Jose.keys;
using Stream = System.IO.Stream;
using System.Web.Script.Serialization;
using Newtonsoft.Json;

public partial class holding : System.Web.UI.Page
{
    string ClientID = "mlDBKnXXXXXTYRTYRTYyYdmzFGD6HcBPsHZ2W";
    string RemoteURL = "https://www.example.org";
    string RemoteTokenAppend = "/token";
    string RedirectURL = "https://www.exampleabc.com/holding.aspx";
    //-----private key for Encrypting the token
    string PrivateKey = @" 
        {
            ""x"": ""4kELRTR545GDGDGtvilOLrtr5luaQaWgaTlpqUf7o"",
            ""y"": ""iCyNdwX73FWKJTjn1Q19gdjEILKjEILK3Y_XwgY3Y_XwgY"",
            ""d"": ""wiYrwNa5SgBNgdqRtSMpaUvRmipaBJ6hfmL1CUMpwlQ"",
            ""kty"": ""EC"",
            ""crv"": ""P-256""
        }";
    Dictionary<string, object> PrivateKeyHeader = new Dictionary<string, object>
        {
            { "typ", "JWT" },
            { "kid", "TST_SERVER" },
            { "alg", "ES256" }
        };
    //----Public Enc key for Decrypting the JWE token from the remote host
    string PublicKey_Enc = @" 
        {
            ""x"": ""_ylhMfdVwaRrLx8HL8z7X1ixVkk2rbpwD9oU-uAqyhE"",
            ""y"": ""aCRo4kY2dTl7wZXjsp2NJyF9Tcmzk1XZN5ueJWNq7Lk"",
            ""d"": ""Jz9aEpbt_4aKL5FVdCLlux7U-Ubt_4aKL5VdCLLTR2Y"",
            ""kty"": ""EC"",
            ""crv"": ""P-256""
        }";

    public void Page_Load(object sender, EventArgs e)
    {
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(RemoteURL + RemoteTokenAppend);
        ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
        request.ProtocolVersion = HttpVersion.Version10;
        var postData = "client_assertion_type=" + HttpUtility.UrlEncode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        postData += "&client_id=" + HttpUtility.UrlEncode(ClientID);
        postData += "&grant_type=" + HttpUtility.UrlEncode("authorization_code");
        postData += "&redirect_uri=" + HttpUtility.UrlEncode(RedirectURL);
        postData += "&code=" + HttpUtility.UrlEncode(Request.QueryString["code"]);
        postData += "&client_assertion=" + EncryptTokenJose();

        var data = Encoding.ASCII.GetBytes(postData);

        request.Method = "POST";
        request.ContentType = "application/x-www-form-urlencoded";
        request.Headers.Add("Content-Encoding", "ISO-8859-1");

        request.ContentLength = data.Length;
        try
        {
            using (var stream = request.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }

            var webResponse = (HttpWebResponse)request.GetResponse();
            var webStream = webResponse.GetResponseStream();
            var responseReader = new StreamReader(webStream);
            var response = responseReader.ReadToEnd();
            //---Decrypt the Response from Remote
            string JoseRes = DecryptTokenJose(response.ToString());
            //---close the response reader
            responseReader.Close();
            Response.Write("<br><br>Payload = " + JoseRes + "<br><br>");
            //---Get the json string and values from the decrypted Token
            JsonTextReader reader = new JsonTextReader(new StringReader(JoseRes));
            var sData = JsonSerializer.CreateDefault().Deserialize<payload>(reader);

            //----Sample Payload
            //---- Payload = { "sub":"s=S775566X,u=c57acrtereb8-d102-455a-860a-ae7dretef4b8d","aud":"mlDBKnGyYfgdgdmzwx770mqXKb6HcBPsHZ2W","amr":["pwd","swk"],"iss":"https:\/\/www.exampleabc.com","exp":1637810980,"iat":1637810380,"nonce":"TJtv85f586sTgxjUlFm5"}
            //----get the sub from Payload
            string sub = sData.sub;

            Response.Write("<br><br>Sub = " + sub + "<br><br>");
            //---Get the list array of sub to extract the IC
            string[] subList = sub.Split(',');

            //---Get the first item of the array to get the IC
            Response.Write("<br><br>NRIC = " + subList[0] + "<br><br>");

            //---Retrieved IC value will be s=S775566X, so replace s= to "" to get the exact NRIC value and set the Session value
            Session["NRIC"] = subList[0].Replace("s=", "");

            //---if Session["RedirctPage"] is set then go to that page
            if (Session["RedirctPage"] != null)
                Response.Redirect(Session["RedirctPage"].ToString());
            else
                Response.Redirect("Register_uat.aspx");

        }
        catch (WebException ex)
        {

            using (WebResponse response = ex.Response)
            {


                string ErrorString = "Error from the Server:-----<br><br>";
                HttpWebResponse httpResponse = (HttpWebResponse)response;                   
                using (Stream data1 = response.GetResponseStream())
                using (var reader = new StreamReader(data1))
                {
                    ErrorString += reader.ReadToEnd();
                    Response.Write(ErrorString);
                }

                
            }
        }
    }

    public string EncryptTokenJose()
    {

        const uint JwtToAadLifetimeInSeconds = 60 * 2; 
        DateTime validFrom = DateTime.UtcNow;
        long exp = ConvertToTimeT(validFrom + TimeSpan.FromSeconds(JwtToAadLifetimeInSeconds));
        long iat = ConvertToTimeT(validFrom);
        //---Payload string
        string payloadStr = "{\"aud\":\"" + RemoteURL + "\",\"exp\":" + exp.ToString() + ",\"iss\":\"" + ClientID + "\",\"iat\": " + iat.ToString() + ",\"sub\":\"" + ClientID + "\"}";
        //---get the Private key to form the public key
        JsonTextReader reader = new JsonTextReader(new StringReader(PrivateKey));
        var jwk = JsonSerializer.CreateDefault().Deserialize<JWK>(reader);
        var publicECCKey = EccKey.New(Base64Url.Decode(jwk.x), Base64Url.Decode(jwk.y), Base64Url.Decode(jwk.d), usage: CngKeyUsages.KeyAgreement);
        string token = Jose.JWT.Encode(payloadStr, publicECCKey, JwsAlgorithm.ES256, extraHeaders: PrivateKeyHeader);
        return token;
    }

    public string DecryptTokenJose(string Res)
    {
        var jss = new JavaScriptSerializer();
        string json = Res;
        Dictionary<string, string> sData = jss.Deserialize<Dictionary<string, string>>(json);
        string AccessToken = sData["access_token"].ToString();
        string TokenType = sData["token_type"].ToString();
        string IdToken = sData["id_token"].ToString();

        Response.Write("<br><br>" + IdToken + "<br><br>");
        //---get the Public key Enc to decrypt the JWE token
        JsonTextReader reader = new JsonTextReader(new StringReader(PublicKey_Enc));
        var jwk = JsonSerializer.CreateDefault().Deserialize<JWK>(reader);
        var publicECCKey = EccKey.New(Base64Url.Decode(jwk.x), Base64Url.Decode(jwk.y), Base64Url.Decode(jwk.d), usage: CngKeyUsages.KeyAgreement);

        //---get the decrypted token
        string token = Jose.JWT.Decode(IdToken, publicECCKey, JweAlgorithm.ECDH_ES_A128KW, JweEncryption.A256CBC_HS512);

        //----todo: Verify the signature of the decoded JWS token

        //----5 parts token with dot(.) as separator
        string[] toklist = token.Split('.');
        //----get the 2nd item of the list which will have the Payload with User IC details
        string Payload = toklist[1];
        //----decode the payload to bytes and from bytes to readable string
        var base64EncodedBytes = Base64Url.Decode(Payload);
        return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);

    }

    public static long ConvertToTimeT(DateTime dt)
    {
        return (long)(dt - new DateTime(1970, 1, 1, 0, 0, 0, 0)).TotalSeconds;
    }

    public class payload
    {
        public string sub { get; set; }
        public string aud { get; set; }
        public string iss { get; set; }
        public string exp { get; set; }
        public string iat { get; set; }

    }

    public class JWK
    {
        public string x { get; set; }
        public string y { get; set; }
        public string d { get; set; }
    }
}