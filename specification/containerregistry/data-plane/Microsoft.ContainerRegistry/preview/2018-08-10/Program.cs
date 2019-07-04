using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.ContainerRegistry;
using Microsoft.Rest;
using Microsoft.Rest.Serialization;
using Microsoft.Azure.ContainerRegistry.Models;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics.Tracing;

namespace testsdk
{
    class Program
    {

        const int FETCH_COUNT_MANIFEST = 5;
        const int FETCH_COUNT_TAGS = 5;

        static void Main(string[] args)
        {
            string username = "";
            string password = "";
            string loginUrl = "csharpsdktest.azurecr.io";
            int timeoutInMilliseconds = 1500000;
            CancellationToken ct = new CancellationTokenSource(timeoutInMilliseconds).Token;
            AcrClientCredentials clientCredential = new AcrClientCredentials(AcrClientCredentials.LoginMode.TokenAuth,
                loginUrl,
                username,
                password,
                ct);

            AzureContainerRegistryClient client = new AzureContainerRegistryClient(clientCredential);

            client.LoginUri = "https://csharpsdktest.azurecr.io";
            try
            {
                Console.WriteLine("################################################################### ACR V1 enpoint API ###################################################################");
                testACRV1(clientCredential, client, ct);
                Console.WriteLine("################################################################### ACR V2 enpoint API ###################################################################");
                testACR2(clientCredential, client, ct);

            }
            catch (Exception e)
            {
                Console.WriteLine("Exception caught: " + e);
            }
        }

        /**
         * Test the V1 api endpoints:
         * /acr/v1/_catalog
         *  - get               - Test Provided (1)
         *  
         * /acr/v1/{name}/_tag/ {reference}
         *  - get               - Test Provided (2)
         *  - patch                             (3)
         *  - delete            - Test Provided (4)
         * 
         * /acr/v1/{name}/_tags
         *  - get               - Test Provided (5)
         *  
         * /acr/v1/{name}/_manifests
         *  - get               - Test Provided (6)
         *  
         * /acr/v1/{name}/_manifests/{reference}
         *  - get               - Test Provided (7)
         *  - patch                             (8)
         * 
         */
        private static void testACRV1(AcrClientCredentials clientCredential, AzureContainerRegistryClient client, CancellationToken ct)
        {
            // ------------------------ Acr V1 Get Repositories ------------------------  (1)
            Repositories repositories = client.GetAcrRepositoriesAsync(null, 20, ct).GetAwaiter().GetResult();
            Console.WriteLine("GET /acr/v1/_catalog result");
            //Console.WriteLine(SafeJsonConvert.SerializeObject(repositories, client.SerializationSettings));

            foreach (string repository in repositories.Names)
            {
                // ------------------------ Acr V1 Get Repository Attributes ------------------------  (2)
                RepositoryAttributes repositoryAttributes;
                Console.WriteLine("GET /acr/v1/{0} result", repository);
                //Console.WriteLine(SafeJsonConvert.SerializeObject(repositoryAttributes, client.SerializationSettings));
                AcrRepositoryTags tags_in;

                try
                {
                    repositoryAttributes = client.GetAcrRepositoryAttributesAsync(repository, ct).GetAwaiter().GetResult();
                    // ------------------------ Acr V1 Get Repository Tags ------------------------  (5)
                    Console.WriteLine("GET /acr/v1/{0}/_tags result", repository);
                    tags_in = client.GetAcrTagsAsync(repository,
                        null,
                        FETCH_COUNT_TAGS,
                        null,
                        null,
                        ct).GetAwaiter().GetResult();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    continue;
                }
                //Console.WriteLine(SafeJsonConvert.SerializeObject(tags_in, client.SerializationSettings));
                foreach (AcrTagAttributesBase tag in tags_in.TagsAttributes)
                {
                    // ------------------------ Acr V1 Get Tag Attributes ------------------------ ?
                    Console.WriteLine("GET /acr/v1/{0}/_tags/{1} result", repository, tag.Name);
                    AcrTagAttributes tagAttribute;
                    try
                    {
                        tagAttribute = client.GetAcrTagAttributesAsync(repository,
                        tag.Name, null,
                        ct).GetAwaiter().GetResult();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                        Console.WriteLine("{0} {1}", tag.Name, repository);
                        continue;
                    }

                    //Console.WriteLine(SafeJsonConvert.SerializeObject(tagAttribute, client.SerializationSettings));
                }

                // ------------------------ Acr V1 Get Repository Manifests ------------------------ (6)
                AcrManifests manifests = client.GetAcrManifestsAsync(repository,
                    null,
                    FETCH_COUNT_MANIFEST,
                    null,
                    ct).GetAwaiter().GetResult();
                Console.WriteLine("GET /acr/v1/{0}/_manifests result", repository);
                //Console.WriteLine(SafeJsonConvert.SerializeObject(manifests, client.SerializationSettings));
                foreach (AcrManifestAttributesBase manifest in manifests.ManifestsAttributes)
                {
                    Console.WriteLine("GET /acr/v1/{0}/_manifests/{1} result", repository, manifest.Digest);
                    AcrManifestAttributes manifestAttribute = null;
                    // ------------------------ Acr V1 Get Manifest Attributes ------------------------  (7)
                    try
                    {
                        manifestAttribute = client.GetAcrManifestAttributesAsync(repository,
                        manifest.Digest,
                        ct).GetAwaiter().GetResult();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                        Console.WriteLine(SafeJsonConvert.SerializeObject(manifest, client.SerializationSettings));
                    }
                }
            }
            // ------------------------ Acr V1 Patch Tag ------------------------  (3)
            Console.WriteLine("PATCH /acr/v1/{name}/_tags/{reference}");
            AcrRepositoryTags tags = client.GetAcrTagsAsync(repositories.Names[0]).GetAwaiter().GetResult();
            // Need to enables delete in case it was disabled in preparation for delete
            ChangeableAttributes changed = new ChangeableAttributes(true, true, true, !tags.TagsAttributes[0].ChangeableAttributes.ReadEnabled);
            client.UpdateAcrTagAttributesAsync(tags.ImageName, tags.TagsAttributes[0].Name, changed, ct).GetAwaiter().GetResult();
            AcrRepositoryTags tagsPostPatch = client.GetAcrTagsAsync(repositories.Names[0], null, null, null, tags.TagsAttributes[0].Digest).GetAwaiter().GetResult();
            //Console.WriteLine(SafeJsonConvert.SerializeObject(tagsPostPatch, client.SerializationSettings));
            Debug.Assert(tagsPostPatch.TagsAttributes[0].ChangeableAttributes == changed);


            // ------------------------ Acr V1 Delete Tag ------------------------  (4)
            Console.WriteLine("DELETE /acr/v1/{name}/_tags/{reference}");
            //Console.WriteLine(SafeJsonConvert.SerializeObject(tags, client.SerializationSettings));
            client.DeleteAcrTagAsync(tags.ImageName, tags.TagsAttributes[0].Name).GetAwaiter().GetResult();
            AcrRepositoryTags tagsPostDelete = client.GetAcrTagsAsync(repositories.Names[0]).GetAwaiter().GetResult();
            //Console.WriteLine(SafeJsonConvert.SerializeObject(tagsPostDelete, client.SerializationSettings));
            Debug.Assert(!tagsPostDelete.TagsAttributes.Contains(tags.TagsAttributes[0]));
            Console.WriteLine("Succesfully deleted {0}/{1}", tags.ImageName, tags.TagsAttributes[0]);


            // ------------------------ Acr V1 Patch Manifest ------------------------  (8)
            AcrManifests newManifests = client.GetAcrManifestsAsync(repositories.Names[0],
                null,
                null,
                null,
                ct).GetAwaiter().GetResult();

            Console.WriteLine("PATCH /acr/v1/{0}/_manifests/{1} result", repositories.Names[0], newManifests.ManifestsAttributes[0].Digest);
            ChangeableAttributes changed2 = new ChangeableAttributes(true, !newManifests.ManifestsAttributes[0].ChangeableAttributes.ListEnabled, true, !newManifests.ManifestsAttributes[0].ChangeableAttributes.ReadEnabled);
            client.UpdateAcrManifestAttributesAsync(newManifests.ImageName, newManifests.ManifestsAttributes[0].Digest, changed2).GetAwaiter().GetResult();
            AcrManifests manifestsPostPatch = client.GetAcrManifestsAsync(repositories.Names[0],
                null,
                null,
                null,
                ct).GetAwaiter().GetResult();
            Debug.Assert(manifestsPostPatch.ManifestsAttributes[0].ChangeableAttributes == changed2);


        }


        /**
        * Test the V2 api endpoints:
        * 
        * /v2/_catalog
        *  - get               - Test Provided (1)
        * 
        * /v2/{name}/tags/list
        *  - get               - Test Provided (2)
        * 
        * /v2/{name}/manifests/{reference}
        *  - get               - Test Provided (3)
        *  - put               - Test Provided (4)
        *  - delete            -               (5)
        * /v2/
        *  - get               - Test Provided (6)
        *  
        *  
        * 
        */
        private static void testACR2(AcrClientCredentials clientCredential, AzureContainerRegistryClient client, CancellationToken ct)
        {

            // ------------------------ Docker V2 Get Repositories ------------------------  (1)
            Repositories catalogResponse = client.GetRepositoriesAsync(null,
                null,
                ct).GetAwaiter().GetResult();
            Console.WriteLine("GET /v2/_catalog result");
            //Console.WriteLine(SafeJsonConvert.SerializeObject(repositories, client.SerializationSettings));
            foreach (string repository in catalogResponse.Names)
            {
                // ------------------------ Docker V2 Get Tags ------------------------  (2)
                RepositoryTags repositoryTagsPaginated = client.GetTagListAsync(repository,
                    ct).GetAwaiter().GetResult();
                Console.WriteLine("GET /v2/{0}/tags/list result", repository);
                //Console.WriteLine(SafeJsonConvert.SerializeObject(repositoryTags, client.SerializationSettings));

                foreach (string tag in repositoryTagsPaginated.Tags)
                {
                    // ------------------------ Docker V2 Get Manifest ------------------------  (3)
                    Manifest manifest = client.GetManifestAsync(repository,
                        tag,
                        "application/vnd.docker.distribution.manifest.v2+json", // most of docker images are v2 docker images now. The accept header should include "application/vnd.docker.distribution.manifest.v2+json"
                        ct).GetAwaiter().GetResult();
                    Console.WriteLine("GET /v2/{0}/manifests/{1} result", repository, tag);
                    //Console.WriteLine(SafeJsonConvert.SerializeObject(manifest, client.SerializationSettings));

                    // ------------------------ Docker V2 Update Manifest ------------------------  (4)
                    // Use the same manifest to update the manifest
                    // Keep in mind, you need to wait at least 5 seconds to let this change be committed in server.
                    // Getting manifest again right after updating will actually getting old manifest.
                    if (!string.Equals(tag, "3.7"))
                    {
                        continue;
                    }

                    // 1. Reference by tag
                    client.PutManifestAsync(repository,
                        tag, // Reference by tag
                        manifest,
                        ct).GetAwaiter().GetResult();
                    Console.WriteLine("PUT /v2/{0}/manifests/{1} result. reference by tag", repository, tag);
                    //Console.WriteLine(SafeJsonConvert.SerializeObject(manifest, client.SerializationSettings));

                    // 2. Reference by digest
                    string manifestString = SafeJsonConvert.SerializeObject(manifest, client.SerializationSettings);
                    string digest = computeDigest(manifestString);
                    client.PutManifestAsync(repository,
                        digest, // Reference by digest
                        manifest,
                        ct).GetAwaiter().GetResult();
                    Console.WriteLine("PUT /v2/{0}/manifests/{1} result. reference by digest", repository, digest);
                    //Console.WriteLine(SafeJsonConvert.SerializeObject(manifest, client.SerializationSettings));
                }
            }
        }

        private static string computeDigest(string s)
        {
            StringBuilder sb = new StringBuilder();

            using (var hash = SHA256.Create())
            {
                Encoding enc = Encoding.UTF8;
                Byte[] result = hash.ComputeHash(enc.GetBytes(s));

                foreach (Byte b in result)
                    sb.Append(b.ToString("x2"));
            }

            return "sha256:" + sb.ToString();
        }
    }

    public class AcrClientCredentials : ServiceClientCredentials
    {
        Microsoft.Azure.ContainerRegistry.AzureContainerRegistryClient authClient;

        private class TokenCredentials : ServiceClientCredentials
        {
            private string AuthHeader {get; set;}

            /*To be used for General Login Scheme*/
            public TokenCredentials(string username, string password)
            {
                AuthHeader = EncodeTo64(username + ":" + password);
            }
            /*To be used for exchanging AAD Tokens for ACR Tokens*/
            public TokenCredentials()
            {
                AuthHeader = null;
            }
            public override async Task ProcessHttpRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (request == null)
                {
                    throw new ArgumentNullException("request");
                }
                if (AuthHeader != null)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Basic", AuthHeader);
                }
                await base.ProcessHttpRequestAsync(request, cancellationToken);
            }
        }
        struct Token
        {
            public string token { get; set; }
            public DateTime Expiration { get; set; }
        }

        public enum LoginMode
        {
            Basic,
            TokenAuth,
            TokenAad
        }


        private string AuthHeader { get; set; }
        private LoginMode Mode { get; set; }
        private string LoginUrl { get; set; }
        private string Username { get; set; }
        private string Password { get; set; }
        private String Tenant { get; set; }

        private Token AcrRefresh;
        private Token AcrAccess;
        private Token AadAccess;

        // <Scope> <Token>
        private Dictionary<string, string> AcrAccessTokens;

        // Need to somehow prefill this
        //{GET}v2/_catalog : registry:catalog:*
        //{GET}v2/{name}/_tags/list : repository:{name}:pull
        //

        // <Operation> <Scope>
        private Dictionary<string, string> AcrScopes;

        private CancellationToken RequestCancellationToken { get; set; }

        public AcrClientCredentials(LoginMode mode, string loginUrl, string username, string password, CancellationToken cancellationToken = default(CancellationToken))
        {
            Mode = mode;
            if (Mode == LoginMode.TokenAad)
            {
                throw new Exception("AAD token authorization requires you to provide the AAD_access_token");
            }
            LoginUrl = loginUrl;
            Username = username;
            Password = password;
            RequestCancellationToken = cancellationToken;
            commonInit();
        }

        public AcrClientCredentials(string AAD_access_token, string loginUrl, string tenant = null, string LoginUri = null, CancellationToken cancellationToken = default(CancellationToken))
        {
            Mode = LoginMode.TokenAad;
            LoginUrl = loginUrl;
            RequestCancellationToken = cancellationToken;
            AadAccess.token = AAD_access_token;
            Tenant = tenant;
            commonInit();
        }

        private void commonInit() {
            AcrScopes = new Dictionary<string, string>();
            AcrAccessTokens = new Dictionary<string, string>();
        }

        public override void InitializeServiceClient<AzureContainerRegistryClient>(ServiceClient<AzureContainerRegistryClient> client)
        {
            if (Mode == LoginMode.Basic)
            {
                AuthHeader = EncodeTo64(Username + ":" + Password);
                return;
            }

            // For Bearer modes

            // Step 1: get challenge response from /v2/ API. THe response Www-Authenticate header is token server URL.
            string challegeUrl = (LoginUrl.StartsWith("https://") ? "" : "https://") + LoginUrl + (LoginUrl.EndsWith("/") ? "" : "/") + "v2/";
            HttpClient runtimeClient = new HttpClient();
            HttpResponseMessage response = null;
            string tokenServerUrl = "";
            try
            {
                response = runtimeClient.GetAsync(challegeUrl, RequestCancellationToken).GetAwaiter().GetResult();
                tokenServerUrl = response.Headers.GetValues("Www-Authenticate").FirstOrDefault();
            }
            catch (Exception e)
            {
                Console.WriteLine("v2 call throws exception {0}", e.Message);
            }

            if (!String.IsNullOrEmpty(tokenServerUrl))
            {
                //AcrRefresh.token = noCredentialClient.GetAcrRefreshTokenAsync("access_token", this.LoginUrl, Tenant, null, AadAccess.token).GetAwaiter().GetResult().RefreshToken;
                
            }
            else
            {
                throw new Exception("Could not find Authentication endpoint for this registry");
            }

            if (Mode == LoginMode.TokenAuth) // From Credentials
            { 
                authClient = new Microsoft.Azure.ContainerRegistry.AzureContainerRegistryClient(new TokenCredentials());
                authClient.LoginUri = tokenServerUrl;
            }
            else // From AAD Access Token
            { 
                authClient = new Microsoft.Azure.ContainerRegistry.AzureContainerRegistryClient(new TokenCredentials());
                authClient.LoginUri = tokenServerUrl;
                AcrRefresh.token = authClient.GetAcrRefreshTokenAsync("access_token", this.LoginUrl, Tenant, null, AadAccess.token).GetAwaiter().GetResult().RefreshToken;
            }



        }
        public override async Task ProcessHttpRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            if (Mode == LoginMode.Basic)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", AuthHeader);
            }
            else
            {
                string operation = "https://" + LoginUrl +  request.RequestUri.AbsolutePath;
                string scope = getScope(operation, request.Method.Method);
                request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + getAcrAccessToken(scope));
            }
            //request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            //Print(request);
            //request.Version = new Version(apiVersion);
            await base.ProcessHttpRequestAsync(request, cancellationToken);

        }

        public string getAcrAccessToken(string scope)
        {

            if (AcrAccessTokens.ContainsKey(scope))
            {
                return AcrAccessTokens[scope];
            }
            else if (Mode == LoginMode.TokenAad)
            {
                string acrAccess = authClient.GetAcrAccessTokenAsync(this.LoginUrl, scope, AcrRefresh.token).GetAwaiter().GetResult().AccessToken;
                AcrAccessTokens[scope] = acrAccess;
            }
            else if (Mode == LoginMode.TokenAuth)
            {
                string acrAccess = authClient.GetAcrAccessTokenFromLoginAsync(this.LoginUrl, scope).GetAwaiter().GetResult().AccessToken;
                AcrAccessTokens[scope] = acrAccess;
            }
            else
            {
                throw new Exception("This Function cannot be invoked for requested Login Mode ");
            }

            return AcrAccessTokens[scope];
        }

        public string getScope(string operation, string method) {

            if (AcrScopes.ContainsKey(operation)) {
                return AcrScopes[operation];
            }

            HttpClient runtimeClient = new HttpClient();
            HttpResponseMessage response = null;
            string scope = "";
            try
            {
                response = runtimeClient.SendAsync(new HttpRequestMessage(new HttpMethod (method), operation)).GetAwaiter().GetResult();
                scope = response.Headers.GetValues("Www-Authenticate").Last();
                AcrScopes[operation] = scope;
            }
            catch (Exception e)
            {
                throw new Exception("Could not identify appropiate Token scope: " + e.Message);
            }
            return scope;

        }

        static public string EncodeTo64(string toEncode)
        {
            byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(toEncode);
            string returnValue = System.Convert.ToBase64String(toEncodeAsBytes);
            return returnValue;
        }

        private void Print(HttpRequestMessage request)
        {
            Console.WriteLine("=============method ===================");
            Console.WriteLine(request.Method);
            Console.WriteLine(request.RequestUri);
            Console.WriteLine("==============headers ==================");
            Console.WriteLine(request.Headers.ToString());
            Console.WriteLine("==============content headers ==================");
            Console.WriteLine(request.Content?.Headers?.ToString());
            Console.WriteLine("==============content==================");
            Console.WriteLine(request.Content?.ReadAsStringAsync().GetAwaiter().GetResult());
            // Console.WriteLine(request.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            /*
            string headers = String.Empty;
            foreach (var key in request.Headers)
                headers += key + "=" + request.Headers.GetValues(key).FirstOrDefault() + Environment.NewLine;
            Console.WriteLine(headers);
            */
            Console.WriteLine("================================");
        }
    }
}
