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

namespace testsdk
{
    class Program
    {
        static void Main(string[] args)
        {
            string username = "cSharpSdkTest";
            string password = "";
            string loginUrl = "csharpsdktest.azurecr.io";
            int timeoutInMilliseconds = 15000;
            CancellationToken ct = new CancellationTokenSource(timeoutInMilliseconds).Token;
            AcrClientCredentials clientCredential = new AcrClientCredentials(true,
                loginUrl,
                username,
                password,
                ct);
            AzureContainerRegistryClient client = new AzureContainerRegistryClient(clientCredential);
            client.LoginUri = "https://csharpsdktest.azurecr.io";
            try
            {
                testACRV1(clientCredential, client, ct);
                testACR2(clientCredential, client, ct);

            }
            catch (Exception e)
            {
                Console.WriteLine("Exception caught: " + e.Message);
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
            Repositories repositories = client.GetAcrRepositoriesAsync(null, "", ct).GetAwaiter().GetResult();
            Console.WriteLine("GET /acr/v1/_catalog result");
            Console.WriteLine(SafeJsonConvert.SerializeObject(repositories, client.SerializationSettings));
            foreach (string repository in repositories.Names)
            {
                // ------------------------ Acr V1 Get Repository Attributes ------------------------  (2)
                RepositoryAttributes repositoryAttributes = client.GetAcrRepositoryAttributesAsync(repository, ct).GetAwaiter().GetResult();
                Console.WriteLine("GET /acr/v1/{0} result", repository);
                Console.WriteLine(SafeJsonConvert.SerializeObject(repositoryAttributes, client.SerializationSettings));

                // ------------------------ Acr V1 Get Repository Tags ------------------------  (5)
                AcrRepositoryTags tags_in = client.GetAcrTagsAsync(repository,
                    null,
                    null,
                    null,
                    null,
                    ct).GetAwaiter().GetResult();
                Console.WriteLine("GET /acr/v1/{0}/_tags result", repository);
                Console.WriteLine(SafeJsonConvert.SerializeObject(tags_in, client.SerializationSettings));
                foreach (AcrTagAttributesBase tag in tags_in.TagsAttributes)
                {
                    // ------------------------ Acr V1 Get Tag Attributes ------------------------ ?
                    AcrTagAttributes tagAttribute = client.GetAcrTagAttributesAsync(repository,
                        tag.Name,
                        ct).GetAwaiter().GetResult();
                    Console.WriteLine("GET /acr/v1/{0}/_tags/{1} result", repository, tag.Name);
                    Console.WriteLine(SafeJsonConvert.SerializeObject(tagAttribute, client.SerializationSettings));
                }

                // ------------------------ Acr V1 Get Repository Manifests ------------------------ (6)
                AcrManifests manifests = client.GetAcrManifestsAsync(repository,
                    null,
                    null,
                    null,
                    ct).GetAwaiter().GetResult();
                Console.WriteLine("GET /acr/v1/{0}/_manifests result", repository);
                Console.WriteLine(SafeJsonConvert.SerializeObject(manifests, client.SerializationSettings));
                foreach (AcrManifestAttributesBase manifest in manifests.ManifestsAttributes)
                {
                    // ------------------------ Acr V1 Get Manifest Attributes ------------------------  (7)
                    AcrManifestAttributes manifestAttribute = client.GetAcrManifestAttributesAsync(repository,
                        manifest.Digest,
                        ct).GetAwaiter().GetResult();
                    Console.WriteLine("GET /acr/v1/{0}/_manifests/{1} result", repository, manifest.Digest);
                    Console.WriteLine(SafeJsonConvert.SerializeObject(manifestAttribute, client.SerializationSettings));
                }
            }


            // ------------------------ Acr V1 Delete Tag ------------------------  (4)
            Console.WriteLine("DELETE /acr/v1/{name}/_tags/{reference}");
            AcrRepositoryTags tags = client.GetAcrTagsAsync(repositories.Names[0]).GetAwaiter().GetResult();
            Console.WriteLine(SafeJsonConvert.SerializeObject(tags, client.SerializationSettings));
            Console.WriteLine("---------------Delete Called ---------------");
            client.DeleteAcrTagAsync(tags.ImageName, tags.TagsAttributes[0].Name).GetAwaiter().GetResult();
            AcrRepositoryTags tagsPost = client.GetAcrTagsAsync(repositories.Names[0]).GetAwaiter().GetResult();
            Console.WriteLine(SafeJsonConvert.SerializeObject(tagsPost, client.SerializationSettings));
            Debug.Assert(!tagsPost.TagsAttributes.Contains(tags.TagsAttributes[0]));

            // ------------------------ Acr V1 Patch Tag ------------------------  (3)


            // ------------------------ Acr V1 Patch Manifest ------------------------  (8)


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
            Repositories repositories = client.GetRepositoriesAsync(null,
                null,
                ct).GetAwaiter().GetResult();
            Console.WriteLine("GET /v2/_catalog result");
            Console.WriteLine(SafeJsonConvert.SerializeObject(repositories, client.SerializationSettings));
            foreach (string repository in repositories.Names)
            {
                // ------------------------ Docker V2 Get Tags ------------------------  (2)
                RepositoryTags repositoryTags = client.GetTagListAsync(repository,
                    ct).GetAwaiter().GetResult();
                Console.WriteLine("GET /v2/{0}/tags/list result", repository);
                Console.WriteLine(SafeJsonConvert.SerializeObject(repositoryTags, client.SerializationSettings));

                foreach (string tag in repositoryTags.Tags)
                {
                    // ------------------------ Docker V2 Get Manifest ------------------------  (3)
                    Manifest manifest = client.GetManifestAsync(repository,
                        tag,
                        "application/vnd.docker.distribution.manifest.v2+json", // most of docker images are v2 docker images now. The accept header should include "application/vnd.docker.distribution.manifest.v2+json"
                        ct).GetAwaiter().GetResult();
                    Console.WriteLine("GET /v2/{0}/manifests/{1} result", repository, tag);
                    Console.WriteLine(SafeJsonConvert.SerializeObject(manifest, client.SerializationSettings));

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
                    Console.WriteLine(SafeJsonConvert.SerializeObject(manifest, client.SerializationSettings));

                    // 2. Reference by digest
                    string manifestString = SafeJsonConvert.SerializeObject(manifest, client.SerializationSettings);
                    string digest = computeDigest(manifestString);
                    client.PutManifestAsync(repository,
                        digest, // Reference by digest
                        manifest,
                        ct).GetAwaiter().GetResult();
                    Console.WriteLine("PUT /v2/{0}/manifests/{1} result. reference by digest", repository, digest);
                    Console.WriteLine(SafeJsonConvert.SerializeObject(manifest, client.SerializationSettings));
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
        private string AuthHeader { get; set; }
        private bool BasicMode { get; set; }

        private string LoginUrl { get; set; }
        private string Username { get; set; }
        private string Password { get; set; }
        private CancellationToken RequestCancellationToken { get; set; }

        public AcrClientCredentials(bool basicMode, string loginUrl, string username, string password, CancellationToken cancellationToken = default(CancellationToken))
        {
            BasicMode = basicMode;
            LoginUrl = loginUrl;
            Username = username;
            Password = password;
            RequestCancellationToken = cancellationToken;
        }

        public override void InitializeServiceClient<T>(ServiceClient<T> client)
        {
            if (!BasicMode)
            {
                // For bear mode
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
                    // Step 2: present username and password to token server to get access token
                    // TODO: Call token server to get access token
                    return;
                }
            }

            AuthHeader = EncodeTo64(Username + ":" + Password);
        }
        public override async Task ProcessHttpRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            if (AuthHeader == null)
            {
                throw new InvalidOperationException("Token Provider Cannot Be Null");
            }

            if (BasicMode)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", AuthHeader);
            }
            else
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bear", AuthHeader);
            }
            //request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            Print(request);
            //request.Version = new Version(apiVersion);
            await base.ProcessHttpRequestAsync(request, cancellationToken);

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
