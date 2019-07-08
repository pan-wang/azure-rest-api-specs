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
using System.Text.RegularExpressions;

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


}
